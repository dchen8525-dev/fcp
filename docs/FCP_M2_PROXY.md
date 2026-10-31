# FCP M2 代理设计：FCP-STREAM 与代理入口

> 依据：`FCP_PROTOCOL_V6.md`（§4 帧格式、§5 结算、§6 握手、§8 策略、附录 C #29）、
> `FCP_V6_DETAILED_DESIGN.md`。日期：2026-10-30。
> 范围裁定（用户确认）：可靠字节流由 **FCP 原生 stream 层**提供（不引入 KCP/ikcp 依赖）；
> 入口做 **SOCKS5 TCP CONNECT + HTTP CONNECT**（不做 UDP ASSOCIATE、不做静态端口转发）；
> **每条被代理连接一条 FCP 会话**（不做 conn_id 多路复用）；交付 **CLI 双端 + Qt GUI 代理页**
> （GUI 内嵌引擎，不是拉起子进程）。
>
> **不改线上格式**：M1 冻结的 §4 帧/信封字节一律不动。FCP-STREAM 只占据 data 符号的
> payload 内部，属于"宿主层协议"，与 KCP 在同一位置——因此本文件是 §4 之下的新增层，
> 不是 v6 的修订版。

---

## 1. 分层与数据通路

```
应用（浏览器/命令行）
   │  TCP 127.0.0.1:1080 (SOCKS5) / 127.0.0.1:1081 (HTTP CONNECT)
   ▼
本地监听 ──accept──▶ Connection{ Session + Stream }   客户端 ProxyEngine
   │                        │ on_kcp_output(seg) → Stream 段 → Session → 符号 → UDP
   ═════════════════════════╪══════════════════════════════════════════════════
                            ▼  同一 UDP 端口，多会话按信封 salt 区分
                    服务端 ProxyEngine：salt → Connection{ Session + Stream }
                            │ 首段有序字节 = OPEN{ATYP,ADDR,PORT}
                            ▼
                        远端解析 → TCP 拨号 → 双向泵 → 目标
```

FCP 侧的既有分工保持不变：Session 负责信封、RS/FEC、结算、FECSTAT 与自适应 k；
它**不提供**可靠交付——丢包未修复时由本层 ARQ 补齐（规格 §8 的"一组无需重传的概率"
口径正是对本层而言）。

## 2. FCP-STREAM v1 段格式

一个段 = 一个 FCP data 符号的 payload。段长上限取 `Session::mtu_limits().payload_max`
（MTU 1400 / IPv4 为 1336B），首字节为类型：

| 类型 | 值 | 布局 | 说明 |
|---|---|---|---|
| `DATA` | 0x01 | `type(1) \| seq(4) \| flags(1) \| bytes(n)` | `n ≤ payload_max − 6`；`flags.bit0 = fin`（该段携带 1 个伪序号字节，见下） |
| `ACK` | 0x02 | `type(1) \| cum(4) \| rwnd(4) \| sack_start(4) \| sack_end(4)` = 17B | 纯控制段，不占序号、不参与序号空间 |
| `RST` | 0x03 | `type(1) \| code(1)` | 立即作废，丢弃全部在途 |

字段一律小端。`seq` 是**字节序号**（不是段号）：`seq` 为本段首字节在发送字节流中的
绝对偏移。这样累积确认 `cum` 直接等于"已按序收到的字节数"，重传时的切块边界与原始段
不同也不会让对端记账错乱。

- 两个方向各自从 **0** 开始编号，不需要随机初始序号：跨连接串流的威胁已经被"每连接一条
  会话 + 明文 salt 派生独立会话密钥"（§3、#28①/F1）挡在信封认证之外，随机 `iss` 只会多出
  一套需要同步的编号空间（初版实现就是这样写的，`rcv_nxt` 误用本端 `iss` 初始化导致两个
  方向串到同一空间，单测第一轮就抓出来了）。
- `fin` 用一个**独立的零长 `DATA` 段**携带，占用最后一个数据偏移之后的 1 个伪序号，
  与 TCP 的 FIN 同构。好处：关闭点天然落在序号空间里，被同一套累积确认覆盖，且接收端
  收到 `cum == fin_seq + 1` 即代表"数据全部交付 + 对端已关闭"，不需要二次确认语义。
- `ACK` 携带**单个 SACK 块**（`[sack_start, sack_end)`，左闭右开，空块时两者相等且都等于
  `cum`）。只报第一个乱序区间而不做位图：本层的职责是"别让洞等满一个 RTO"，一个块就够
  把 `cum` 之后的第一个洞点出来；多个洞交给 RTO 兜底。位图口径（`sack_base + 64bit`）在
  字节序号空间里没有稳定的 bit 含义，已放弃。
- ACK 时机：**每收到一个 DATA 段立刻回一个 ACK**，不做延迟确认。这让 RTT 样本密集、
  实现简单，代价是控制段与数据段近似 1:1（17B 对 1336B，约 1.3% 开销），列入 §7。
- **帧层的跨集合去重必须关掉**（`SessionConfig::sn_of = nullptr`）：M1 的 `FrameRx` 在集合
  内去重（`orig_mask`/`recov_mask`）之外还有一层按 payload 里"KCP sn"（偏移 12 的 4 字节）
  做的跨集合去重，用于合并同一 sn 的 FEC 重建与 KCP 重传。FCP-STREAM 的段不是 KCP 段，
  偏移 12 落进数据或 SACK 字段里；而重传**故意**重复同一个 `seq`——接收端要靠再收一次才会
  重发 ACK。两层假设撞在一起的表现是：接收端把合法重传当重复吞掉，不再回 ACK，发送端
  无限重传（集成测试里 `late_dup=83 / delivered=50`，窗口停在 199866/204800 达 30s）。
  字节层的去重本来就是 Stream 的职责（越界部分裁成 0 字节后照常确认），帧层这一层对
  stream 载荷只有害处。默认值保持 `&kcp_sn_of`，M1 的 KCP 载荷路径行为不变。

### 2.1 发送侧

- `snd_una`：最早未确认字节偏移；`snd_nxt`：下一个待发送偏移。
- 在途集合按段保存（未确认即不释放），`in_flight = Σ 未确认段的 wire_len`，
  `wire_len = 用户字节 + (fin ? 1 : 0)`。
- 拥塞/流控（最小版）：`in_flight ≤ min(固定发送窗口 W, 对端 rwnd)`，`W` 默认 256 KiB
  （`StreamConfig::send_window_bytes`）。无慢启动、无拥塞避免——FCP 的 FEC 与
  FECSTAT 闭环负责丢包侧，本层的窗口只防接收端缓冲溢出与在途失控。这是刻意的取舍，
  列入 §7 已知边界。
- 重传两条路径：
  - **超时**：`RTO = clamp(2 × srtt, 100ms, 5s)`（`rto_min_ms`/`rto_max_ms` 可配）。
    段按发送顺序排队，所以从头扫、遇到第一个未到期的就停。
  - **SACK 补洞**：`sack_start` 落在 `snd_una` 之后说明它前面就是洞，立刻重发
    `[snd_una, sack_start)` 区间内已上线的段。`sack_filled_up_to_` 单调递增，同一洞不重复
    补；已在本次 RTO 内重发过的段不叠加（避免超时+SACK 双份流量）。
- RTT：Karn 规则——一次 ACK 弹出的集合里只要含重传段就整轮丢弃样本；否则取其中**最新**
  一条干净样本，`srtt = srtt + (sample − srtt) / 8`（无中间方差项，最小版）。每个新
  `srtt` 通过宿主回调 `RttFn` 上报，宿主再调 `Session::on_rtt_sample()`，从而让 §5 的
  `late_guard = clamp(RTT,100,500)`、墓碑时长与 §8 的排队护栏取到真实 RTT 而不是默认 200ms。

### 2.2 接收侧

- `rcv_nxt`：已按序交付给应用的字节偏移。乱序段进 `oob` 列表（按偏移排序、相邻即合并），
  只要与 `rcv_nxt` 相接就合并前缀并交付，然后回 ACK。
- 接收缓冲上限 `rcv_buf`（默认 256 KiB）：`rwnd = rcv_buf − oob 已占字节`，在 ACK 中通告。
  合并时已有字节优先；新块放不下的**尾部按字节截断**，所以 `oob` 恒 ≤ `rcv_buf`，`rwnd`
  不会通告成负数或被一段超额顶穿。被截断的字节仍是未确认状态，发送端会重传。
- 单个 SACK 块就是 `oob` 的第一个区间——相邻乱序块已经合并，所以连续的一大段空洞只会占
  一个块，正好点出"从 `cum` 起第一个缺的地方"。
- 越界/重叠段（整段落在 `rcv_nxt` 之前、或部分重叠）按字节裁剪，裁掉的字节计入
  `dup_bytes`；整段重复仍然回 ACK，否则发送端的 RTO 会一直触发。
- `rwnd == 0` 时发送端停发数据但仍发 ACK；每 `probe_ms`（默认 1000ms）放行**一个**段
  做零窗探测，`probe_credit_` 只给一次额度。与 TCP 的 1 字节探测不同，这里放出去的是一个
  整段：本层的分段粒度是"待发队列的下一个整段"，切 1 字节会让后续重传重新切块，收益不如
  直接把窗口阻塞的第一个段推出去让对端重新通告。
- 交付是**同步回调**（`ReadFn`），宿主必须把它写进本地 socket 或缓冲；宿主背压由
  `Stream::can_write()`/`write()` 的返回值表达，本层不自行无限缓冲。回调可能在同一调用栈
  里回到 `on_segment()`（进程内回环宿主会这样），所以交付与发包都先更新自己的状态、再把
  字节交给宿主，迭代 `tx_` 用下标而非引用。

### 2.3 关闭与错误

两个事件、两个回调，代理宿主需要区分：`EofFn()` 只表示**读侧结束**（对端 fin 已按序交付），
此时本端仍可继续发数据；`ClosedFn(reason)` 表示**彻底拆除**，每条流最多触发一次。

| 事件 | 本层动作 | 对本地 TCP 的映射 |
|---|---|---|
| 收到 `fin` 且已追平到交付点 | 转 `kPeerClosed` → 回调 `EofFn()`；此后仍逐段回 ACK | 读侧 EOF，`shutdown(local, SHUT_RD)` |
| 本地 socket EOF | `close()` → 排空待发队列后发独立 fin 段（即使无数据也发，对端要靠它才知道结束），状态 `kSendingFin`；`cum ≥ fin_seq + 1` 且读侧已 EOF → `Closed(kLocalEof)` | 写侧 `shutdown(local, SHUT_WR)` 半关闭 |
| 半关闭后对端仍在发数据 | 照常交付：本端 fin 被确认不等于连接作废 | 继续读 |
| 本地 socket 出错 / 用户停止 | 发 `RST{kAbort}` 并立即回收 | `close()` + RST |
| `idle_timeout_ms`（默认 300s）**无入站** | `Closed(kIdle)`；自己发包不续命，所以链路死了能被发现 | 关闭 |
| `RST` 到达 | 丢弃在途、`Closed(kReset)` | RST |
| `fin` 之后仍来数据 | 协议违例，直接丢弃该段（不重传、不改变状态） | — |
| 握手失败（Session 层 `kNoAck`） | 宿主调 `Stream::abort()` → `Closed(kReset)` | 本地侧回 `REP=host unreachable` |

## 3. 会话与 salt

每条被代理连接 = 一条 FCP 会话，复用 M1 既有机制，不新增协议字段：

- 信封头本身就是 `salt(8) | nonce_ctr(8) | 密文 | tag(12)`，salt 明文携带；
  会话密钥 `session_key = AES128(PSK, salt ‖ 0×8)`（#28①/F1）。因此**同 PSK 的多条并发
  会话必须用不同 salt**，否则 (key, IV) 跨会话重用。
- 客户端每连接生成 8B 随机 salt；服务端用 `SessionTable::add()` 注册，返回 false
  （salt 冲突）时拒收该会话并记 `salt_clash`。8B 随机的生日碰撞在 10⁶ 并发下仍 <10⁻³，
  且冲突只会导致一次连接失败，不会串流（不同 salt → 不同密钥 → 认证失败）。
- 服务端收包路径：解信封需要 salt → 先读明文 salt 查 `SessionTable`，未知名则用
  "待建会话"路径（新 salt 的首包按 HELLO 处理，握手成功后才入表）。HELLO/HELLO_ACK
  是 oob 帧（#25），因此未认证包不会进 FEC 路径。
  落地口径（`ProxyEngine`）：服务端不预知 salt，连接表就是 `by_salt_`（8B 明文 salt →
  conn）与 `by_conn_` 双索引；首次见到的 salt 直接建 `Conn` 并**采用该 salt** 作为会话
  salt（`create_server_conn`），因此"待建会话"与"已建会话"在引擎里是同一张表，没有第三条
  路径。salt 已在表但源地址不同 → 记 `salt_clash` 并立刻关（信封用的是同一把密钥，认证
  挡不住第四方重放，这里是唯一能 enforce 绑定的地方）。
- 会话生命周期与 TCP 连接一一对应：连接关闭即 `SessionTable::remove()`，
  不留悬挂会话。服务端另有 `--max-sessions`（默认 256）与空闲回收。

## 4. 代理入口与隧道报文

### 4.1 本地 SOCKS5（仅 CONNECT）

标准 GSS 无关子集：方法协商只接受 `NO AUTH`(0x00)，客户端没提供时回 `05 FF` 后关闭；
请求 `CMD=CONNECT`，`ATYP ∈ {0x01 IPv4, 0x03 DOMAIN, 0x04 IPv6}`；其余 CMD 回
`0x07 command not supported`，未知 ATYP 回 `0x08`。绑定地址回 `ATYP=0x01, 0.0.0.0, 0`
（不承诺真实出口地址）。

编解码在 `src/fcp/proxy_proto.h/.cc`（纯函数、无 socket、无时钟），三条贯穿 §4 的约定：

- **字节序**：代理侧报文（SOCKS5 与 OPEN）的多字节字段是**网络序（大端）**，与 RFC 1928
  一致；FCP-STREAM 自身的段头是小端。两者不是同一套口径，也互不解析，所以不冲突。
- **消费长度**：解析成功时输出整条请求的字节数，其后的字节属于被代理的连接，宿主原样
  转进隧道、一个都不能吃；`kNeedMore` 不消费任何东西，宿主继续收。
- **坏形与短读的区分**：`RSV≠0`、`NMETHODS=0`、DOMAIN 长度 0、端口 0、域名含非法字符、
  版本非 5 都判畸形（不回复、直接关）；首字节不是 `0x05` 立刻判定"不是 SOCKS5"，不必等
  凑满问候。请求最长 `kSocks5MaxRequestBytes = 262`，解析只看这个窗口——客户端可以把
  问候、请求和首批数据写进同一次 `send()`，超出部分天生属于隧道。

### 4.2 本地 HTTP CONNECT

解析 `CONNECT host:port HTTP/1.x` + 头部直到 `\r\n\r\n`（头部总量上限 8 KiB，超限
`431`/关闭）；成功回 `HTTP/1.1 200 Connection Established\r\n\r\n`。非 CONNECT 方法回
`405`，其余坏形回 `400`，两个错误响应都带 `Connection: close`；响应体是常量、不含任何对端
输入，因此没有头注入面。隧道被服务端拒绝时（头部早已收齐、`200` 还没发出）回 `502`
（`HttpReply::kBadGateway`，同样 `Connection: close`）——`400/405/431` 只能答请求本身，
`502` 是这条链路上唯一在"请求合法之后"才可能的失败。TLS over CONNECT 与 SOCKS5 之后的
流量都是裸字节，本层不解析。

口径补充（`tests/proxy_proto_test.cc` 逐条钉住）：

- 版本接受 `HTTP/1.0` 与 `HTTP/1.1`，其他（含 `HTTP/2.0`）算 `400`；行尾只认 CRLF，裸 LF
  不算换行。头部没读满 `\r\n\r\n` 之前一律 `kNeedMore`，所以方法判断发生在头部收齐之后
  ——一个被截断的 `GET` 头部先表现为短读，收满才回 `405`。
- 目标恒为 `kAtypDomain`（IP 字面量也一样）：远端解析走 `getaddrinfo()`，对字面量本来就
  短路，把文本透过去比在本层手写 `inet_pton` 更省、也更不容易出错。带方括号的 IPv6
  （`[::1]:8443`）去掉方括号、保留地址文本。
- 端口必须显式给出且落在 1–65535（`CONNECT` 的 authority 没有默认端口），主机名 ≤255
  字节——这正是 OPEN 的长度字段上限，超了拒绝而不是截断。
- 431 的判据是"预算用尽且窗口内没有空行"：扫描窗口就是 8 KiB，所以宿主读超了也不会
  改变结论；空行之后还有字节的完整头部照旧 `200`，多出来的进隧道。

### 4.3 隧道 OPEN（有序流上的第一段字节，非独立帧）

```
OPEN     : "FCPO"(4) | ver(1)=1 | atyp(1) | len(1) | addr(len) | port(2)
OPEN_OK  : "FCPO"(4) | ver(1)=1 | 0x01 | reserved(2)
OPEN_ERR : "FCPO"(4) | ver(1)=1 | 0xFF | code(1)
```

`atyp` 同 SOCKS5；DOMAIN 长度 1–255，IPv4/IPv6 的 `len` 必须分别是 4/16，不符即
`kBadAddress`。长度：OPEN 请求 = `9 + len`（最长 `kOpenMaxBytes = 264`）、OPEN_OK = 8、
OPEN_ERR = 7；端口同样是网络序，`port = 0` 既编不出也解不出。OPEN_OK 的 reserved(2) 必须
为 0，收到非 0 说明两端对格式的理解不一致，按 `kBadReserved` 关流而不是继续隧道。请求与
应答的解析同样遵守"消费长度"契约：其后的字节都属于隧道，故 `len` 可以大于报文本身。
**域名由服务端解析（远端解析）**，客户端不做本地 DNS，避免泄漏与污染绕过。`code`：
1 refused（策略）、2 dns、3 target timeout、4 not supported（atyp 未知）、5 too many
sessions。`OPEN_OK` 之后双向都是裸字节。`OpenError → Socks5Rep` 的映射放在同一层
（`socks5_rep_for_open_error`），客户端只转发：refused→`0x05`、dns→`0x04`、
timeout→`0x06`、not supported→`0x08`、too many→`0x02`；HTTP 监听侧五种 code 一律回
`502`（`4xx` 已经用完了，且失败原因确实来自上游）。**一条隧道只拒一次**：`OPEN_ERR` 发出
后即使迟到的 `on_dial_result(ok)` 到达也不改写结论。服务端解析用可注入的 `Resolver`
接口（CLI 用工作线程，Qt 用 `QHostInfo`），解析超时 5s。

## 5. 链路参数预热

短连接是自适应 FEC 的天然盲区（规格 §14.13）：一条会话要跑出一个 FECSTAT 报告周期
才有第一个 k 决策（2s **且** 累计 256 个 data 符号，否则退到 60s 强制上报）。
每连接一条会话会把这个代价按连接重付，因此：

- 库侧新增三个**默认保持 M1 行为**的可选字段：
  - `SessionConfig::initial_srtt_ms`（0 = 沿用内部默认 `kDefaultSrttMs = 200ms`）：
    让首包起 `T_flush`、`late_guard`、墓碑就用历史 RTT。只暖 `srtt_ms_`，
    `min_srtt_ms_` 仍从 0 起步，所以 §8 的排队护栏不会拿缓存基线当"最小 RTT"，
    护栏只在看过真实样本之后才生效；
  - `SessionConfig::initial_k`，原样透传给 `FecStrategyConfig::initial_k`
    （−1 = 按 §8 从 OFF 冷启动；≥1 = 直接以该 k 进入 ON；0 表示"上次链路是干净的"，
    与冷启动等价，缓存里存成 −1）。**它是起点不是设置**：上报照常驱动状态机，暖过头会
    一路降下来、clean streak 照常把它 retire 回 OFF。`pinned_k` 存在时由它接管状态机
    （含"钉在 0"），此时 seed 一律作废，不会出现"钉 OFF 却被预热打开 parity"的组合。
- 宿主侧 `src/fcp/prewarm.h/.cc`：`PeerProfile{srtt_ms, initial_k}` +
  `PrewarmCache`（键 `peer_key(host, port)`，裸 IPv6 自动加方括号；TTL 10 分钟；写者覆盖；
  `get()` 只把过期项读成缺失、`prune()` 才回收；条目上限
  `kPrewarmMaxEntries = 4096`——服务端那侧的键是**客户端自选的地址**，不收口就等于
  让对端决定本进程的内存；写满时先清过期项，仍满则拒绝写入，代价只是那一条会话冷启动）+
  `apply_prewarm()` 把缓存值写进 `SessionConfig`/`StreamConfig`（两个先验各自独立：
  只有 RTT 也照样暖计时器）。记录时机是会话结束（或周期性）时的**本端发送侧**
  `Session::k()` 与 `Stream::srtt_ms()`——k 由发送端依 FECSTAT 决定，客户端与服务端各存各的。
  缺失/过期即冷启动，宿主无需分支。
- 冷启动保护：预热值超过当前 `p_max` 时按 `p_max` 截断（与 `pinned_k` 同一钳位口径，
  在 `FecStrategy` 构造里做，`p_max_` 已经是 `min(p_max, P')`，stats 模式下为 0 → 不预热）。
  会话日志会打一行 `FEC warmed: k=N (prewarm)`（截断后的实际值），与
  `FEC pinned: k=N (operator)` 分开，便于在代理控制台里区分"操作员钉的"和"缓存带的"。
- 副作用要记在账上：暖过的 RTT 会让结算更紧（`late_guard = clamp(RTT,100,500)`、
  墓碑 `= clamp(2×RTT,200,1000)`）。缓存值偏小时首两个报告的迟到容忍度下降，
  表现是个别符号从"迟到可收"变成"迟到丢弃"，由本层 ARQ 重传兜住，不影响正确性。

`tests/prewarm_test.cc`（13 场景）覆盖：默认配置行为与 M1 冷启动一致、seed 进入 ON 且
仍可收敛/仍会爬升、seed 的三档截断（`p_max`、`p_max=2`、stats 的 0）、pinned 接管、
`peer_key` 的 IPv6 括号、TTL 命中/过期/刷新/prune、条目上限（刷新已存在的键不算插入、
表满时先清过期项再写、全满则拒收新键）、`apply_prewarm` 的独立性与 no-op、
以及会话侧"新会话第一个集合就带 parity，且不需要任何 FECSTAT 上报"这一条正面证据
（`k=3` seed 下单符号集合按 `k_eff = ceil(k·n/D)` 缩到 1 个 parity，仍完成重建）。
T33（同链路 20 条短连接的开/关对比）的两个开关都已就位（默认开、`--no-prewarm` 关）。
WAN A/B 已随 #22 收口（见 §8.1）：先 1MiB 预热传输学出 k，再 40 条 64KB 短连接，预热开
每条省 ~0.43s（~25%）；5.4KB 小响应上差异低于运行间漂移（固定成本 ~4×RTT 主导，预期）。

## 6. 模块与文件

| 位置 | 内容 | 依赖 |
|---|---|---|
| `src/fcp/stream.h/.cc` | FCP-STREAM v1（纯逻辑，无 socket、无时钟，时间由宿主传入） | 仅 std |
| `src/fcp/prewarm.h/.cc` | `PeerProfile` / `PrewarmCache` / `apply_prewarm`（§5） | 仅 std、`session.h`、`stream.h` |
| `src/fcp/proxy_proto.h/.cc` | SOCKS5 / HTTP CONNECT / OPEN 编解码（纯函数） | 仅 std |
| `tests/stream_test.cc`、`tests/prewarm_test.cc`、`tests/proxy_proto_test.cc` | 单测，注册进 ctest 门禁 | — |
| `apps/fcp-proxy/engine.h/.cc` → `fcp_proxy_core` | `ProxyEngine`（连接表 + salt 路由 + tick + 预热缓存）。**无 socket、无真实时钟**：宿主以 `Host` 回调注入收发与 DNS，时间全部由 `now_ms` 参数传入，因此 ctest 能直接驱动它 | `fcp` |
| `apps/fcp-proxy/reactor.h/.cc`、`cli.h/.cc`、`main_client.cc`、`main_server.cc` | 跨平台 select 反应堆（Windows 非阻塞 connect 的 `exceptfds` 语义；名称解析走 4 线程池 + 全部 A/AAAA 记录顺序回退；POSIX `fd ≥ FD_SETSIZE` 守卫；64 KiB UDP 收包缓冲；服务端 peer 槽随会话销毁回收；数值参数区间校验）、共用参数解析、CLI 双端入口 | `fcp_proxy_core`、`ws2_32`(Win) |
| `tests/proxy_engine_test.cc` | 引擎级 socket-free 场景（16 个：SOCKS5/HTTP 往返、`OPEN_ERR → 本地应答`映射、畸形入口、背压、**部分拒绝后的零窗恢复**、salt 路由与重放绑定、短连接无残留、拨号超时与 grace 钟、会话上限、tombstone 尾段吸收、trace 落盘、未认证首包不成会话、认证前非 HELLO 超时、拨号背压上限、peer 回调配平） | `fcp_proxy_core` |
| `apps/fcp-client/proxy_host.h/.cpp` → `ProxyHost` | Qt 侧适配器：`QTcpServer` 收本地 SOCKS5/HTTP 入口、`QUdpSocket` 走 FCP wire、`QHostInfo` 解析拨号目标、25ms `QTimer` 是引擎唯一时钟；全部在 GUI 线程（与 BenchEngine 同构，两功能可共存）。`app_send` 实现为高水位写（Qt 的 `write()` 恒全量接收，按 256KiB 上限截断才能保住 §7 第 8 条的不变式），`app_close` 走 `disconnectFromHost()` 优雅排空（`abort()` 会丢掉 Qt 写缓冲里的尾字节），UDP 收发缓冲对齐 CLI 的 2MiB。页面入口见 `MainWindow::buildProxy()`（导航第 3 页），QSettings 键 `proxy/*`，`--proxy-host/--proxy-port/--proxy-listen/--proxy-psk/--proxy-autostart` 供脚本化验收 | `fcp_proxy_core`、Qt Widgets/Network |

`fcp_proxy_core` 是独立静态库且在 `FCP_BUILD_PROXY`（默认 OFF）之外：Qt 客户端只链接引擎、
不需要 CLI 的两个可执行文件，而门禁必须能在不开 `FCP_BUILD_PROXY` 时跑到引擎。反应堆与
`main_*` 才受该开关约束（根 `CMakeLists.txt` 用 `FCP_BUILD_PROXY OR FCP_BUILD_APP OR
FCP_BUILD_TESTS` 决定是否进入 `apps/fcp-proxy`）。

## 7. 已知边界（明确不做，写在这里以免被当成缺陷）

1. **无拥塞控制**：固定发送窗口 + rwnd 流控。跨 WAN 的多连接并发下会公平性不佳；
   与 §"VPS 单线程会话在 >30 Mbps 饱和"是同一类天花板。
2. **只做单块 SACK 补洞，不是完整快速重传**：没有重复 ACK 计数、没有多个洞的 SACK、
   没有拥塞窗口减半。第一个洞由 SACK 立即补上，后续洞仍等 RTO——burst 丢包（规格
   §14.10、实测单组修复率 60% vs 模型 87%）下尾延迟会高于 KCP 级实现，这是"最小可靠
   有序流"的定价（原先"完全不快速重传、洞只靠 FEC 或 RTO"的口径已被实测吞吐否掉：
   20 Mbps 下纯 RTO 恢复会让在途窗口长时间空转）。
   **（M3 #27 已补齐，2026-10-31）**：接收端在重复 ACK 上轮转 SACK 块 + 发送端
   dup≥3 强制补首洞；同一确定性 burst 场景 225ms → 25ms，设计见 `FCP_M3_CONTROL.md`
   §4/§4.1。拥塞窗口减半仍不做（§7 第 1 条不变）。
   **（M4 #33 同链路 A/B 实证）**：真实 WAN（181ms）上 `b6f76d2` 双端 1.45–2.21 Mbps vs
   HEAD 双端 4.51–4.92 Mbps——M3 改动兑现单流 2.2–3.2 倍；本条"定价"自此有对照数据。
3. **每个 DATA 段立刻回 ACK，无延迟确认**：控制段与数据段近似 1:1，17B 对 1336B 约
   1.3% 额外开销，换来 RTT 样本密集与状态机简单。M2 不做 `delayed_ack` 计时器。
4. **不支持 UDP ASSOCIATE**：DNS/QUIC/游戏流量不走代理。远端解析覆盖 DNS 泄漏的主要场景。
5. **不做静态端口转发与 TUN**：需要管理员权限与驱动的部分留待后续。
6. **每连接一次握手**：WAN 实测建链 57–156ms（预算 2.1s），短请求首字节延迟会高于
   多路复用方案；预热只缓解 k/RTT 冷启动，不消除握手往返。
7. **单线程引擎**：CLI 与 GUI 都在一个循环里跑全部会话，吞吐天花板与 §16 的
   VPS 单线程结论一致。
8. **缓冲全归引擎，`send_space()` 数的是"已写未确认"**：`Stream` 的发送配额是
   `bytes_queued_ - bytes_acked_`，不是 `in_flight_ + tx_pending_`。原因是 `pump()`
   把待发送字节切成段是**无条件**的，被对端窗口挡住的那批段既不在 `in_flight_` 也不在
   `tx_pending_`——旧口径对它们完全失明，写侧会一直被通知"还有空间"，于是慢读者能把
   发送队列撑到无上限。改后的代价是窗口关闭时 `write()` 直接返回较少字节，宿主必须
   重排队（反应堆用 `wants_local_read()`/`wants_target_read()` 表达这件事）。定死的上界：
   每条连接每侧内存 ≈ `send_window_bytes + rcv_buf_bytes`，`tests/proxy_engine_test.cc`
   的 `backpressure_closes_the_window` 与 `tests/stream_test.cc` 的
   `TestStalledReaderBoundsTheSendQueue` 一起守这条不变式。
9. **Windows 被拒绝的 connect 只走 `exceptfds`，而且要 ~2.05 s 才报**：非阻塞
   `connect()` 失败在 Winsock 里不进 `writefds`，必须查异常集（`reactor.cc` 已处理，
   否则拒绝目标会从 `OPEN_ERR 1`→SOCKS `0x05` 退化成等满拨号超时）。而"多久报出来"是
   Windows TCP 栈自己的：实测回环上打向 closed 端口，`select` 异常集、
   `WSAEventSelect(FD_CONNECT)`、甚至**阻塞** `connect()` 三条路径都是 2047ms 上下，
   Linux 则立即返回 `ECONNREFUSED`。因此 CLI 联调里"拒绝目标 2.087s"是 OS 开销，
   代理侧只占 ~0.1s，不是缺陷、也修不动。
10. **grace 钟只在有进展时滑动**：`on_tick()` 里 `progress_of()`（已确认 + 已交付 +
    应用已收）变了才重新计时，时钟到点才关会话，理由按 `app_in`/`to_stream` 是否非空
    分成"应用 socket 不再收字节"与"对端不再确认"。这条钟只在 `only_if_idle` 时装一次，
    且判超时的 `kDialing` 分支必须带 `!closing` 守卫——否则已被拨号截止判死的隧道每 tick
    都赢下第一个 `else if`，grace 截止永远不会被读到，服务端会话会一路活到 idle 超时。
11. **宿主回调不得重入引擎**：`Host` 的回调只允许标记 `Phase::kDone` 并把 id 压进
    `reap_ids_`（关闭）或 `dial_queue_`（待拨号），真正的销毁与 `host_.dial` 发起统一在
    `reap()` 里做（`in_reap_`/`in_flush_dials_` 双守卫；`flush_dials()` 按 id 逆序、
    逐个重新 `find()` 并跳过 `closing` 与非 `kDialing` 的会话，因为队列存 id 正是为了
    防 `Conn` 在这段行走中失效）。写新宿主（Qt 适配器）时这是第一条要遵守的规则。

## 8. 验收线（新增 T28–T33）

| # | 场景 | 通过条件 |
|---|---|---|
| T28 | Stream 单元：有序/乱序/裁剪/重叠/单块 SACK/零窗口与探测 | 交付字节与源完全一致，无重复、无越界写 |
| T29 | Stream 单元：累积 ACK + RTO 重传 + SACK 补洞（含 FEC 不可修洞） | 全部补齐；Karn 规则不产生污染样本；同一洞不重复补 |
| T30 | Stream × Session：`e2e_link.h` 随机与 burst 丢包注入 | 零错序零丢失；`on_rtt_sample` 有真实样本；恒等式零违例 |
| T31 | 代理协议：SOCKS5/HTTP/OPEN 分支与越界输入 | 错误码正确、拒绝畸形、无 OOB 读 |
| T31b | `ProxyEngine`（无 socket、虚拟时钟）：往返、`OPEN_ERR → 本地应答`、背压、salt 路由与重放、清理、超时 | 隧道级不变式成立；每连接内存受窗口与 rwnd 约束；会话表与预热缓存零残留 |
| T32 | 端到端：回环 + WAN 下 `curl --socks5`（HTTP 与 HTTPS 目标） | 内容一致、吞吐与 FCP 统计自洽、会话表无泄漏 |
| T33 | 预热收益：同链路连续 20 条短连接，预热开/关对比 | 首周期 k 冷启动消除，累计 parity 开销与有效吞吐可量化 |

落地情况：T28/T29 由 `tests/stream_test.cc`（15 场景）覆盖，T30 由
`tests/stream_e2e_test.cc`（6 场景：无损双向、纯 ARQ 随机丢包、pinned k 修复、burst 超出
RS 预算、半关闭、200KB 持续流）覆盖，§5 的预热由 `tests/prewarm_test.cc`（13 场景）覆盖，
T31 由 `tests/proxy_proto_test.cc`（18 场景：SOCKS5 问候/请求/应答与 0xFF/0x07/0x08 分支、
HTTP 的 200/400/405/431 与 authority 各种形态（含方括号 IPv6、255B 主机名、8 KiB 预算）、
OPEN 三种报文的往返与全部拒绝分支、`OpenError → Socks5Rep` 映射；每条报文都按"逐字节截断"
再解一遍，短读必须是短读、消费长度必须为 0）覆盖，T31b 由
`tests/proxy_engine_test.cc`（16 场景，客户端与服务端各一个 `ProxyEngine`，中间用内存管道
对拷 datagram，虚拟时钟 25ms/tick）覆盖；五者都在 `build.bat` 的 ctest 门内
（Windows Debug/Release 各 27/27，Debug 2.33s / Release 0.57s）。
`proxy_engine_test` 同时是 §7 第 8、10 两条不变式的守卫：`backpressure_closes_the_window`
在真实 `send_space()` 口径错的时候报 `pushed=409600 refused=0`（即无上限堆积），
`dial_timeout_and_grace_clock` 在 grace 分支不可达的时候让服务端 `live` 永远停在 1——
两个缺陷都是后被这个 socket-free 驱动逼出来的——CLI 回环联调把它们掩盖了（活着的会话
总会确认一次，队列还没来得及无限堆积就结了尾）。T30 用的回环载体沿用
`tests/e2e_link.h` 的 UDP socket 对，但其 `UdpSocket` 现在把 `SO_RCVBUF` 提到 1MiB——
默认 8KiB 在窗口级突发下会溢出，那部分丢失不进注入器计数，注入模型就不再"已知"了。

T32 的回环半边已在 `build/proxy-live/suite.sh`（git 忽略的临时目录）跑通七项：普通 GET、
`/big` 与 2MiB `/huge` 的 `cmp` 逐字节一致、分块 `/slow`、HTTP CONNECT + TLS、拒绝目标、
20 条串行 + 10 条并发；服务端收尾统计 `live=0 up=36 tunnels=35 refused=1 hs_failed=0
clash=0 over=0 unknown=0`，2MiB 传输 `t=0.366s`。

### 8.1 WAN 半边与 T33（#22，2026-10-31 收口）

环境：本机(电信) ↔ 测试 VPS（Ubuntu 24.04, g++ 13.3；地址不入库），RTT 180ms，当晚
下行丢包 10–17%（服务端 FECSTAT `pre` 口径 122923–182519ppm；fcp_bench 发/收差 7%，
ICMP 口径一度 20%）。部署注意：该
云商**只放行 UDP/40000**（UDP/40001 报文到网卡但不进 socket，与 §16 的 53/443 拦截同类）。

- **T32 WAN 七项全绿**：普通 GET、HTTP CONNECT + TLS（证书端到端校验）、5400B 与 8MiB
  逐字节 `cmp` 一致（直连同源对照）、拒绝目标（Linux 立即 `OPEN_ERR 1`→SOCKS `0x05`，
  0.43s——对比 Windows 回环的 2.1s 反向印证 §7 第 9 条是 OS 行为）、20 串行 + 10 并发。
  服务端收尾 `up=35 tunnels=34 refused=1 bad_entry=0 hs_failed=0 clash=0 over=0
  unknown=0`，客户端 `live=0`；两端统计自洽（服务端 wire tx 17.13MB ↔ 客户端收
  14.39MB，1.19× = parity + 重传）。
- **尾段竞态（WAN 可见、回环掩盖，良性）**：客户端会话先亡时，服务端迟到的重传在客户端
  计 `unknown_salt`（42 个，封顶不增长）；客户端 2 条 grace 钟 close 对应服务端尾段 FIN
  迟到，收尾统计前双端会话全部归零（服务端 `live` 从 14 → 0）。正确性不受影响；M3 若
  做优雅关闭可考虑 tombstone 之后短暂保留路由。**（M3 #29a 已收口：reap 的 salt 进 5s
  宽限墓碑，`salt_tombstone` 静默计数；服务端侧同根缺陷——迟到重传被误当新 HELLO 重建
  幽灵会话——一并修掉，测试见 `salt_tombstone_absorbs_tail`。）**
- **吞吐 = §7 第 2 条的 WAN 定价实测**：8MiB 下载自适应 k 51.9s（1.29 Mbps）、钉 k=3
  32.2s；速率曲线是 ~1MB 突发 + ~2s 停顿，即单块 SACK 之外等 RTO 的节奏；窗口
  256KiB→2MiB 仅 +12%（排除窗口瓶颈）。同日 fcp_bench 标定（无交付义务、令牌桶匀速、
  k=3 先验）同方向 25.8 Mbps——差值即"非完整快速重传"的价格，快速重传留 M3。
  （**勘误随 §8.2**：该"突发-停顿"节奏后被证实主要是子段窗口探针缺陷的签名而非纯
  §7 第 2 条定价；修复后同链路 8MiB 7.84s ≈ 8.56 Mbps。）
- **T33 预热 A/B**：每臂先 1MiB 预热传输学出 k，再 40 条 64KB 短连接（双端全新进程，
  开/关各两轮）：预热开 1.269/1.365s vs 关 1.727/1.777s（conns2+ 均值 t_total），
  **每条短连接省 ~0.43s（~25%）**；服务端 40/40 条 `FEC warmed: k=2 (prewarm)`。机制
  与 §5 预期一致：短会话凑不齐 FECSTAT 的 256 符号门槛、自己永远学不出 k，冷臂每个
  丢失都付本层 ARQ 往返，暖臂 parity 内联修复。5.4KB 响应（~5 段）上差异低于运行间
  漂移（0.79 vs 0.79s）——固定成本 ~4×RTT + 握手主导，预热对小响应无感。
- **#22 修掉一个真实缺陷**：CLI 参数解析要求所有选项必须带 `=`，帮助文本与文档承诺的
  裸布尔旗标 `--no-prewarm` 实际传不进去（"unknown argument"）。`CollectArgs` 现接受
  裸 `--flag`（存空串，`Find` 语义不变）。

Linux × Debug/Release ctest 均 25/25（与 Windows 同日四套全绿）。

### 8.2 GUI 代理页与 Qt 适配器（#23，2026-10-31 收口）

`apps/fcp-client/proxy_host.h/.cpp`（`ProxyHost`）+ `MainWindow::buildProxy()`（导航第 3 页：
服务器/PSK/监听口/MTU/钉 k/预热开关 + 活动连接、隧道、上下行累计与速率曲线；QSettings
`proxy/*`；`--proxy-autostart` 脚本化验收）。引擎仍是 socket-free 的 `fcp_proxy_core`，
GUI 线程 25ms tick 驱动，`QTcpServer`/`QUdpSocket`/`QHostInfo` 各司其职，§7 第 11 条
（回调不重入）靠"回调只碰 socket"守住。

**联调逼出两个真实缺陷，都修了：**

1. **子段窗口死锁（引擎级，`src/fcp/stream.cc`）**：发送端冻结在 `peer_rwnd=906`、
   `in_flight=0`、199 个段待发——窗口**非零但装不下一整段**（906 < 1336B）时，
   `probe_zero_window` 的 `peer_rwnd_ != 0` 短路让探针永不触发，且没有其他恢复路径。
   触发链：GUI 宿主的 256KiB 高水位 `app_send` 让接收端 `app_in` 停在 261238B
   （rwnd 广播 906），随后排空——重开的窗口没有任何 ACK 载体告知对端。修法：探针条件
   从"窗口为 0"改为"装不下第一个未发送段"。**回环 2MiB 由 60s 冻结 → 2.2s；#22 §8.1
   的"~1MB 突发 + ~2s 停顿"节奏即此缺陷的签名**——修复后同链路 CLI 8MiB 7.84s
   （8.56 Mbps，对比修复前 1.29 Mbps，含当晚链路好转的成分）。回归测试两层：
   `stream_test` 的 `TestSmallWindowProbeUnblocks`（sliver=50 < 117B 段）与
   `proxy_engine_test` 的 `zero_window_recovery_after_partial_refusal`（部分拒绝式背压）。
   注：T28 的原零窗测试只打了"恰好为 0"的粒度，侥幸未覆盖本态。
2. **Qt 关闭排空竞态（宿主级，`proxy_host.cpp`）**：引擎判定隧道结束（双向 FIN）后
   `app_close` 里 `QTcpSocket::abort()` 把 Qt 写缓冲中未落 to curl 的尾字节直接丢弃
   （CLI 的 `closesocket()` 默认优雅排空，所以只有 GUI 中招）——WAN 上 8MiB 稳定短
   1.7–5.5KB、短连接整条失败（响应整段死在缓冲里）。修法：`disconnectFromHost()` 优雅
   排空，且**不得**紧跟 `deleteLater()`（会抢在排空前删掉 socket），删除交给既有的
   `disconnected` 处理器。另：QUdpSocket 补 2MiB 收发缓冲（对齐 reactor 的 TuneUdp，
   默认 64KiB 在窗口级突发下溢出）。

**验收证据**（GUI 进程内代理，curl 直打 `127.0.0.1:1080`）：

- 回环（CLI 服务端 + node origin）：GET、5400B/2MiB 逐字节一致（2.2s）、CONNECT+TLS、
  拒绝目标 2.09s（Windows OS 口径，同 §7 第 9 条）、20 串行 + 10 并发全过。
- WAN（VPS 服务端）：GET / HTTPS-CONNECT 内容校验过、8MiB `sha256` 与源一致
  （6.36s ≈ 10.6 Mbps）、20 串行 0 败、10 并发 10/10；服务端收尾
  `up=76 tunnels=76 closed=76 bad_entry=0 refused=0 hs_failed=0 reset=0 idle=0
  clash=0 over=0 unknown=0`——零泄漏零异常。
- 四套门禁：Windows Debug/Release + Linux Debug/Release ctest 各 25/25（新增两场景）；
  `build_app.bat` Debug/Release 均通过并部署 Qt 运行时。

M2 验收线 T28–T33 至此全部落地；§7 第 2 条的"最小可靠有序流"定价在修复后重测为
8.5–10.6 Mbps（同链路、同 VPS），剩余天花板（单线程会话、单块 SACK）见 §7。

### 8.3 CLI 反应堆 / 引擎 / Stream 对抗复查（#30 续，2026-10-31）

M2 代理半边的第二轮对抗（首轮见 `FCP_M3_CONTROL.md` 的 #30 条）。本轮 10 轮分析中
第 8–10 轮落在 CLI/反应堆、重放工具与端到端不变式上；以下是实锤缺陷与修法。

1. **名称解析只用首条 A/AAAA（实机复现）**：`getaddrinfo("localhost")` 通常先返回
   `::1`，目标只监听 IPv4 时非阻塞 connect 失败，服务端报 `OPEN_ERR 1`、curl 收
   0 字节。回环冒烟（node 监听 `127.0.0.1:18080` + `curl --socks5-hostname
   127.0.0.1:11080 http://localhost:18080/`）稳定复现。修法：解析 worker 收集全部
   A/AAAA 记录（上限 16 条），反应堆按顺序逐条非阻塞 connect；同步失败直接下一
   条，异步失败在 `connect_event`/`except_event` 里继续，直到成功或耗尽。每条记录
   一份 `connect_timeout_ms`，总预算仍由引擎的 `dial_timeout_ms` 从上方封顶。复测
   三连 64 KiB 全部 `200 / 65536`，服务端日志三条 `tunnel open`。
2. **解析线程生命周期（UAF）**：旧实现的 detached 线程捕获 `this` 并写入
   `results_`，Reactor 析构后仍写。改为 `shared_ptr<ResolveQueue>`（线程按值持有），
   析构置 `stopping` 并唤醒；固定 4 worker + 256 job 上限，DNS 吊死不再按拨号数
   起线程，队列满/关闭时立即回 `OpenError::kDns`，不占着拨号钟。
3. **POSIX `fd_set` 越界**：旧守卫只数条目数；POSIX 的 `fd_set` 按 fd 值索引，fd ≥
   `FD_SETSIZE` 时 `FD_SET` 越界写。现在所有 FD_SET（含 udp_/listener_）先查
   `0 ≤ fd < FD_SETSIZE`；Windows 的 `fd_set` 是句柄数组，仍只查数量。
4. **UDP 收包截断与参数区间**：2048B 栈缓冲在 `--mtu > ~2KiB` 时静默截断（下游只
   表现为认证失败）；改为 64 KiB 成员缓冲，覆盖全部合法 UDP 载荷。CLI 补数值区间
   与整串校验（`--mtu` 256..65535、`--d` 1..255、`--p/--p-max` 0..7、`--k` -1..7、
   端口 1..65535，以及 `--window/--rcv-buf/--idle/--dial-timeout/--connect-timeout/
   --max-sessions/--stats` 与有限 `--fec-budget`），拒绝 `--d=abc`/`--mtu=99999`
   之类的静默截断。`--mtu` 的帮助文本同步更正为"IP packet budget incl. IP+UDP
   headers"——实现（`compute_mtu_limits`）一直按 IP 包字节计算，旧文案 "UDP payload"
   会让人把上界 65535 误当成 UDP 载荷。
5. **服务端 peer 槽只增不复用**：每个新源地址追加槽位，到 8192 后新客户端全被丢，
   NAT 端口轮换或垃圾源可长期占表。新增 `PeerSlot{refs, used}` + 空闲链表 + 轮转
   回收（只回收 `refs == 0` 的槽），引用数由引擎 `peer_bound`/`peer_retired` 回调
   维护（服务端会话创建/销毁成对，含未认证首包建会后立刻销毁的路径）；客户端固定
   peer id 0。`reap()` 先拷贝 peer id 再 `erase()`——Conn 销毁后再读是 UAF。
6. **nonce 预算耗尽的会话静默**（协议 §4.1 / T25）：旧实现只打日志并让 `seal()`
   拒发，连接吊死。`Session::set_send_nonce()/nonce_exhausted()` 公开测试/宿主
   接口；引擎 tick 发现耗尽即关闭应用侧——预算正是"发不出 ERROR 报文"的原因，
   线上没有额外控制帧。`session_test` 覆盖耗尽后不再出站。
7. **未认证首包与投递挂账**（引擎级）：服务端首包建会后认证失败必须立刻结束，不能
   留无主会话；`flush_app` 的 `set_delivery_pending` 计入 `app_in + stream_in`，
   否则拨号未完成时本地窗口实际可无限收字节（拨号背压场景守这条）。
8. **Stream 关闭/SACK 复核（无新缺陷）**：对端 FIN 到达但本端未确认的数据不会被提前
   丢弃（`TestPeerFinDoesNotDropUnackedData`）；越过 `cum`/`snd_nxt` 的 SACK 块被忽略
   （`TestInvalidSackBlockIgnored`）。两项守卫均为已入库测试（#31），本轮回归确认。
9. **统计计数器位宽不一致**（#31 引入）：`frame_rx` 的 `dup_after_recovered_` 成员是
   `uint64_t`，而访问器、引擎聚合与 stats 行（`duprec=%u`）都是 `uint32_t`，读取时静默
   截断，且每个包含该头的编译单元都报 MSVC C4244。与其余接收计数器统一为
   `uint32_t`，代理 Release 重建后该告警消失。

验证：Windows Debug/Release 均为 27/27；`--mtu=3000` 回环三连 64 KiB 字节一致；proxy_engine_test
新增未认证首包、认证前非 HELLO 超时、拨号背压上限与 peer 回调配平四场景。本轮未在
Linux 主机复跑（fd 守卫为 POSIX 条件编译，其余逻辑平台无关）；下次 Linux 门禁需覆盖
`reactor.cc` 的该分支。
