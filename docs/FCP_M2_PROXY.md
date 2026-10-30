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
输入，因此没有头注入面。TLS over CONNECT 与 SOCKS5 之后的流量都是裸字节，本层不解析。

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
timeout→`0x06`、not supported→`0x08`、too many→`0x02`。服务端解析用可注入的 `Resolver`
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
T33（同链路 20 条短连接的开/关对比）要等 `apps/fcp-proxy` 落地，属 #22 的联调范围。

## 6. 模块与文件

| 位置 | 内容 | 依赖 |
|---|---|---|
| `src/fcp/stream.h/.cc` | FCP-STREAM v1（纯逻辑，无 socket、无时钟，时间由宿主传入） | 仅 std |
| `src/fcp/prewarm.h/.cc` | `PeerProfile` / `PrewarmCache` / `apply_prewarm`（§5） | 仅 std、`session.h`、`stream.h` |
| `src/fcp/proxy_proto.h/.cc` | SOCKS5 / HTTP CONNECT / OPEN 编解码（纯函数） | 仅 std |
| `tests/stream_test.cc`、`tests/prewarm_test.cc`、`tests/proxy_proto_test.cc` | 单测，注册进 ctest 门禁 | — |
| `apps/fcp-proxy/` | `ProxyEngine`（连接表 + salt 路由 + tick + 预热缓存）、跨平台 select 反应堆、`main_client.cc`、`main_server.cc`；`FCP_BUILD_PROXY` 默认 OFF | `fcp` |
| `apps/fcp-client/` | 代理页 + Qt 侧适配器（`QTcpServer`/`QUdpSocket`/`QHostInfo` 驱动同一引擎） | `fcp`、Qt Widgets/Network |

## 7. 已知边界（明确不做，写在这里以免被当成缺陷）

1. **无拥塞控制**：固定发送窗口 + rwnd 流控。跨 WAN 的多连接并发下会公平性不佳；
   与 §"VPS 单线程会话在 >30 Mbps 饱和"是同一类天花板。
2. **只做单块 SACK 补洞，不是完整快速重传**：没有重复 ACK 计数、没有多个洞的 SACK、
   没有拥塞窗口减半。第一个洞由 SACK 立即补上，后续洞仍等 RTO——burst 丢包（规格
   §14.10、实测单组修复率 60% vs 模型 87%）下尾延迟会高于 KCP 级实现，这是"最小可靠
   有序流"的定价（原先"完全不快速重传、洞只靠 FEC 或 RTO"的口径已被实测吞吐否掉：
   20 Mbps 下纯 RTO 恢复会让在途窗口长时间空转）。
3. **每个 DATA 段立刻回 ACK，无延迟确认**：控制段与数据段近似 1:1，17B 对 1336B 约
   1.3% 额外开销，换来 RTT 样本密集与状态机简单。M2 不做 `delayed_ack` 计时器。
4. **不支持 UDP ASSOCIATE**：DNS/QUIC/游戏流量不走代理。远端解析覆盖 DNS 泄漏的主要场景。
5. **不做静态端口转发与 TUN**：需要管理员权限与驱动的部分留待后续。
6. **每连接一次握手**：WAN 实测建链 57–156ms（预算 2.1s），短请求首字节延迟会高于
   多路复用方案；预热只缓解 k/RTT 冷启动，不消除握手往返。
7. **单线程引擎**：CLI 与 GUI 都在一个循环里跑全部会话，吞吐天花板与 §16 的
   VPS 单线程结论一致。

## 8. 验收线（新增 T28–T33）

| # | 场景 | 通过条件 |
|---|---|---|
| T28 | Stream 单元：有序/乱序/裁剪/重叠/单块 SACK/零窗口与探测 | 交付字节与源完全一致，无重复、无越界写 |
| T29 | Stream 单元：累积 ACK + RTO 重传 + SACK 补洞（含 FEC 不可修洞） | 全部补齐；Karn 规则不产生污染样本；同一洞不重复补 |
| T30 | Stream × Session：`e2e_link.h` 随机与 burst 丢包注入 | 零错序零丢失；`on_rtt_sample` 有真实样本；恒等式零违例 |
| T31 | 代理协议：SOCKS5/HTTP/OPEN 分支与越界输入 | 错误码正确、拒绝畸形、无 OOB 读 |
| T32 | 端到端：回环 + WAN 下 `curl --socks5`（HTTP 与 HTTPS 目标） | 内容一致、吞吐与 FCP 统计自洽、会话表无泄漏 |
| T33 | 预热收益：同链路连续 20 条短连接，预热开/关对比 | 首周期 k 冷启动消除，累计 parity 开销与有效吞吐可量化 |

落地情况：T28/T29 由 `tests/stream_test.cc`（15 场景）覆盖，T30 由
`tests/stream_e2e_test.cc`（6 场景：无损双向、纯 ARQ 随机丢包、pinned k 修复、burst 超出
RS 预算、半关闭、200KB 持续流）覆盖，§5 的预热由 `tests/prewarm_test.cc`（13 场景）覆盖，
T31 由 `tests/proxy_proto_test.cc`（18 场景：SOCKS5 问候/请求/应答与 0xFF/0x07/0x08 分支、
HTTP 的 200/400/405/431 与 authority 各种形态（含方括号 IPv6、255B 主机名、8 KiB 预算）、
OPEN 三种报文的往返与全部拒绝分支、`OpenError → Socks5Rep` 映射；每条报文都按"逐字节截断"
再解一遍，短读必须是短读、消费长度必须为 0）覆盖；四者都在 `build.bat` 的 ctest 门内
（Windows Debug/Release 各 24/24）。T30 用的回环载体沿用
`tests/e2e_link.h` 的 UDP socket 对，但其 `UdpSocket` 现在把 `SO_RCVBUF` 提到 1MiB——
默认 8KiB 在窗口级突发下会溢出，那部分丢失不进注入器计数，注入模型就不再"已知"了。
