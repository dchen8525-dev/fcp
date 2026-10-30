# FCP v6 M1 任务跟踪清单

> 依据：`FCP_PROTOCOL_V6.md`（规格）+ `FCP_V6_DETAILED_DESIGN.md`（详细设计），
> 含 2026-10-30 文档审查勘误（规格附录 C #22–#25、设计附录 A #9–#13）。
> 本清单回答"先做什么、后做什么、做到哪了、怎么算做完"。
> 状态：☐ 未开始　◐ 进行中　✅ 完成　⛔ 受阻

---

## 1. 依赖关系（为什么是这个顺序）

```text
阶段A 纯算法（无状态，可并行，先做——最好测）
  A1 RS 域与矩阵 ──▶ A2 RS 编解码
  A3 加密信封        （独立）
  A4 线格式编解码     （独立）
        │
阶段B 有状态模块（按数据流向串行推进）
  B1 k_for 纯函数 ──▶ B2 策略状态机
  B3 握手            （依赖 A4）
  B4 发送路径        （依赖 A2+A4+B3）
  B5 接收路径        （依赖 A2+A3+A4+B3）
  B6 结算器          （依赖 B5）
  B7 FECSTAT 上报    （依赖 B6）
        │
阶段C 集成
  C1 Session 组装 ──▶ C2 端到端测试 ──▶ C3 回归+冻结+门禁
```

排期原则：**每个任务自带测试，测试不过不算完成**。A 阶段 5 个任务可并行；
B3 可与 B1/B2 并行；其余按依赖顺序。A3b 依赖 A3a。

---

## 2. 任务清单

### 阶段 0：工程骨架

| ID | 任务 | 产出 | 验证方法 | 状态 |
|---|---|---|---|---|
| T0 | 建工程骨架：`src/fcp/` + `tests/`、CMake、CHECK 宏、覆盖率统计、CI 门禁 | 可编译空工程 | `cmake --build && ctest` 通过（0 个测试也算过） | ✅ 2026-10-29 |

**T0 四项决策（2026-10-29 已确认）**：
1. 测试框架：**手写 CHECK 宏**（与 kcp-cpp 现状一致，零依赖）；
2. AES-GCM 来源：**FCP 内置独立实现**（不复用 kcp-cpp 的 gcm.cc，不引 OpenSSL；按惯例需对抗评审）；
3. 覆盖率门禁：**line ≥ 90 / branch ≥ 80**；
4. 语言标准：**C++20**（`CMAKE_CXX_STANDARD 20`，`CXX_EXTENSIONS OFF`）；新代码按 C++20 编写，
   不使用编译器私有扩展。

### 阶段 A：纯算法模块（无状态）

| ID | 任务 | 内容要点 | 验证方法 | 关联测试 | 状态 |
|---|---|---|---|---|---|
| A1 | GF(2^8) 域 + 柯西矩阵 | 生成多项式 0x11D，log/exp 表启动构建；`C[r][c] = 1/(x_r ⊕ y_c)`，x_r=r、y_c=k+c（设计勘误 #8）；两端同公式现场构造，不传矩阵 | ① 表性质：`exp(0)=1`、`g^255=1`、log/exp 互逆全表验证；② 任意子矩阵可逆性：随机抽 n/k 组合验证 k×k 子式非零（含边界 n=1、k=P）；③ 编码小样本 golden 冻结进仓库（自有参考值，无外部互验） | — | ✅ 2026-10-29 |
| A2 | RS encode/decode | `encode(data, n, k, symbol_max)` 算满 k 条（码长恒 n+k，k_eff 不进矩阵）；`decode` 擦除位填 nullptr；零扩展尾零 | 属性 fuzz：随机 n∈[1,10]、k∈[0,4]、symbol_max∈[1,1400]，任意丢 ≤k 片（含幽灵 parity 擦除）恢复后与原始逐字节一致 | T17、T22 解码部分 | ✅ 2026-10-29 |
| A3a | AES 核心 + GHASH | AES-128 块加密：AES-NI 硬件路径 + T-table 纯软件回退；GHASH（GF(2^128)，归约多项式 x^128+x^7+x^2+x+1） | ① FIPS 197 附录 C.1 标准向量；② NIST GCM test vectors（含 tag=12 截断用例）；③ AES-NI 与 T-table 两路径输出逐字节一致 | — | ✅ 2026-10-29 |
| A3b | GCM 封装 + 信封 | seal/open、28B 信封（salt8+nonce8+tag12）；IV=counter(8,LE)‖direction(1)‖0×3；nonce_ctr 到 2^48 断连；open 失败就地丢弃 | ① T19：空明文 wire=28、tag=12、IV 方向隔离；② 加解密往返；③ 篡改 1 bit 必拒；④ 旧 nonce_ctr 重放拒收；⑤ nonce_ctr 边界（2^48−1 → 断连） | T19 | ✅ 2026-10-29 |
| A4 | 线格式编解码 | FcpHdr 6B pack/parse + 5 条校验（顺序按设计 §4.2）；FECSTAT 128B 结构 + offsetof static_assert + 四类丢弃 + 单调键 | ① T16 golden：`(k<<5)\|(j<<2)\|type` 往返；j≥k / index≥S / n 越界全拒；② T1：128B、偏移断言、magic/salt/ver 校验、stale 拒收、dropped 原因四分类 | T16、T1 | ✅ 2026-10-29 |

### 阶段 B：有状态模块

| ID | 任务 | 内容要点 | 验证方法 | 关联测试 | 状态 |
|---|---|---|---|---|---|
| B1 | k_for 反解 + 二项分布 CDF | 策略的纯函数部分先做；目标修复率 0.80 | T20 反解表 golden：loss 2/5/10/15/20/25% → k=1/1/2/3/4/4（20% 不回落到 3）；CDF 数值与 Python 参考对齐（已有参考值：RS(10,8)@20%=67.8%（旧 8+2 几何、k=2）、RS(14,10)@20%=87.0%） | T20 | ✅ 2026-10-29 |
| B2 | 策略状态机 | OFF/ON 迁移、每报告 ±1、排队护栏（3 报告强降）、clean 5 报告回 OFF、防抖 3 报告、pin 绕过、样本不可信不动 | 状态迁移表驱动测试：① loss≥1.5% 立即进 ON；② 0.8%≤loss<1.5% 连续 2 报告进 ON；③ 护栏 streak=3 → k−1；④ clean_streak=5 → OFF；⑤ OFF 后 3 报告内 loss<4.5% 不再开启；⑥ pin 完全绕过 | T20 扩展 | ✅ 2026-10-29 |
| B3 | 握手 | Idle→HelloSent→Established/Failed；3×300ms 重试后 ERROR 断连；caps u16 校验；幂等；**协商前 data 缓存 64 段/64KB** | ① T11：3 次超时 ERROR；caps 违规（D'≥1、P'≤7、D'+P'≤256 用 u16）拒绝；② 双方同时 HELLO 交换成功；③ 重复报文吞掉；④ T21：Established 前 data 不上线、完成后按序补发 | T11、T21 | ✅ 2026-10-29 |
| B4 | 发送路径 | on_kcp_output、HELLO/ACK 前缀识别（逐段判定）、集合组装、T_flush=clamp(RTT,25,200)、close_set + k_eff、MTU 断言 | ① T12：满组/空闲/异常三路径计数正确；② T14：control 不占槽，data_expected == D×sets_expected；③ T17：3 包停 300ms → n=3、发 `min(k, max(1,ceil(k·3/10)))` 条、码长仍 n+k；④ T2：IPv4/IPv6 × {1400, 极值} 断言 | T4、T14、T17、T2 | ✅ 2026-10-29 |
| B5 | 接收路径 | on_datagram 分流、三张位图（orig/recov/parity 分离）、n 只由 parity 给出、try_decode（幽灵擦除）、sn 去重窗口 4096 | ① T4：data_rx_orig 不含重建项；② T9：伪造 len / n 冲突 / j≥k 全部 struct_fail；③ T18：(12,2)→n=10、(6,1)→5、无 parity 不重建；④ T22：k_eff<k 解码成功；⑤ sn 重复不二次交付 | T4、T9、T18、T22 | ✅ 2026-10-29 |
| B6 | 结算器 | eligible/accounted 判定、墓碑 clamp(2×RTT,200ms,1s)、整组全丢只计 sets_k_unknown、样本可信门 10%、恒等式自检 | ① T5/T6：整组全丢不进 expected、不虚增丢包率；k_unknown 占比>10% 标记 untrusted；② T13：late 首次交付计 data_late_rx、重复计 late_dup；③ 墓碑期内恢复不回填计数；④ 恒等式 `rx+rec+lost+late=expect` fuzz 断言 | T5、T6、T13、T22 | ✅ 2026-10-29 |
| B7 | FECSTAT 上报 | 2s/≥256 包节奏 + 60s 强制门、flg bit1/bit2、p50/p95 分位、reset 清零 | T15：① ≥256 包驱动 2s 上报；② 60s 强制上报且 interval_ms≈60000；③ flg 位与尾丢/迟到恢复对齐；④ 分位数正确、上报后计数器归零 | T15 | ✅ 2026-10-29 |

### 阶段 C：集成与验收

| ID | 任务 | 内容要点 | 验证方法 | 关联测试 | 状态 |
|---|---|---|---|---|---|
| C1 | Session 组装 | 每会话单线程、salt 哈希会话查找、定时器（25ms 轮询 + 2s FECSTAT）、模块接线 | 内存回环双端 Session：跑通 握手→数据→结算→FECSTAT→策略调 k 全闭环；日志输出与设计 §11 样例逐字段核对 | 全链路冒烟 | ✅ 2026-10-29 |
| C2 | 端到端测试 | 回环 socket + 应用层丢包注入（可设丢包率） | ① T3：k=0 无损，rx==expect、pre=0；② T7：重建/重传撞车只交付一次；③ T8：auth_fail 不触碰集合；④ T10：FRAMED_STATS 无 RS、k≡0；⑤ **20% 随机丢包 fuzz：data_delivered（含重建+重传）== 注入总数，恒等式无违例** | T3、T7、T8、T10 | ✅ 2026-10-29 |
| C3 | 回归 + 冻结 + 门禁 | golden 全部入库；对照规格附录 C 21 条逐条核验 | ① T1–T23 全绿（T23 随 D1）；② 覆盖率达门禁（CI 执行，本机无插桩工具链）；③ 附录 C 21 条 + #22–#25 逐条打勾记录；④ 双端在 0%/5%/20% 三档丢包下跑 10 分钟无 crash、无恒等式违例 | 全部 | ✅ 2026-10-29（② 待 CI；T23 随 D1 于 2026-10-30 补绿） |

### 阶段 D：2026-10-30 文档审查勘误落地（规格附录 C #22–#25、设计附录 A #9–#13）

| ID | 任务 | 内容要点 | 验证方法 | 状态 |
|---|---|---|---|---|
| D1 | 握手通道 oob 化（#25，取代原"control 判定收紧"方案） | HELLO/ACK 改为 **type=2 oob**（HELLO magic 补齐 16B、线上 16→20B；ACK 不变；`type=3` 取消未定义、收到按 struct_fail 丢弃）；删除成帧层内容分类与在途登记（#9/#22①/#23① 机制作废）；握手层自管 3×300ms 重传、Established 即停；握手 golden（HELLO 16→20B）重录 | T23（oob 化回归）全绿；以 `FCP_HELLO_V3` 开头的用户段按 data 进集合、零丢失；T14 oob 不占槽位 | ✅ 2026-10-30（`TestWireGolden` 20B/20B、`TestHandshakeRidesOob`、`TestHandshakeAckRidesOob`、`TestKcpOutputIsAlwaysData`、`TestInvalidTypeAndOobBypass`；Debug/Release 20/20） |
| D2 | 恢复可编译并补记 | `FrameRx::SnFn` 契约改动（`bool(payload,len,sn*)`，第二轮 F2）最初遗留 7 处调用点未同步、树不可编译；已随 F2 修复一并适配，`adv_test` 补记于验收文档 §10 | `build.bat Debug/Release` 全绿：20/20（1.7 s / 0.5 s） | ✅ 2026-10-30 |
| D3 | 慢链路 FEC 下限（§14.8，M2/M3 可选） | < 4.3 包/s 链路在 M1 机制下保持只观测；按速率放大强制间隔、或对慢链路单列样本门（如 `interval ≥ 60s` 时降为 ≥64） | 真实慢链路或仿真标定 | ☐ |

### 阶段 E：2026-10-30 网络协议评审 #27 落地（规格 #27、设计附录 A #14）

| ID | 任务 | 内容要点 | 验证方法 | 状态 |
|---|---|---|---|---|
| E1 | 握手重传指数退避（#27①） | `kHandshakeRetryMs=300` 固定间隔改为 **300→600→1200ms**（3 个 HELLO 上限不变、总等待 900ms → ~2.1s，覆盖 RTT ≤ ~700ms 链路）；Established 即停语义不变；重复 HELLO 幂等/必重发 ACK 不变 | T26：① 重传间隔序列 300/600/1200 断言（`next_retry_ms`）；② ACK 在任意退避阶段到达即停；③ 3 个 HELLO 后 ERROR；④ RTT=500ms 仿真（前两个 HELLO 丢失）握手成功（固定 900ms 预算下必失败）；⑤ 全量回归 Debug/Release 绿 | ✅ 2026-10-30（`handshake.cc` 退避 + `TestRetryBackoff`/`TestTimeout`/R9.4 更新；Debug/Release 20/20） |
| E2 | 突发丢包 burst 注入实测（#27②，验收项） | e2e 确定性 burst 注入（每 25 个 data 丢连续 5 个，均值 20%，仅 data、parity/oob 不丢）：实测单组修复率与 §8 二项表格值对照，量化 i.i.d. 假设偏差；不改机制 | `TestBurstLossRepairRate`（k=4 pinned，100 满组）：命中 40 组各丢 5 连片 > k → `recovered=0`、`sets_full=60/100`，实测修复率 **60.0% vs 二项 87.0%**（-27pp）；ARQ 兜底后 1000 段恰好一次交付、恒等式零违例 | ✅ 2026-10-30（`e2e_link.h` burst 注入器 + `e2e_test` 新用例；BURST 行随测试输出） |

### 阶段 F：2026-10-30 第二轮对抗复查 #28 落地（规格 #28、设计附录 A #15）

| ID | 任务 | 内容要点 | 验证方法 | 状态 |
|---|---|---|---|---|
| F1 | **会话密钥按会话派生（#28①，P0）** | 信封构造改为 `session_key = AES128-Encrypt(PSK, salt(8)‖0×8)`（复用 `aes128_encrypt_block`，不引入哈希），方向密钥 KDF 的 ikm 从 PSK 换成 session_key；`SessionConfig.key` 语义变为"PSK"，两端各自本地派生，零线上改动；服务端在线 salt 查重随即真正保证"并发会话密钥互异" | T27：① 同 PSK 不同 salt → session_key 互异；② 同 PSK 同 salt → 两端派生逐字节一致；③ 方向密钥从 session_key 派生 + 旧方案手工报文拒收（`envelope_test TestSessionKeyDerivation`）；④ T19/T25 回归绿；⑤ 全量 Debug/Release | ✅ 2026-10-30（`envelope.h/cc` `derive_session_key` + 构造函数重接；`TestSessionKeyDerivation` 新增、`TestRecvNonceLimit` 同步为派生密钥；Debug/Release 20/20） |
| F2 | 协商前缓存溢出反压（#28③，M2 前置评估） | **采用"按 BDP 放大缓存"路径**：默认上限 64 段/64KB → **512 段/512KB**，并经 `SessionConfig.handshake_cache_segments/bytes` 可配置；超限仍"丢弃并 ERROR"（响亮失败）。"暂停 KCP 泵"式反压需宿主配合（KCP 泵在库外），如部署仍触顶由宿主侧跟进（M2 记录） | `TestCacheLimits` 重写：显式小上限（4 段/16B）钉边界语义 + 默认上限 512×1KB 恰好容纳、513 段溢出；全量回归绿 | ✅ 2026-10-30（`handshake.h/cc` 构造参数 + `session.h` 配置透传） |
| F3 | FECSTAT 连发两份（#28⑤，M2 小项） | `FcpReporter` 每次报告连发两份（逐字节相同）；校验器新增 `kDuplicate`：键等于最近接受值的副本不计 `stale`/`dropped`，单独计 `fecstat_dup`，不污染诊断口径 | `fecstat_test`/`adv_test` 补 `kDuplicate` 断言；`session_test`/`e2e_test`/`reporter_test` 发送计数与 oob 流索引同步；全量回归绿 | ✅ 2026-10-30（`reporter.cc` 双发 + `fecstat.h/cc` `kDuplicate` + `session` `fecstat_dup`） |

---

## 3. T1–T23 → 任务映射（验收对照表）

| 测试 | 归属任务 | 测试 | 归属任务 | 测试 | 归属任务 |
|---|---|---|---|---|---|
| T1 FECSTAT golden | A4 | T9 struct_fail | B5 | T17 空闲闭合+k_eff | B4 |
| T2 MTU 断言 | B4 | T10 FRAMED_STATS | C2 | T18 n 由 parity 给 | B5 |
| T3 k=0 无丢失 | C2 | T11 握手失败 | B3 | T19 信封 28B | A3 |
| T4 位图分离 | B5 | T12 闭合三路径 | B4 | T20 k_for 反解 | B1 |
| T5 parity 全丢 | B6 | T13 迟到记账 | B6 | T21 握手期缓存 | B3 |
| T6 整组全丢 | B6 | T14 control 不占槽 | B4 | T22 幽灵 parity/恒等式 | A2+B5+B6 |
| T7 sn 去重 | C2 | T15 区间自适应 | B7 | T23 握手 oob 化回归 | D1 |
| T8 auth_fail | C2 | T16 头字段 golden | A4 | T24 重放窗口 256 | #26（envelope_test+adv R1.4） |
| T25 终止线+方向密钥 | #26（envelope_test） | T26 握手重传退避 | E1 | | |
| | | T27 会话密钥按会话派生 | F1（P0）✅ | | |

**勘误回归四主力**：T6（勘误③）、T17（勘误①）、T21（勘误④）、T22（勘误①⑤）——
这四条必须最严格，是五轮评审修出来的行为。

---

## 4. M1 完成标准（验收线）

1. T1–T27 全部通过（T24/T25 随 #26、T26 随 E1、T27 随 F1 均已绿），golden 数据冻结进仓库；
2. 双端回环在 20% 随机丢包下：`data_delivered == 注入总数`（重建 + KCP 重传兜底）；
3. 恒等式断言 `rx + rec + lost + late = expect` 在所有 fuzz 下零违例；
4. 覆盖率门禁达标；
5. 规格附录 C 21 条逐条核验记录归档。

## 5. 明确不做（M1 范围外，勿混入）

`deadline` 统计（M2）、字节预算与 `R(k)` 模型（M3）、KCP 行为改动（M4）、
滑动窗口 FEC、大小分桶、非对称 D:P。

---

## 6. 变更记录

| 日期 | 变更 |
|---|---|
| 2026-10-29 | 建立清单：4 阶段 12 任务（T0 + A1–A4 + B1–B7 + C1–C3），映射规格 T1–T22 |
| 2026-10-29 | 决策锁定：手写 CHECK 宏 / AES-GCM 内置独立实现 / line≥90 branch≥80；A3 拆为 A3a（AES+GHASH）+ A3b（GCM 封装+信封） |
| 2026-10-29 | T0 完成：CMakePresets + build.bat（vcvars64 + Ninja）、16 个模块占位 .cc、skeleton 测试通过。Windows 构建入口 `build.bat [Debug\|Release]`；覆盖率的 gcc/clang 分支留给 CI |
| 2026-10-29 | 澄清：FCP 是自有新协议，**不做任何 kcp-go/kcp-cpp 互验**；A1 golden 用自有参考值，A3a 验证只靠 FIPS/NIST 标准向量 + 双路径一致性 |
| 2026-10-30 | 网络专家审查 #26 落地（规格 8 处 + 代码 + 测试，20/20 绿）：① 终止线 2^48→2^32（GCM 块预算，envelope.h kNonceLimit）；② 方向密钥 M1 强制（SP 800-108 KDF，label fcp-c2/fcp-s2，derive_direction_keys；曾误走手写 SHA-256 已废弃）；③ 重放窗口 64→256 槽（kReplayWindow，adv_test R1.4 更新）；④ --fec-parity-max 允许 5..7（FcpConfig.parity_max）。测试 T24/T25（envelope_test TestDirectionKeyIsolation + TestRecvNonceLimit 改用派生密钥封包） |
| 2026-10-29 | 新约束：实现语言统一 **C++20**（T0 决策 4），CMake 标准由 17 升到 20 |
| 2026-10-29 | 阶段 A 完成（A1–A4，9 个测试全绿）：GF 表/柯西矩阵、RS 编解码、AES 双路径、GCM+信封、6B 头+FECSTAT 128B。设计勘误 #8（柯西 `y_c = k + c`）落码并回写设计文档 |
| 2026-10-29 | B1 完成：`binom_cdf` / `k_for`（目标 0.80），T20 golden 与 §8 表逐项一致（20% → 4） |
| 2026-10-29 | B2 完成：`FecStrategy` 状态机（含规格 §8 的 256 包样本门与 10% 不可信门），11 个场景测试全绿 |
| 2026-10-29 | B3 完成：`Handshake`（HELLO 16B / ACK 20B、u16 caps 校验、min/AND 协商、3×300ms 超时、幂等、64 段/64KB 协商前缓存），握手测试全绿 |
| 2026-10-29 | B4 完成：`FrameTx`（T_flush=clamp(SRTT,25,200)、满组/空闲闭合、`k_eff=min(k,max(1,ceil(k·n/D)))`、码长恒 n+k、control 前缀零拷贝旁路、MTU 断言），覆盖 T12/T14/T17/T2 |
| 2026-10-29 | B5 完成：`FrameRx`（orig/recov/parity 三张位图互斥、n 仅由 parity 给出、幽灵 parity 缺失行、sn 4096 窗口去重、集合容量淘汰、anchor 窗口），覆盖 T4/T9/T18/T22；`validate_hdr` 的 `s` 升为 u16（D+P 可为 256） |
| 2026-10-29 | B6 完成：`FcpSettle`（Active→Eligible→Accounted 相位机、late_guard=clamp(RTT,100,500)、墓碑 clamp(2×RTT,200,1s)、按位图结算、**整组全丢按 set_id 跳变占位只计 sets_k_unknown**、10% 不可信门、迟到事件分类 data_late_rx / late_dup / data_recovered_late 且不回填），覆盖 T5/T6/T13/T22（200 组 20% 丢包 fuzz 恒等式零违例） |
| 2026-10-29 | B7 完成：`FcpReporter`（2s 且 data_expected≥256、60s 强制门且 interval_ms 如实/封顶 60000、空闲不发、flg bit1/bit2、修复时延 nearest-rank p50/p95、上报后结算与自有计数整体清零），覆盖 T15 |
| 2026-10-29 | C1 完成：`Session`（envelope→handshake→FrameTx/FrameRx→FcpSettle→FcpReporter→FecStrategy 单线程接线；协商后按 D'/P' 懒建模块；协商前 data 缓存补发；FECSTAT 四类丢弃、样本门与 §11 日志；`SessionTable` salt 哈希查找；修复时延经 `FcpSettle` 观察者写入上报器）。内存回环双端全闭环：握手→k=0 数据→20% 丢包→结算→FECSTAT→策略 ON→k 生效后 40 组按 k 发 parity→恒等式与重建字节校验 |
| 2026-10-29 | C2 完成：`tests/e2e_test.cc` 以 127.0.0.1 真实 UDP 回环（Winsock2/POSIX 双实现、非阻塞收发、sendto 前应用层按符号类型丢包）驱动双 `Session`：① T3 k=0 无损 40 组 rx==expect==400、pre=0、尾组 tail_drop；② T7 重建 sn 与 KCP 重传撞车经 sn 窗口只交付一次（late_dup=1、恒等式成立）；③ T8 篡改 GCM tag 仅 `auth_fail+1`，集合/anchor/结算 14 项计数逐一不变；④ T10 P'=0 时 k≡0、零 parity、FECSTAT 仍正常；⑤ 1000 段 20% 丢包 + 12 轮 ARQ：`data_delivered==1000` 且每个 sn 恰好交付一次，逐 tick 恒等式零违例 |
| 2026-10-29 | C3 完成（覆盖率项留 CI）：① Debug/Release 均 19/19 ctest 通过，1103 条 CHECK；② golden 清单与附录 C 21 条逐条核验归档于 `docs/FCP_M1_ACCEPTANCE.md`；③ `soak_test` 三档丢包共享墙钟交错跑 10 分钟（`FCP_SOAK_MS=600000 FCP_SOAK_REALTIME=1`），零 crash、零恒等式违例、三通道双向 `delivered` 与 `tx` 完全相等（96000/96000），0% 通道 OFF/零 parity、5%/20% 通道 ON 且重建生效（结果原文见 `FCP_M1_ACCEPTANCE.md` §6）；④ 覆盖率门禁由 CI 的 `scripts/coverage.sh` 执行（本机无 gcov/llvm-cov，不伪造本地数字） |
| 2026-10-29 | 对抗分析 10 轮（实现自查）：修复 9 处代码问题并补 8 个回归用例 —— ① 接收侧拒绝 nonce_ctr ≥ 2^48；② 认证通过但超出 MTU 预算的报文按 struct_fail 丢弃，同时封住集合 `symbol_max`/解码缓冲的放大面；③ 畸形远未来 set_id 不再推进窗口锚点且不创建空集合（先校验后提交）；④ oob 头固定 `set_id=0`（§4.7）；⑤ 接通 FECSTAT `data_bytes_rx`/`parity_bytes_rx`（按 wire 长度、按认证类型）；⑥ `p_max`/pinned k 夹到协商 P'（否则高丢包下 k＞P' 会让 parity `index≥S` 被对端判 malformed）；⑦ 本地 caps 非法（如 D=0）时 `start` 拒绝并禁止建编解码器，FrameTx 闭合加除零护栏；⑧ KCP 输出中的 HELLO/ACK 前缀走 control 旁路，不再进协商前 data 缓存（否则自锁）；⑨ 第 9 轮确认"尾丢集合已收 data 计入 wire 字节但不计入 `data_rx_orig`"属规格行为，修正测试假设而非实现；⑩ 新增/扩展 8 个回归用例覆盖上述路径。详见 `FCP_M1_ACCEPTANCE.md` §9 |
| 2026-10-30 | 文档审查勘误（规格附录 C #22、设计附录 A #9–#11）：control 判定收紧为"在途消息整段字节相等"（新增 T23/D1）；`lost` 口径统一为 `expect − rx − rec − late`；§12.1 RS 接口改为计划值 k；慢链路 FEC 下限 ~4.3 包/s 澄清并列入 §14.8（D3）；B1 参考值 RS(12,8)→RS(10,8) 更正；新增阶段 D（D1/D2/D3），测试矩阵增至 T1–T23。另：D2 跟踪的 `SnFn` 编译中断已随同日第二轮对抗审查修复（Debug/Release 20/20，见验收文档 §10/§11） |
| 2026-10-30 | 对抗分析（文档层，规格附录 C #23、设计附录 A #12）：HELLO/ACK 注销规则统一为"KCP 确认或 `max(3×srtt,2s)` 兜底"（D1 口径更新）；§7.1 校验项补尾丢豁免 `tail_delivered`；§4.1 新增 64 槽重放窗口；§4.5 补 k 冲突、认证后超 MTU 拒收、容量兜底；§7.1 单调键半窗注明；§6.2 caps 清单补 ver/保留位；§5.2 慢集合边界入档；规格 §12.1/设计 §4.1 清理 OpenSSL 残留。除 D1 外均为规格与现有实现对齐，无新增代码工作 |
| 2026-10-30 | 设计合理性复查 + 分叉裁定（规格附录 C #24/#25、设计附录 A #12 补注/#13）：#24 salt 职责更正、方向密钥列入 §14.9；**#25 control 通道由 KCP（type=3+内容分类）改为 oob（type=2）**——内容分类是历次 control 缺陷的根源且其收益与握手定时器冗余；D1 重定义为握手通道 oob 化（HELLO 16→20B、golden 重录）；#22①/#23① 机制部分作废（记录保留） |
| 2026-10-30 | **D1 完成**：HELLO/ACK 以 type=2 oob、`set_id=index=0` 发送（HELLO magic 补齐 16B，线上 20B，golden 重录为 20/20）；删除 KCP 输出内容分类与在途登记，`FCP_HELLO_V3` 开头的用户段按普通 data 进集合；收到 type=3 计 struct_fail（type=3 已取消、未定义）；握手层自管 3×300ms、Established 即停；协商前超 MTU 报文在进缓存前拒收。测试适配 5 参 `FrameRx` 并补齐 T23 双侧覆盖。另按规格 §8 补"连续 3 个报告周期无 FECSTAT → 保持 k、WARNING 一次"看门狗，并按 §10 暴露 `fecstat_rx`/`last_pre_ppm`/`last_usable_ppm` 供 stats 行使用；新增 `TestMissingFecstatWarning`。Debug/Release 均 20/20 |
| 2026-10-30 | 网络协议评审 #27（规格 #27、设计附录 A #14）：**E1 新增**——握手重传指数退避 300/600/1200ms（固定 3×300ms 总预算 900ms 在 RTT > 450ms 链路是"ACK 未到先判死"的假失败；上一条 D1 记录中的"握手层自管 3×300ms"口径随本条更新，待 E1 落码，T26 ☐）；**E2 新增**——突发丢包 burst 注入实测，量化 `k_for` i.i.d. 假设偏差（M1 验收项）；i.i.d. 假设、拥塞冗余正反馈、无 PMTU 发现三项边界入档规格 §14.10–14.12（不改机制）；验收线 T1–T23 → T1–T26（T24/T25 已随 #26 绿，T26 随 E1） |
| 2026-10-30 | **E1/E2 完成**：① `handshake.cc` 重传间隔改为 `300 << (retries−1)`（300/600/1200ms，总等待 2.1s），`handshake.h` 注释同步；T26 落地为 `TestRetryBackoff`（退避序列/任意阶段 ACK 即停/RTT=500ms 仿真成功/重复 HELLO 仍重发 ACK），`TestTimeout`、`TestCacheLimits`、session `TestHandshakeTimeout`、adv R9.4 时序同步到退避口径；② `e2e_link.h` 新增确定性 burst 注入器（每 25 个 data 丢 5 连片，仅 data），`e2e_test` 新增 `TestBurstLossRepairRate`：k=4 下实测单组修复率 **60.0% vs 二项模型 87.0%**（-27pp，命中组 5 连丢 > k 全部不可修、ARQ 兜底 1000/1000 恰好一次、恒等式零违例）。Debug/Release 均 20/20 |
| 2026-10-30 | 第二轮对抗复查 #28（规格 #28、设计附录 A #15）：**P0 发现——规格"salt 是 KDF 熵源"与实现不符**（`derive_direction_keys` 只用配置 PSK，salt 未参与任何派生），同一 PSK 的任意两会话方向密钥相同、IV 每会话从 0 起 → GCM (key, IV) 跨会话重用，多客户端共用 PSK 部署下可互相解密/伪造；**F1 新增（P0，M1 收尾前必做）**——`session_key = AES128(PSK, salt‖0×8)` 按会话派生 + T27；**F2/F3 新增（M2）**——协商前缓存溢出反压评估（#28③：退避把最坏握手期拉长 2.3 倍，8 Mbit/s 下 ~80ms 填满 64 段/64KB）、FECSTAT 连发两份（#28⑤）；重放窗口 256 槽覆盖数字勘误（13–19 Mbps，非 25 Mbps，#26④ 算错）；late_guard/墓碑上限口径、短连接自适应盲区入档规格 §14.13–14.16；验收线 T1–T26 → T1–T27；**F1 已落地**（`derive_session_key` + `TestSessionKeyDerivation`，Debug/Release 20/20） |
| 2026-10-30 | **F2/F3 完成**：F2 采用"按 BDP 放大缓存"路径——协商前缓存默认 64 段/64KB → 512 段/512KB、`SessionConfig.handshake_cache_*` 可配置（超限保持响亮失败；泵级反压需宿主配合，M2 宿主侧跟进）；F3 FECSTAT 每报告连发两份 + 校验器 `kDuplicate`（键等于最近接受值单独计 `fecstat_dup`，stale/dropped 口径不变）；测试同步（TestCacheLimits 重写、R9.6 显式上限、validator equal→kDuplicate、reporter/session/e2e 发送计数），Debug/Release 20/20 |
| 2026-10-30 | 第三轮实现审查（规格 §6.2/§8）：① **修复协商前入站 data 反射**——`Session::on_wire` 曾把对端 data 段写入握手缓存，而该缓存只服务本端 KCP 输出的补发，`configure()` 时被 `take_cached_data()` 回灌 `FrameTx`，把对端业务段当成自己的数据再发一遍（parity 则静默丢弃）；现按 §6.2"协商完成前只允许 oob 上线"直接丢弃入站 data/parity，出站缓存语义不变；② **修复排队护栏 min_rtt 基线**——`min_srtt_ms_` 曾固定初值 200ms，RTT > 240ms 的链路（卫星/跨洲）`srtt − min_rtt ≥ 40ms` 恒真，k 被永久压到 1；改为首个 `on_rtt_sample` 样本作基线、无样本时护栏不生效。新增 `TestPreNegotiationInboundDropped`、`TestQueuedGuardrailUsesObservedMinRtt`，`TestPreNegotiationMtuReject` 同步（边界帧不再进缓存）；Debug/Release 20/20 |
| 2026-10-30 | 第四轮对抗分析 10 轮（按模块定向攻击；第 1/3/4/5/7/8/10 轮无缺陷）：修复 3 处并补 3 个回归用例 —— ① **C2 墓碑释放后迟到分片重算**：`release_set` 后槽位可被迟到 data/parity 重建，且因 anchor 已在前方立即满足 Eligible，late_guard 后二次结算、重复计入 expected/rx/parity 并污染对端丢包率与策略；`FrameRx` 新增有界 `retired_` id 集（半窗 256，随 anchor 回收），入口在锚点更新前丢弃并计 `retired_dropped()`，容量淘汰已结算组同样登记；② **C4 容量淘汰未告知结算**：`get_or_create` 淘汰未结算组只 erase，`sets_tail_dropped`/`tail_delivered` 漏计且可破坏 `delivered_le_sum()`；新增 `RxEvent::kSetTailDropped`（value=已交付符号数）由 settle 记账；③ **C3 MTU 下界未覆盖 FECSTAT oob**：128B 报告以 oob 上线，IPv4 需 ≥190、IPv6 ≥210，低于此值时报告恒不可达（出站越界/对端认证后按超 MTU 拒收，违反 T2）；`Session::start`/`ensure_configured` 增加"MTU 须容纳最大 oob"校验并保持 Idle。回归：`settle_test TestNoReaccountAfterRelease`/`TestCapacityEvictionAccounting`、`session_test TestMtuMustCarryOob`；Debug/Release 均 20/20。详见 `FCP_M1_ACCEPTANCE.md` §14 |
| 2026-10-30 | **Linux 编译验证**（Ubuntu 24.04.5 / GCC 13.3 / CMake 3.28 / Ninja 1.11，2 核 1GB 远程机）：`linux-x64` preset（Debug）与 `build/linux-x64-release`（Release）均一次配置成功，ctest 各 20/20，`-Wall -Wextra -Wpedantic` 零告警。GCC 额外暴露并修复 2 个仅 Linux 可见的测试问题：① `envelope_test::TestRecvNonceLimit` 从未注册进 `main()`（接收侧 nonce 上限回归此前在 Windows 上也未执行，只是 MSVC 不报未使用函数），注册后通过；② `fecstat_test` golden 从 15 字节字符串字面量 `memcpy` 16 字节（越界读，第 16 字节实际依赖零初始化），改为 15。Windows Debug/Release 复跑仍 20/20。详见 `FCP_M1_ACCEPTANCE.md` §15 |
| 2026-10-30 | **真实网络基准**：新增 `tools/fcp_bench.cc`（server/client、令牌桶 `--mbps`、`--pinned-k`、`--progress`；`FCPBENCH` 会合规避 2.1s 握手预算；服务端按线上到达的 data 报文建立相位时钟）。VPS（测试机，地址不入库）↔本机(电信) 实测：上行 10/20/30 Mbps 档 9.68/19.37/29.00（链路干净）；下行路径固有丢包 ≈15%（原始 UDP 84.6% 交叉验证），自适应 k=2–3 把交付率从 84% 提到 94–96%，20 Mbps 档有效吞吐 +12%；>30 Mbps 受 VPS 单线程会话限制。另确认该云商入方向拦截 UDP/53、443，基准使用 40000。仅改基准工具，`src/fcp/` 未动；四套构建 ctest 均 20/20。详见 `FCP_M1_ACCEPTANCE.md` §16 |
| 2026-10-30 | **Qt 桌面客户端落地**（`apps/fcp-client`，连接与测速控制台，UI 参照 `kcp-proxy-cpp/gui/electron` 的纸感墨白三视图）：`BenchEngine` 复刻 `fcp_bench` 客户端时序（`FCPBENCH` 会合 → 握手 → 1–8s 上行令牌桶 → 下行检测 → 18s 收尾），GUI 线程 5ms 定时器驱动 `QUdpSocket`+`Session`、Stats 10Hz；无边框主窗 + 概览/连接设置/运行日志、速率 sparkline、`QSettings` 持久化、`--host/--port/--mbps/--autostart` 覆盖。构建：`build_app.bat`（preset `windows-x64-app`，vcpkg Qt 6.11.2，`FCP_BUILD_APP` 默认 OFF 故库构建不受影响），Release/Debug 均通过并 `windeployqt` 部署。两处口径修正：target 编译期 `QT_NO_KEYWORDS`（`FrameTx::emit()` 与 Qt `emit` 宏冲突）；交付率改按下行测速流 `sn` 计算（`FcpSettle` 区间计数器跨区间累加会把收尾比值顶到 101.2%），并滤掉在路的会合魔法包避免虚报 `auth_fail`。本机回环联调：上行/下行 19.39 Mbps、交付率 100.0%、授权/结构失败 0、结算一致 ✓，与服务端 RESULT 逐项吻合；`src/fcp/` 未改，Windows Debug/Release ctest 仍 20/20。详见 `FCP_M1_ACCEPTANCE.md` §17 |
| 2026-10-30 | **M2 设计定稿 + FCP-STREAM 落地（T28/T29）**：`docs/FCP_M2_PROXY.md` 锁定分层（可靠字节流用**新增的 `src/fcp/stream.*`**，不引入 KCP/ikcp；入口 SOCKS5 TCP CONNECT + HTTP CONNECT；每连接一条会话；远端解析；CLI 双端 + GUI 内嵌引擎）。流层为最小可靠有序流：字节序号、单块 SACK、per-DATA ACK、`in_flight ≤ min(W, rwnd)`、`RTO = clamp(2×srtt,100ms,5s)` + Karn、零窗探测放行**一个整段**、`fin` 用独立零长段占 1 个伪序号、`EofFn`/`ClosedFn` 两段关闭回调。三处由测试抓出的设计/实现错误：① `initial_seq` 双编号空间（`rcv_nxt` 误用本端 `iss` 起算，两个方向串到同一空间）→ 取消 `iss`，各方向从 0 起；② 重复 ACK 里的 SACK 被 `cum` 未推进的早退吞掉（等于没有快速重传，洞只能等 RTO）→ SACK 判定前置于 `prior_una` 短路；③ `close()` 在"对端已 EOF 且本端无待发"时短路不发 fin，对端永远等不到关闭信号 → `close()` 一律排入 fin。`tests/stream_test.cc` 15 场景，Windows Debug/Release ctest 21/21 |
| 2026-10-30 | **T30 完成（Stream × Session 集成与丢包回归）**：新增 `tests/stream_e2e_test.cc`，在 `e2e_link.h` 的 UDP 回环载体上把两个 `Stream` 挂到两个真 `Session` 上（信封/FEC/结算/FECSTAT 全在线），6 场景：无损双向、纯 ARQ 随机丢包（一个报告周期内完成，FEC 未参与）、pinned k=3 修复、burst 超出 RS 预算、半关闭、200KB 持续流 12% 双向丢包；断言交付字节与源完全相等、`on_rtt_sample` 把会话从 200ms 冷默认拉下、`identity_ok`/`delivered_le_sum` 零违例、`auth_fail`/`struct_fail`/`send_fail` 全零。**P1 修复：帧层跨集合去重与 stream 载荷冲突**——`FrameRx` 默认按 payload 偏移 12 的"KCP sn"去重，FCP-STREAM 段在该偏移是数据/SACK 字段，且重传**故意**重复同一 `seq`（对端要再收一次才会重发 ACK）；表现是接收端把合法重传当重复吞掉、不再回 ACK，发送端窗口停在 199866/204800 无限重传 30s（`late_dup=83 / delivered=50`）。修法：`SessionConfig::sn_of`（默认 `&kcp_sn_of`，**M1 KCP 路径行为不变**、§4 线上字节未动），stream 宿主置空并把去重留在字节层。测试基建两处：`UdpSocket` 的 `SO_RCVBUF` 提到 1MiB（默认 8KiB 在窗口级突发下溢出，那部分丢失不进注入器计数，注入模型不再"已知"）；burst 图形从 5/25 改 4/17，避免与 D=10 对齐——对齐时每个受损集合恰好丢 5 个，"可修/不可修"退化为一边倒，RS 路径根本不出现。Windows Debug/Release ctest 22/22 |
| 2026-10-30 | **#19 链路参数预热完成（M2 §5）**：库侧加三个默认保持 M1 行为的可选字段——`SessionConfig::initial_srtt_ms`（0 = 沿用 `kDefaultSrttMs` 200ms）、`SessionConfig::initial_k`（透传给新增的 `FecStrategyConfig::initial_k`，−1 = 从 OFF 冷启动、≥1 = 直接以该 k 进入 ON）。语义上是**起点不是设置**：上报照常驱动状态机，暖过头一路降、clean streak 照常 retire 回 OFF；`pinned_k` 存在时（含"钉在 0"）seed 一律作废，避免出现"钉 OFF 却被预热打开 parity"。钳位在 `FecStrategy` 构造里做（`p_max_` 已是 `min(p_max, P')`，stats 模式为 0 → 不预热），会话日志新增 `FEC warmed: k=N (prewarm)` 与 `FEC pinned: k=N (operator)` 分列。**只暖 `srtt_ms_`，不暖 `min_srtt_ms_`**——排队护栏的基线必须是真实观测，否则缓存基线会让 `srtt − min_rtt ≥ 40ms` 在链路变堵后恒真、k 被永久压到 1（与 #28 那次修复同一类错误）。新增宿主侧 `src/fcp/prewarm.h/.cc`：`PeerProfile{srtt_ms, initial_k}` + `PrewarmCache`（`peer_key(host,port)` 裸 IPv6 自动加括号、TTL 10min、写者覆盖、`get()` 把过期读成缺失而 `prune()` 才回收、条目上限 4096：服务端那侧的键是客户端自选的地址，不收口等于让对端决定本进程内存；写满先清过期项、仍满则拒写，代价只是那条会话冷启动）+ `apply_prewarm()`（RTT 与 k 两个先验各自独立）。记的是**本端发送侧** `Session::k()`/`Stream::srtt_ms()`。副作用入档：暖过的 RTT 让结算更紧（`late_guard`/墓碑按 clamp 收窄），首两个报告的迟到容忍度下降，个别符号从"迟到可收"变"迟到丢弃"，由本层 ARQ 重传兜住，不影响正确性。`tests/prewarm_test.cc` 13 场景（含会话侧正面证据：`k=3` 预热下**没有任何 FECSTAT 上报**的第一个集合即带 parity，单符号集合按 `k_eff=ceil(k·n/D)` 缩到 1 个 parity 仍完成重建，`T_flush` 从 200ms 变 45ms）。Windows Debug/Release ctest 23/23 |
| 2026-10-30 | **#20 代理入口编解码完成（M2 §4 / T31）**：新增 `src/fcp/proxy_proto.h/.cc`（纯函数、无 socket、无时钟，宿主自己累积缓冲）与 `tests/proxy_proto_test.cc`。三段：① **SOCKS5**（RFC 1928 的 NO AUTH + CONNECT 子集）问候/请求/应答，其余 CMD 解成 `kCommandNotSupported`→回 `0x07`、未知 ATYP→`0x08`，绑定地址固定 `ATYP=0x01,0.0.0.0:0`；② **HTTP CONNECT** 解析请求行 + 头部到 `\r\n\r\n`，四个常量响应体 200/400/405/431（错误响应带 `Connection: close`，响应体不含对端输入 → 无头注入面）；③ **隧道 OPEN/OPEN_OK/OPEN_ERR**（`FCPO|ver|…`，域名 ≤255B、IPv4/IPv6 的 len 必须 4/16）与 `OpenError → Socks5Rep` 映射。三条贯穿的口径：**字节序**——代理侧端口大端（与 RFC 1928 一致），FCP-STREAM 段头小端，两套互不解析；**消费长度**——成功时精确给出报文长度，其后的字节原样属于隧道（客户端可把问候+请求+首批数据挤一次 `send()`），`kNeedMore` 一律 0 消费；**短读与坏形分开**——`RSV≠0`/`NMETHODS=0`/DOMAIN 长度 0/端口 0/域名非法字符/版本非 5 判畸形，首字节非 `0x05` 立即判"不是 SOCKS5"，OPEN 首字节非 `F` 立即判 `kBadMagic`。窗口收口：SOCKS5 只看 `kSocks5MaxRequestBytes=262`、OPEN 只看 `kOpenMaxBytes=264`、HTTP 只看 8 KiB 预算（空行只会在预算内被承认 → 超预算恒 431，与宿主读多少无关）。写的时候自查出并修掉四处：`OPEN_OK`/`OPEN_ERR` 长度按字段重算成 **8/7**（原先按 9/8 会把 reserved/code 读到偏移 7/8，正好读进隧道字节）、`HTTP/1.1` 被版本检查拒掉、方括号 IPv6 分支写死成 400（`[::1]:8443` 解不出）、`socks5_parse_request` 漏了它自己注释承诺的 RSV 校验；另加端口 0 双侧拒（HTTP 与 SOCKS5/OPEN 口径一致）。测试 18 场景，**每条报文都再按逐字节截断重解一遍**（断言非 `kOk` 且消费 0），越界输入的分支覆盖即由此钉住。`proxy_proto.cc` 进 `fcp` 库、`proxy_proto_test` 进 ctest 门（无 socket，不需 `ws2_32`）。Windows Debug/Release ctest **24/24**，Qt 应用 `build_app.bat Release` 仍通过。M2 §4 已按此定稿（含字节序与长度表） |
| 2026-10-30 | **#21 ProxyEngine + select 反应堆 + CLI 双端（M2 §6）**：新增 `apps/fcp-proxy/`。① `engine.h/.cc` → 独立静态库 `fcp_proxy_core`，**无 socket、无真实时钟**（`Host` 回调注入收发/拨号/DNS，`now_ms` 全由参数传入），内含连接表（`by_conn_` + `by_salt_` 双索引）、salt 路由与重放绑定、`Phase` 状态机（客户端 `kEntry→kAwaitReply→kTunnel`，服务端 `kNegotiating→kAwaitOpen→kDialing→kTunnel`，两端共用 `kDone`）、rwnd 反压、预热缓存读写、`on_tick` 的拨号截止与 grace 钟；② `reactor.h/.cc` 跨平台 select（Windows 非阻塞 connect 失败只进 `exceptfds`）；③ `cli.h/.cc` + `main_client.cc` / `main_server.cc`（`--key/--host/--port/--listen/--local-port/--bind/--mtu/--d/--p/--k/--window/--rcv-buf/--idle/--dial-timeout/--max-sessions/--no-prewarm/--stats/-v`）。`FCP_BUILD_PROXY` 仍默认 OFF，但门禁改为 `FCP_BUILD_PROXY OR FCP_BUILD_APP OR FCP_BUILD_TESTS` 即进入 `apps/fcp-proxy`——引擎是 Qt 客户端要链接的那一半，不能因为不开 CLI 就编不出来。**修掉两个真实缺陷**：(a) `Stream::send_space()` 用 `in_flight_ + tx_pending_` 计量，而 `pump()` 无条件把 pending 切成段、被窗口挡住的段两边都不算，慢读者能把发送队列撑到无上限（`pushed=409600 refused=0`）；改为 `bytes_queued_ - bytes_acked_`，每连接每侧内存上界回到 `send_window + rcv_buf`。(b) `ProxyEngine::on_tick` 的 `kDialing && 过拨号截止` 分支在会话已判死时仍每 tick 赢下 `else if`，grace 截止永远读不到，服务端 `live` 卡 1 直到 idle 超时；加 `!closing` 守卫。两者都过了 CLI 回环联调、由 socket-free 驱动逼出。新增 `tests/proxy_engine_test.cc`（9 场景：SOCKS5/HTTP 往返、5 组 `OPEN_ERR→本地应答`映射 + "一条隧道只拒一次"、畸形入口 5 例、背压、salt 路由与跨地址重放 + 短 stub、20 条短连接零残留、拨号超时与两种 grace 钟理由、双端会话上限）与 `stream_test` 的 `TestStalledReaderBoundsTheSendQueue`。回环七项联调全绿（含 2MiB 逐字节一致 0.366s、HTTP CONNECT + TLS、20 串行 + 10 并发、拒绝目标 2.087s）；拒绝目标的 2.1s 用三条路径实测（`select` 异常集 / `WSAEventSelect(FD_CONNECT)` / 阻塞 `connect`）确认是 Windows TCP 栈自身的 ~2047ms（Linux 立即 `ECONNREFUSED`），不是代理开销。Windows Debug/Release ctest **25/25**（2.33s / 0.57s）。M2 文档按此更新：§3 落地口径、§6 模块表拆分、§7 新增第 8–11 条边界、§8 新增 T31b 与回环进度 |
| 2026-10-31 | **#22 WAN 联调收口（T32 WAN 半边 + T33 预热 A/B + Linux 回归，M2 §8.1）**：对测试 VPS（Ubuntu 24.04/g++ 13.3，RTT 180ms，下行丢包 10–17% FECSTAT pre 口径）部署双端跑通。① **T32 WAN 七项全绿**：GET / CONNECT+TLS / 5400B 与 8MiB 逐字节一致 / 拒绝目标 0.43s（Linux 立即 `OPEN_ERR 1`，反向印证 §7 第 9 条）/ 20 串行 + 10 并发；收尾 `refused=1 bad_entry=0 clash=0 over=0 unknown=0` 双端 `live=0`，两端字节自洽（wire tx 17.13MB ↔ 客户端收 14.39MB，1.19× = parity + 重传）。② **尾段竞态入档（良性）**：客户端先亡时服务端迟到重传计客户端 `unknown_salt`（42，封顶）、grace 钟 close 与服务端尾段 FIN 迟到对应，收尾前双端全归零。③ **吞吐 = §7 第 2 条 WAN 定价实测**：8MiB 自适应 k 1.29 Mbps / 钉 k=3 32.2s，速率曲线 ~1MB 突发 + ~2s 停顿（单块 SACK 外等 RTO）；窗口 ×8 仅 +12% 排除窗口瓶颈；fcp_bench 同日标定 25.8 Mbps（无交付义务）——差值即"非完整快速重传"价格，快速重传留 M3。**部署事实：该云商只放行 UDP/40000（40001 到网卡不进 socket）**。④ **T33 预热 A/B**：每臂 1MiB 预热传输学出 k 后 40 条 64KB 短连接、双端全新进程、开/关各两轮——**开 1.269/1.365s vs 关 1.727/1.777s（省 ~0.43s/条 ≈ 25%）**，服务端 40/40 `FEC warmed: k=2`；5.4KB 响应无显著差异（0.79 vs 0.79s，固定成本 ~4×RTT 主导，预期）。⑤ **修掉一个真实缺陷**：CLI 解析要求选项必带 `=`，文档承诺的裸布尔旗标 `--no-prewarm` 传不进去（"unknown argument"）；`CollectArgs` 接受裸 `--flag`（存空串）。⑥ Linux × Debug/Release ctest **25/25**（顺带删掉 `proxy_engine_test.cc` 里 g++ 报未用的 `domain_addr`）；Windows Debug/Release ctest **25/25**（2.33s / 0.57s，四套同日全绿） |
