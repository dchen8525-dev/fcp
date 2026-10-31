# FCP M3 控制：R(k) 模型、字节预算与突发检测

> 依据：`FCP_PROTOCOL_V6.md` §8（策略）、§9（护栏耦合）、§12.2（阶段表 M3 行）、§14.8/§14.10/
> §14.11/§14.14/§14.16（待标定）、`FCP_V6_DETAILED_DESIGN.md`、`FCP_M2_PROXY.md` §7（已知边界）
> 与 §8（验收线）。M2 已收口（T28–T33 全绿，见 M2 文档 §8.2），本里程碑从 #24 起编号。

## 0. 范围盘点（2026-10-31，M3 开工时）

路线图 §12.2 的 M3 行：**完整控制器：`R(k)` 模型、字节预算、三态、突发检测**，验收为
"5%/10%/20% 与 Gilbert–Elliott 下 k 稳定、预算不超"。逐项核对后的真实范围：

- **已就位（不再做）**：原路线图"M2 观测增强"的四项里有三项已随 M1/M2 落地——修复时延
  分位数（`repair_lat_p50/p95_ms`）、data/parity 字节计数（`data_bytes_rx/parity_bytes_rx`）、
  deadline 统计口径（`data_recovered_dl` vs 结算时未恢复，§5.2"accounted 时刻即期限内判据"）。
  FECSTAT 双发（#28⑤/F3）、`usable_loss` 接入 RTO（M2）也已落地。
- **本里程碑新增**：R(k) 经验修正、三态控制器、字节预算（`--fec-budget`）、突发检测
  （KL/经验分布）、Gilbert–Elliott 注入验收。
- **承接项**：快速重传/多洞 SACK（M2 §7 第 2 条，WAN 实测"等 RTO"是剩余吞吐差的主项）、
  离线重放工具（观测项中唯一缺席者）、优雅关闭 tombstone 路由（M2 §8.1）、D3 慢链路样本门
  （§14.8）、`late_guard`/墓碑上限标定（§14.14）、跨连接继承评估（§14.16）。

## 1. R(k) 模型：经验修正的二项反解

### 1.1 问题

`k_for` 按二项分布反解，隐含组内丢包 i.i.d.（§14.10/#27②）。突发丢包下一次长度 > k 的
游程即可击穿单组，实测单组修复率低于二项预测——`k_for` 系统性欠保护。M1 验收的 burst
注入已实测确认该偏差。

### 1.2 设计：接收端账本 + 有效丢包率单侧校正

**账本（接收端，`FcpSettle`）**：每个按期结算的集合若满足 `n_used == D && k 已知 && k ≥ 1`
（满编、真跑过 parity 的组），记三笔账：

- `ledger_groups`：入账集合数；
- `ledger_groups_failed`：结算时仍有 ≥1 个 data 未恢复（`orig + recov < n_used`）的集合数
  ——即"期限内修复失败"的定义（§5.2：`accounted` 时刻就是期限）；
- `k_hist[1..7]`：k 直方图，众数为**主导 k**（`ledger_k`）。稳态限速 ±1 保证区间内 k 近似
  恒定，众数足以代表；
- `run_hist`：组内最大连续丢失游程直方图（§3 突发检测的输入，#26 起上线）。

**线上扩展（FECSTAT `reserved[5]` 复用，128B 不变）**：

```text
offset 108  ledger_groups   u32   账本入账集合数
offset 112  ledger_fail_ppm u32   其中修复失败集合的占比（ppm）
offset 116  ledger_meta     u32   byte0 = 主导 k(1..7)；byte1 = 0；
                                  bytes2-3 = burst_kl（0.01 nat，u16，#26 填充）
offset 120  reserved[2]           继续预留
flg bit3 = 账本有效（0x08）
```

兼容性：旧端 reserved 全零 ⇒ `ledger_groups == 0`，新端忽略，**无需协商**；新端 → 旧端
方向（旧端收报告、新端发）同样安全（旧解码器本来就只认自己的字段集）。字段语义进协议
文档 §7.1 与决策 #29。

**校正（发送端，`FecStrategy`）**：报告满足门（`flg bit3` 且 `ledger_groups ≥ 64` 且
`ledger_k == 当前 k_`）时：

```text
fail_rate = ledger_fail_ppm / 1e6
p_eff     = binom 反解：binom_cdf(ledger_k, D + ledger_k, p_eff) = 1 − fail_rate
p_use     = max(p_observed, p_eff)          # 单侧：只上调、不下调
k_target  = k_for(p_use, ...)               # 其余状态机逻辑不变
```

- 反解即 `binom_cdf` 对 p 的单调反函数（bisection，k ≤ 7 开销可忽略）；新纯函数
  `binom_p_for_cdf(max_losses, trials, q)` 进 `strategy.h` 与 `kfor_test`。
- **单侧的理由**：§14.10 已证失效模式是"欠保护"（突发）；"好于 i.i.d."没有对应的已证
  机制，按运气处理——若允许下调，64 组的小样本运气会让 k 抖动。上调方向受 ±1 限速与
  `p_max` 封顶，风险有界。
- 门全部不满足（旧端、样本不足、k 错位）⇒ 行为与 M1 完全一致（`p_use = p_observed`）。

### 1.3 账本的已知偏差

整组全丢的集合 `k` 不可知、被账本排除（§5.2）——极端突发时账本系统性偏乐观，偏差方向
与校正方向相反。残余风险由 RTO 兜底与 `p_max` 余量覆盖（§14.10 建议 `pmax=5`），不入账
即不污染，不试图修。

## 2. 三态控制器与字节预算（#25）

状态机从 OFF/ON 扩为 **OFF / ON / CAPPED**：

- **进入 CAPPED**：本报告区间冗余比 `parity_bytes_rx / data_bytes_rx > R`
  （`--fec-budget R`，R ∈ (0,1]，默认 **0.50**；`R = 0` 表示不限）。**线上 ratio = k/D**
  （parity 与 data 每包字节数相同，实测 golden 轨迹 0.29@k=3、0.40@k=4）——#28 的重放
  测试逮住原默认 0.40 恰好绑在 k=4（20% 丢包的常用工作点）后改为 0.50：D=10 下 k ≤ 5
  完全自由、k = 6..7 极端档才受限。
- **CAPPED 行为**：k 只降不升（对齐 §8 排队护栏语义）；冗余比回落且连续 1 个报告不超 ⇒
  回 ON。预算比较在每报告时做。
- **定位**（§14.11）：预算是"深队列 + 高丢包"下冗余字节的**天花板**，防正反馈靠它兜底，
  不是拥塞控制器；排队护栏（srtt − min_rtt ≥ 40ms 不升 k）语义不变。

## 3. 突发检测：经验分布 + KL（#26，已落地）

v5 遗产的结构化版本，实现与原案有三处刻意偏差：

- 输入：账本的 `run_hist`——组内最大**原始丢失**游程（`orig_mask` 上的连续缺位，l = 0..8+，
  桶 8 吸收 "≥8"）。**不含恢复位图**：RS 是全有全无修复，洞数 > k 的组所有洞都算未恢复，
  混入会把完美 i.i.d. 链路伪装成突发。原始口径在 #24 的"结算时未恢复"基础上改定。
- 参照：**精确 DP**（游程长度的马尔可夫递推）给出满编组在 i.i.d. 丢包率 p 下的
  P(M = l) 全分布——不是几何近似（几何会错掉有界组长的边界质量，实测对 2^10 掩码穷举
  误差 1e-12）。p 取账本自身总体的原始丢失率（`ledger_data_lost / ledger_data`）。
- 距离：KL(P_emp ‖ Q_iid)，Q 钳 1e-12 防 inf，量化 0.01 nat（饱和 65535）填进
  `ledger_meta` 高 16 位；P_emp 无质量的桶贡献 0。
- 用途（本里程碑内是诊断 + 可信度信号，不改 #24 的校正门）：`burst_kl` 高 ⇒ 突发是
  p_eff 偏差的来源；`burst_kl ≈ 0` ⇒ i.i.d. 成立。用 KL 加权校正留给有真实轨迹标定后
  （离线重放工具）。**检测器不是模型**：只输出偏离度，不估计 Gilbert–Elliott 参数。
- 验收载体（落地时改定）：GE 两态马尔可夫进 `session_test` 的 `Link`（虚拟时钟、固定
  LCG、data-only 丢弃）而非 `e2e_link.h`——后者是真 UDP socket 载体，突发/吞吐测试继续
  用它的周期注入器。**data-only 是关键约定**：GE 若连 parity 一起丢，`sets_k_unknown`
  超 10% 信任门，报告整体不可信，R(k) 反馈路径根本没被行使（实现期实测踩中）。
  T35 注入级验证（`TestLedgerLiftsKUnderBursts`）：双臂同为 ~10% 均值、initial_k=2 起步，
  i.i.d. 臂全程 k=2；GE 臂 fail 17.5%→22% → peff 0.123→0.137→0.169，k=3 且在均值回落到
  9% 的报告上仍被账本顶住（二项答案 k=2）——账本而非均值在支撑 k。

## 4. 快速重传与多洞 SACK（#27，承接 M2 §7 第 2 条）

M2 的定价（单洞 SACK 立补、其余等 RTO）在 WAN 上的实测签名是 "~1MB 突发 + ~2s 停顿"
（#23 探针修复后仍有残留，8.56 Mbps vs fcp_bench 同链路 25.8 Mbps）。M3 补齐：

- **快重**：同一 sn 的重复 ACK 计数 ≥ 3 ⇒ 立即重传第一个未确认洞，不等 RTO；
- **多洞**：SACK 记分板扩展到多洞，每个 dup-ACK 批推进一个洞的快重；
- **不做**：拥塞窗口减半与完整的 NewReno 状态机——§7 第 1 条（无拥塞控制）不变，引擎
  仍只有固定发送窗口 + rwnd 流控；快重放大出的流量受窗口与 rwnd 约束。
- 验收：burst 注入下交付时延从"RTO 尺度"降到"RTT 尺度"；有序/恒等式/无重复不变式全部
  保留（T29/T30 既有断言不许回退）。

### 4.1 落地时的再定案（#27，相对原案的两处修正）

实现前通读 `stream.cc` 发现：M2 的 `fill_holes` 对**第一个**洞已经是" sightings 即补"，
原案快重对其无增益。真正的缺口有两个，落地对应两条机制（17B ACK 线格式不变）：

1. **多洞盲区 → 接收端 SACK 块轮转**：ACK 只携带一个 SACK 块且恒为 `oob_.front()`，
   非相邻多洞时发送端每洞多付一个 RTT（cum 推进后才看得到下一个块）。#27 让接收端在
   **重复 ACK**（同 cum，即对端正被洞挡住）上轮转上报的块——`oob_.size()` 个重复内全部
   暴露，配合 `fill_holes` "补齐 sack_start 之下一切" 的语义，一个远块 sighting 即修复
   其后全部洞。配套给段加 `sacked` 标记：轮转暴露的块会覆盖已 SACK 的段，不标记会被
   `fill_holes` 当洞重发（实现期发现，属组合缺陷）。
2. **补洞重传再丢 → 发送端 dup-ACK 强制补**：`sack_filled_up_to_` 单调门会让丢失的
   重传卡到 RTO。dup-ACK ≥ 3（`kDupAckThresh`，每批一次、cum 推进重置）强制重发
   `tx_.front()`，先于 `fill_holes` 执行、由其 fresh 守卫防同 ACK 双发。代价：常见
   单洞场景多一个副本（SACK 修复在途时 3 个 dup 已到达）——每洞一次、cum 推进即止，
   接收端按字节裁剪进 `dup_bytes`；既有两测试的精确计数随行为更新（1→2、copies 2→3）。

已知边界不变：**尾段丢失无 dup-ACK 载体**（接收方无新段可确认），仍由 RTO 兜底——
这是 §4 原案就声明的定价。验收实测：同一确定性 burst 场景（e2e，虚拟时钟同种子）
M2 管线 225ms → #27 25ms（9×），`TestBurstLossExceedsFec` 以 <200ms 断言守回归；
`TestSackRotationReportsAllHoles` 以"时钟冻结"证明修复全程无超时参与。

## 5. 承接小项（#29 收口时逐项处理）

1. **优雅关闭与 tombstone 路由保留**（M2 §8.1 尾段竞态）：**已随 #29a 落地**——reap 的
   salt 进 5s 宽限墓碑，迟到重传计 `salt_tombstone` 静默丢弃，服务端不再重建幽灵会话。
2. **D3 慢链路样本门**（§14.8）：**已随 #29a 落地**——interval ≥ 55s 的强制报告样本门
   降至 64、入门阈值加倍（strategy_test 守卫）。
3. **`late_guard`/墓碑上限标定**（§14.14）：**已随 #29a 落地**——上限提至 700/1400ms，
   与握手退避的 RTT 门对齐。
4. **跨连接继承评估**（§14.16）：**评估结论（#29a，不做）**——M2 prewarm 已覆盖 k 冷启动
   （T33 实测省 ~25%/条），#24 的 p_eff 单侧校正缓解短连接欠保护；按目标地址聚合丢包
   样本的增量收益不足以抵其状态复杂度，入档为已知边界。
5. **离线重放工具**（#28）：录制（FECSTAT 报告 + 每 tick 决策 + 配置快照，JSONL）→
   离线装载重放到候选控制器参数 → 输出 k 轨迹/预算峰值对比。阈值标定（§14 第 1 条）的
   工具前提。

## 6. 模块与文件

| 位置 | 内容 | 依赖 |
|---|---|---|
| `src/fcp/settle.h/.cc` | 账本聚合：满编组入账/失败计数/k 直方图/游程直方图 | 仅 std |
| `src/fcp/fecstat.h/.cc` | reserved 字段语义化（ledger_groups/fail_ppm/meta）、flg bit3 | 仅 std |
| `src/fcp/strategy.h/.cc` | `binom_p_for_cdf`、p_eff 校正门与单侧 max、（#25）三态与预算 | 仅 std、`fecstat.h` |
| `src/fcp/reporter.h/.cc` | 打包账本字段与 flg bit3 | `settle.h` |
| `src/fcp/session.cc` | FECSTAT 日志行追加账本/p_eff 字段 | — |
| `src/fcp/stream.h/.cc`（#27） | dup-ACK 快重 + 多洞 SACK 记分板 | 仅 std |
| `tests/e2e_link.h`（#26） | Gilbert–Elliott 注入 → **落地改定**：GE 进 `tests/session_test.cc` 的 `Link`（虚拟时钟、data-only），`e2e_link.h` 维持周期突发注入（真 socket 载体） | — |
| `tools/fcp_replay.cc`（#28） | 轨迹录制/回放；#30 续补齐 `--dump` 裸旗标、`--require-exact` 与数值参数校验 | `fcp` |
| `apps/fcp-proxy/`（#25） | `--fec-budget` 透传：`EngineConfig::fec_budget` → `SessionConfig`；CLI 已落地，**GUI 设置页顺延 #29**（本机 Qt 工具链缺失，见变更记录 #24 条） | `fcp_proxy_core` |

`k_for`/`binom_cdf` 纯函数保持不动（M1 的表格与 T 验收继续有效）；改动只发生在"喂给它
什么 loss"与"输出后如何限速"两层。

## 7. 已知边界（明确不做）

1. **账本只含满编组**：`n_used < D` 的部分集合不入账——码长不匹配二项模型的 D+k 假设，
   混入只会按流量形状而非链路特性污染统计。稀疏流量下账本自然饿死（过不了 64 组门），
   退回纯二项，方向安全。
2. **校正单侧**：只上调不下调（§1.2）。更好的-than-i.i.d. 链路享受不到下调，k 停在
   二项答案上；这是防抖定价，不是精度声明。
3. **主导 k 采样**：k 抖动的过渡报告里，非主导 k 的组被计入主导统计（粒度 ≤1 个 parity）。
4. **CAPPED 不识别拥塞成因**：只看冗余比，不看 RTT/队列信号；它是预算护栏不是控制器。
5. **KL 是检测器**：输出 i.i.d. 偏离度，不产出 GE 参数；参数估计依赖真实轨迹（离线重放
   工具就位后才有可能）。
6. **快重不引入拥塞窗口**（§4）：burst 多洞时快重会放大重传流量，受窗口/rwnd 约束，
   与 §7 第 1 条（无拥塞控制）同一天花板。
7. **账本极端突发偏乐观**（§1.3）：整组全丢不入账；`p_max` 余量与 RTO 兜底覆盖。
8. **p_eff 不改均值口径**：`pre_repair_loss` 的 ~10% 相对低报（§7.2）原样保留——校正
   只对组级失败率负责，不做绝对精度修复。

## 8. 验收线（T34–T39）

| # | 场景 | 通过条件 |
|---|---|---|
| T34 | 账本与线上扩展：golden 字节、flg bit3、旧端互操作 | 新旧互操作零协商；128B 与既有偏移不回退 |
| T35 | R(k) 校正：i.i.d. 对照 vs 同均值突发注入 | i.i.d. 下 p_eff ≈ p_obs（容差内、k 稳定）；突发下 p_eff > p_obs 且 k 上调 |
| T36 | 三态与预算：超预算进 CAPPED、只降不升、回落恢复 | **预算不超**（红线）；OFF/ON 既有行为零回退 |
| T37 | 突发检测：KL 在 i.i.d. ≈ 0、GE 显著 | 阈值行为可标定；GE 注入下校正生效 |
| T38 | 快重/多洞 SACK：burst 下交付时延 RTT 尺度 | T28–T30 全部不变式零回退 |
| T39 | 端到端（含离线重放）：5%/10%/20% 与 GE | k 稳定、预算不超、吞吐不回退 |

## 9. 任务分解

| # | 内容 | 覆盖 |
|---|---|---|
| **#24** | 账本 + FECSTAT 扩展 + p_eff 校正（本里程碑第一刀） | T34、T35 |
| #25 | 三态控制器 + `--fec-budget`（CLI/GUI） | T36 |
| #26 | 突发检测（KL）+ Gilbert–Elliott 注入 | T37 |
| #27 | 快重/多洞 SACK | T38 |
| #28 | 离线重放工具 | T39 |
| #29 | WAN 收口 + 承接小项 + 四套门禁 | T39、§5 |

---

## 变更记录

| 日期 | 条目 |
|---|---|
| 2026-10-31 | M3 开工：范围盘点（M2 观测增强三项已在位）、设计定案（R(k) 单侧校正、FECSTAT reserved 复用、三态 CAPPED、预算默认 0.40）、任务分解 #24–#29 |
| 2026-10-31 | **#24 落地**：`settle` 账本（满编组/失败/游程直方图/主导 k）→ `reporter` 打包（flg bit3、fail_ppm 整除舍入）→ `fecstat` codec 语义化 reserved0..2 → `strategy` 的 `binom_p_for_cdf` 反解与单侧校正门（`kMinLedgerGroups=64`、主导 k 必须等于当前 k）→ `session` 日志行 `FEC ledger: ...`。决策 #29 入协议文档（§7.1 字段表 + §8.1）。实现期修正两个测试假设：①洞数 > k 时 RS 欠定、**零恢复**（`TestLedgerFailedRun` 断言 recovered=0 而非 2）；②`binom_cdf` 在 q→1 处双精度平坦（实测 δp=1.6e-9@k=6、1.8e-7@k=7），反解 roundtrip 跳过 q>1−1e-9 带——校正路径无害（max() 单侧兜底）。fecstat_test 补旧端零账本互操作 golden；reporter_test 两场景 flg 断言升级 + 账本字段断言（26 组 1 失败 → 38462ppm）。T34 覆盖；T35 的注入级验证随 #26 的 GE 载体一起做。Windows Debug/Release ctest 25/25（Linux 回归随 #29 WAN 收口）。**Qt 客户端构建门禁本轮未复验**：本机 vcpkg（D:\work\vcpkg 与 VS 内置）均无 qt6、`build/windows-x64-app` 陈旧缓存 `Qt6_DIR-NOTFOUND`——环境缺依赖，非本次改动所致；`apps/` 不含对 `fecstat/settle/strategy` 头的任何引用（Qt 侧只经 `fcp_proxy_core` 引擎 API），新增字段零影响，Qt 门禁在下一次 GUI 相关任务或 #29 收口时补跑 |
| 2026-10-31 | **#25 落地（T36）**：三态控制器 + 字节预算。`FecState::kCapped`（OFF/ON/CAPPED，`fec_state_name()` 统一日志名）；`FecStrategyConfig::budget_ratio`（默认 0.40，≤0 钳为不限）；逻辑在 on_report 的采样门之后：`ratio = parity_bytes_rx/data_bytes_rx` 超限 → CAPPED 且每报告 k−=1（下限 1，预算优先于 k_target）；回落 1 报告 → 回 ON 不步进（滞回）。输入是 FECSTAT 既有字段，**零线上改动**。透传：`SessionConfig::fec_budget` → `EngineConfig::fec_budget` → CLI `--fec-budget=R`（strtod，帮助文本）。session 日志 `FEC capped:`/`FEC budget restored:` 进出行 + 状态名三态化。测试五场景：进态与逐报告降 k、回落滞回与步进恢复、**红线收敛**（R=0.10 → k=1，ratio≈k/10 仿真）、R=0 不绑、R<k=1 自身比值的退化边界（停在 CAPPED 不下溢）。**GUI 设置页顺延**：Qt 工具链在本机缺失（见 #24 条），`--fec-budget` 的 GUI 透传并入 #29 收口或下一个 GUI 任务；CLI 与 GUI 共用的 `fcp_proxy_core` 已含全量逻辑。协议文档 §8.2 入档。Windows Debug/Release ctest 25/25 |
| 2026-10-31 | **#26 落地（T37 + T35 注入级）**：突发检测 = 原始游程账本 + 精确 i.i.d. 参照 + KL。`run_dist_iid`（游程 DP，P(M=l) 全分布，对 2^10 掩码穷举 1e-12）+ `burst_kl_iid`（Q 钳 1e-12，空账本返回 0）+ `FcpSettle::burst_kl()`（p 取账本总体原始丢失率）；reporter 打进 `ledger_meta` 高 16 位（0.01 nat 饱和），session 日志行加 `kl=`。**游程口径从 #24 的"结算时未恢复"改为原始丢失**——RS 全有全无修复会把 i.i.d. 链路伪装成突发；两处 #24 断言随之修正。KL 用途本里程碑定为诊断/可信度信号，不改校正门（加权留待真实轨迹标定）。session_test `Link` 加 GE 两态马尔可夫（**data-only**：丢 parity 会把 `sets_k_unknown` 顶过 10% 信任门，R(k) 反馈路径没被行使——实现期实测）；`TestLedgerLiftsKUnderBursts` 双臂对照（initial_k=2 起步、8000 段、发送与 tick 交错）：i.i.d. 臂全程 k=2；GE 臂 fail 17.5%→22%、kl 1.04→1.60，k=3 且在均值 9% 的报告上仍由 peff=0.149 顶住（二项答案 k=2）——账本而非均值在支撑 k。实现期另踩一坑：发送与 tick 不交错则首份 FECSTAT 在全部段发完后才到，全程 k=0、parity=0。settle_test 新增 3 组 KL 单测（穷举对照、KL(P=Q)=0、KL(δ)=−ln Q、场景级 clean=0 / run-of-3 > 1 nat）。Windows Debug/Release ctest 25/25 |
| 2026-10-31 | **#27 落地（T38）**：快重/多洞 SACK。落地再定案见 §4.1——M2 `fill_holes` 对首洞已是即时补，真缺口是①非相邻多洞的单块盲区（接收端 dup-ACK 上轮转 SACK 块 + 发送端 `sacked` 段标记防把 SACK 段当洞重发）与②补洞重传再丢被 `sack_filled_up_to_` 卡到 RTO（发送端 dup≥3 每批一次强制补 `tx_.front()`，置于 fill 之前由其 fresh 守卫防双发）。17B ACK 格式不变；尾段丢失仍归 RTO（无 dup 载体）。测试：stream_test 新增 3 场景（轮转三块/强制补洞与每批一次/无虚假触发），`TestSackFillsHoleWithoutTimeout`、`TestKarnDropsAmbiguousSamples` 精确计数随行为更新（+1 fast copy，Karn 性质不变），e2e burst 场景确定性实测 225ms→25ms（9×）并以 <200ms 守回归。M2 §7 第 2 条入档指针已加。Windows Debug/Release ctest 25/25 |
| 2026-10-31 | **#28 落地（T39 工具半边）**：`src/fcp/trace.h/.cc`（TraceEntry = 报告全字段扁平 JSONL + 生效配置快照 + 决策；严格扁平扫描解码，未知键跳过；`replay_trace` 用快照重建 FecStrategy 逐报告重放，确定性）→ `SessionConfig::trace` 录制钩子（每个 kOk 报告一条，含被门挡下的——重放时门行为同样复现；快照取协商后的 d/P'）→ `tools/fcp_replay`（装载/覆盖参数/重放，输出 k 轨迹、CAPPED 数、字节比峰值、与录制的 agree 率）。实现期修了 **FrameRx oob 回调丢 now_ms** 的老问题（分发硬编码 0，OobFn 加时间参数）——策略从不需要时间戳所以从未暴露。测试：往返/确定性复现（5/10/20% + GE 全部逐决策一致）/预算 what-if（0.10 → CAPPED 走到 k=1）/golden 文件 + ctest 冒烟。**逮住 #25 真缺陷**：线上 ratio = k/D 而非 §8.2 写的 k/(D+k)，默认 0.40 恰好绑在 k=4（20% 丢包工作点）——默认改 0.50，决策 #30 勘误入协议文档。**T39 全绿的控制器半边就此在 gate 内常驻**（5/10/20% k 稳定 + 预算不超 + GE 抬升）。**CLI/GUI 的 `--trace` 录制接线顺延 #29**（WAN 标定时随部署一起接）。Windows Debug/Release ctest 27/27（新增 replay_test 与 fcp_replay 冒烟） |
| 2026-10-31 | **#29a 落地（本地半边）**：① **salt 路由 tombstone**（M2 §8.1 尾段竞态收口）：reap 的 salt 不再直接遗忘，进 `salt_tombstones_`（宽限 5s = 对端 RTO 尾）——迟到重传按 `salt_tombstone` 静默丢弃，客户端不再计 `unknown_salt`，**服务端不再把迟到重传误当新 HELLO 重建幽灵会话**（原缺陷此前只观察到客户端侧，服务端侧是推演出的同根缺陷）；过期项 on_tick 清扫。② **CLI `--trace=PREFIX`**：每会话一路 JSONL（`PREFIX.<cid>.jsonl`，shared_ptr 随会话销毁关文件），WAN 标定的录制入口就位（GUI 透传仍顺延）。③ **late_guard/墓碑上限 500/1000 → 700/1400ms**（§14.14，对齐握手退避的 RTT≤700ms 门）。④ **D3 慢链路样本门**（§14.8）：interval ≥ 55s 的强制报告样本门降至 64、OFF 入门阈值加倍——分辨率损失不得变成入门抖动。⑤ 跨连接继承评估入档：M2 prewarm 覆盖 k 冷启动 + #24 p_eff 单侧校正缓解短连接欠保护，按目标聚合丢包样本的收益不足以抵其复杂度，**不做，入档为已知边界**（§14.16 的结论）。测试：proxy_engine_test 新增 tombstone（双端）与 trace sink（文件存在/可解码/随会话关闭）场景；settle 钳值断言更新；strategy_test 新增 D3 场景。Windows Debug/Release ctest 27/27 |
| 2026-10-31 | **#29b 落地（Linux 门禁 + 局域网双机联调）**：环境为局域网 Ubuntu 22.04 测试机（g++ 11.4/cmake 3.22/ninja，地址不入库，git archive 传输）。① **Linux × Debug/Release ctest 27/27**（Release 为手动配置——presets 只有 linux-x64-debug 构建预设）——**四套门禁齐**（Windows/Linux × Debug/Release）。② **LAN 双机联调七项全过**（Windows 客户端 ↔ Ubuntu 服务端，SOCKS5 + python http.server 源站）：GET、8MiB SHA256 逐字节一致、**68.9 Mbps**（0.974s，无损链路 k=0 纯吞吐）、HTTP CONNECT + TLS（外网 200）、拒绝目标（curl exit 97 = SOCKS 失败应答）、20 串行 + 10 并发全过；双端收尾 `live=0 refused=1 bad_entry=0 clash=0 unknown=0 tomb=0` 零泄漏零异常（LAN 无损无尾段重传，tomb=0 符合预期，逻辑由 gate 的 `salt_tombstone_absorbs_tail` 守卫）。③ **实机 trace/重放闭环**：双端 `--trace` 各写 37 个会话文件（短会话 0 行符合报告节奏），`fcp_replay` 在 Ubuntu 上回放实机轨迹 agree 2/2、`--budget=0.10` what-if 正常出 CAPPED。④ 修掉 stats 行 `tomb=` 字段——#29a 提交时编辑脚本静默失配未入库，实机验证发现并补上（实机跑一遍的价值）。**遗留**：跨 WAN 复测吞吐（180ms/10% 丢包真链路上 #27 快重与 #24 校正的收益标定）仍需真实 VPS 环境 |
| 2026-10-31 | **#30 落地（M3 代码对抗复查）**：M1/M2 都过过对抗轮（F1–F5、adv_test），M3 新增面照做一遍，抓到三处真缺陷并修掉：① **stream ACK 谎报防线缺失**——`cum > snd_nxt` 的 ACK 会弹光全部未确认段并把数据永久搁浅（接收端也没有那些字节）；`handle_ack` 入口拒绝并计 `bad_segs_`（谎报 rwnd 无害：`send_space` 被本端窗口钳住，测试注释留档）。② **trace 解码器两处**——`1e999` → HUGE_VAL → int 转换 UB（非有限值拒绝整行）、闭括号后尾随垃圾与重复键取首个（对象必须终结该行、重复键按 JSON 语义取末个）。③ **§14.6 关闭时 FECSTAT 补发落地**：`Session::flush_report` 挂在引擎 reap（唯一销毁点），有内容的区间立即上报——对端的墓碑窗口（#29a 的 5s）保证报文仍可路由；短会话的 trace 文件由此必有内容。测试：stream `TestAckBeyondSndNxtIgnored`、reporter `TestFlushOnTeardown`、replay `TestTraceCodecFuzz`（14 个坏行 + 3 个容忍档 + 大数往返 + 重复键）、strategy `TestLedgerFieldExtremes`（fail_ppm 42x钳制无 NaN / k=9 拒收 / 4G 组数过门）。Windows Debug/Release ctest 27/27。复查中也校准了两处测试自身的错误预期（`{"ver":1}` 是合法默认值行、0.20 丢失在 k=2 的失败率就是 44%） |
| 2026-10-31 | **#30 续（对抗复查二轮：重放/确定性）**：① **trace 浮点不是无损格式**——`%.9g` 把 `nextafter(0.8)` 折叠回 `0.8`，配置快照经 encode→decode 后可能与录制时不同，回放恰在阈值附近会分叉；改用 `%.17g`（精确整数范围内仍输出整数），`TestTraceDoubleRoundTrip` 用三个邻接 double 守卫。② **解码器整数字段越界 UB**——`-1`/`1e300`/`70000` 这类值原先经 double→uint8/16/32 转换（C++17 下越界为 UB）；现在每个整数字段先做线宽区间检查，越界拒绝整行，`TestTraceCodecFuzz` 增加 4 条坏行。③ **`fcp_replay --dump` 文档承诺但不可用**——参数解析要求所有选项带 `=`，裸旗标直接 "bad argument"；解析器现接受裸 `--dump`/`--require-exact`。④ **golden 冒烟只查退出码**：新增 `--require-exact`（agree 不等于条目数时退出 1），ctest 冒烟改为 `--dump --require-exact`，黄金轨迹从"能加载"升级为"逐决策复现录制"的真回归门（当前 5/5）。⑤ 工具的覆盖参数补整串/区间校验（`--d=abc` 不再静默变 0，`--budget=nan` 拒绝）。其余发现（反应堆/引擎）与 Stream 守卫复核见 `FCP_M2_PROXY.md` §8.3。Windows Debug/Release 均 27/27 |
