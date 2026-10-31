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
  （`--fec-budget R`，R ∈ (0,1]，默认 **0.40**；`R = 0` 表示不限）。D=10、k ≤ 7 时冗余比
  上界 k/(10+k) ≈ 41%，故默认值实际只在 k=7 时触界——**默认 practically off、wired and
  testable**，深队列部署按需收紧。
- **CAPPED 行为**：k 只降不升（对齐 §8 排队护栏语义）；冗余比回落且连续 1 个报告不超 ⇒
  回 ON。预算比较在每报告时做。
- **定位**（§14.11）：预算是"深队列 + 高丢包"下冗余字节的**天花板**，防正反馈靠它兜底，
  不是拥塞控制器；排队护栏（srtt − min_rtt ≥ 40ms 不升 k）语义不变。

## 3. 突发检测：经验分布 + KL（#26）

v5 遗产的结构化版本：

- 输入：账本的 `run_hist`（组内最大连续丢失游程 l = 0..8+ 的分布）。
- 参照：i.i.d. 假设下 P(L ≥ l) 的几何衰减预测（用区间实测丢包率与 D、k 推出）。
- 距离：KL(P_emp ‖ Q_iid)，量化 0.01 nat 填进 `ledger_meta` 高 16 位。
- 用途：`burst_kl` 高 ⇒ p_eff 校正可信度升高（突发是偏差来源）；`burst_kl ≈ 0` ⇒
  i.i.d. 成立，校正在容差内自动退化为恒等。**检测器不是模型**：只输出偏离度，不估计
  Gilbert–Elliott 参数（p/g/转移概率留给有真实轨迹标定后，见离线重放工具）。
- 验收载体：`tests/e2e_link.h` 增加 Gilbert–Elliott 注入（好/坏两态马尔可夫，坏态丢包
  p_bad、转移概率可配），与既有随机/burst 注入并列。

## 4. 快速重传与多洞 SACK（#27，承接 M2 §7 第 2 条）

M2 的定价（单洞 SACK 立补、其余等 RTO）在 WAN 上的实测签名是 "~1MB 突发 + ~2s 停顿"
（#23 探针修复后仍有残留，8.56 Mbps vs fcp_bench 同链路 25.8 Mbps）。M3 补齐：

- **快重**：同一 sn 的重复 ACK 计数 ≥ 3 ⇒ 立即重传第一个未确认洞，不等 RTO；
- **多洞**：SACK 记分板扩展到多洞，每个 dup-ACK 批推进一个洞的快重；
- **不做**：拥塞窗口减半与完整的 NewReno 状态机——§7 第 1 条（无拥塞控制）不变，引擎
  仍只有固定发送窗口 + rwnd 流控；快重放大出的流量受窗口与 rwnd 约束。
- 验收：burst 注入下交付时延从"RTO 尺度"降到"RTT 尺度"；有序/恒等式/无重复不变式全部
  保留（T29/T30 既有断言不许回退）。

## 5. 承接小项（#29 收口时逐项处理）

1. **优雅关闭与 tombstone 路由保留**（M2 §8.1 尾段竞态）：墓碑之后短暂保留 salt 路由，
   让迟到重传不再计 `unknown_salt`。
2. **D3 慢链路样本门**（§14.8）：`interval ≥ 60s` 强制上报时样本门降为 ≥64 并用保守
   阈值，或按速率放大强制间隔——以慢链路仿真数据定。
3. **`late_guard`/墓碑上限标定**（§14.14）：上限 500ms/1s 与握手退避支持的 RTT≤700ms
   区间不自洽；按实测 srtt 缩放或提上限。
4. **跨连接继承评估**（§14.16）：M2 预热已覆盖 k 冷启动；评估是否需要按目标地址聚合
   丢包样本（大概率结论是"预热够了 + p_eff 校正已缓解"，入档即可）。
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
| `tests/e2e_link.h`（#26） | Gilbert–Elliott 注入 | — |
| `tools/fcp_replay.cc`（#28） | 轨迹录制/回放 | `fcp` |
| `apps/fcp-proxy/`（#25） | `--fec-budget` 透传（CLI 与 GUI 设置页） | `fcp_proxy_core` |

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
