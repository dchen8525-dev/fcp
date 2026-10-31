# FCP v6 M1 验收记录（任务 C3）

> 依据：`FCP_PROTOCOL_V6.md`（§13 测试矩阵、附录 C 21 条修订 + #22–#25 勘误）、
> `FCP_V6_DETAILED_DESIGN.md`、`FCP_M1_TASKS.md` §4 验收线。日期：2026-10-30。
> 本文件是 C3「回归 + 冻结 + 门禁」的归档记录：① T1–T23 全绿；② 覆盖率达门禁；
> ③ 附录 C 21 条 + #22–#25 逐条核验；④ 三档丢包 10 分钟 soak 无 crash、无恒等式违例。

---

## 1. 回归结果

构建与测试（Windows x64 / MSVC 19.51 / Ninja Multi-Config，Debug）：

```bat
cmd /c build.bat Debug
```

- **20/20 ctest 通过**（18 个模块/集成测试 + soak_test + adv_test 对抗探针），Debug 总耗时约 1.6 s；
  Release（`cmd /c build.bat Release`）同样 20/20 通过，约 0.4 s；
- 测试源共 **1451 条 CHECK 断言**（大量断言位于循环内，实际执行次数远高于此；2026-10-30 对抗分析与 D1 适配新增约 350 条，见 §7/§10/§11）；
- 编译器 `/W4 /permissive-` 下零 error；仅存 `sscanf`/`getenv` 的 C4996 弃用提示（与既有测试一致，未开 `/WX`）。

| 测试可执行文件 | 用例数（`void Test*`） | 主要覆盖 |
|---|---|---|
| `fcp_gf256_test` | 2 | 域表性质、四则运算 |
| `fcp_cauchy_test` | 2 | 柯西矩阵 golden、任意子矩阵可逆 |
| `fcp_rs_test` | 4 | 编码 golden、随机丢包恢复 fuzz、幽灵 parity、超擦除拒绝 |
| `fcp_aes_test` | 2 | FIPS 197 附录 C.1、AES-NI/T-table 双路径一致 |
| `fcp_ghash_test` | 2 | GF(2^128) 性质、GHASH golden |
| `fcp_gcm_test` | 2 | NIST GCM 向量、往返与篡改 |
| `fcp_envelope_test` | 10 | 28B 信封、篡改/盐隔离、重放、nonce 上限（收发两侧）、方向密钥隔离（#26）、**会话密钥按会话派生（#28①）**、**v7 黄金向量（#31）**、`rekey` 归零、CSPRNG 可用性 |
| `fcp_hdr_test` | 3 | 6B 头 golden、全字段往返、校验顺序 |
| `fcp_fecstat_test` | 3 | 128B 布局 golden、四类丢弃、单调键 |
| `fcp_kfor_test` | 3 | T20 反解表、CDF 参考值、边界 |
| `fcp_strategy_test` | 11 | OFF/ON 迁移、护栏、clean 5、防抖、pin、样本门 |
| `fcp_handshake_test` | 17 | 线格式 golden（36/52 字节，v3 magic 不识别）、互握手、caps、超时（退避口径）、重传退避 T26、幂等、协商前缓存、**密钥协商一致（#31）**、**ACK echo 不匹配拒收**、**已建立会话拒新 HELLO（R3-24）**、**零 nonce 拒绝**、**nonce 随机性** |
| `fcp_frame_tx_test` | 10 | MTU、满组/空闲/异常闭合、k_eff、KCP 输出恒为 data（无内容分类）、T_flush |
| `fcp_frame_rx_test` | 12 | 位图分离、n 由 parity、幽灵 parity、struct_fail、未定义 type 拒收、锚点不被畸形帧推进、去重窗口、容量淘汰 |
| `fcp_settle_test` | 9 | 相位机、尾丢、k_unknown 与不可信门、迟到记账、恒等式 fuzz |
| `fcp_reporter_test` | 6 | 2s/256 包节奏、60s 强制、空闲抑制、flg、分位数 |
| `fcp_session_test` | 16 | 内存回环全闭环、握手/ACK 走 oob、非法本地 caps、pin 夹到 P'、握手超时、协商前（出站）缓存与超 MTU 拒收、协商前入站 data/parity 丢弃（不反射）、排队护栏 min_rtt 基线、无 FECSTAT 看门狗、SessionTable、**录制握手重放不能复活会话（#31）** |
| `fcp_e2e_test` | 6 | T3/T7/T8/T10 + 20% 丢包 ARQ fuzz（真实 UDP 回环）+ burst 注入实测（E2） |
| `fcp_soak_test` | 3 档 | 0%/5%/20% 双向长跑（见 §6） |

---

## 2. T1–T23 验收对照

| 测试 | 规格要求（§13） | 覆盖位置 | 结果 |
|---|---|---|---|
| T1 | FECSTAT 128B golden、偏移/类型/单位、长度/magic/salt/ver、stale 拒收 | `fcp_fecstat_test`：`TestGoldenLayout` / `TestValidation` / `TestMonotonicKey` | ✅ |
| T2 | IPv4/IPv6 × 默认/极值 MTU，data/parity/oob 不超预算 | `fcp_frame_tx_test`：`TestMtuLimits`（1336/1338/1312、1316/1318/1292、边界 89） | ✅ |
| T3 | `k=0` 无丢失：线上无 parity、`data_expected` 精确、`pre=0` | `fcp_e2e_test`：`TestT3LosslessKZero` | ✅ |
| T4 | `k=P` 单分片/最大分片丢失可恢复；`data_rx_orig` 不含重建 | `fcp_frame_rx_test`：`TestRecoveryMasksDisjoint`（擦除 index 2/7，其中 7 为最大 symbol）、`TestDataDeliveryAndDedup` | ✅ |
| T5 | 整组 parity 全丢：`k` 由 data 得知、`parity_expected=k`、`parity_rx=0`、不重建 | `fcp_frame_rx_test`：`TestNoParityNoDecode`；`fcp_settle_test`：`TestGhostPlanValue`（`parity_expected` 为计划 k） | ✅ |
| T6 | 整组全丢按 `set_id` 跳变只计 `sets_k_unknown`，>10% 标不可信、k 不动 | `fcp_settle_test`：`TestKUnknownAndUntrusted` / `TestTrustedRatio` | ✅ |
| T7 | 原始/重建同一 sn 只交付一次 | `fcp_e2e_test`：`TestT7RecoveryRetransmitCollision`；`fcp_frame_rx_test`：`TestSnDedupWindow` | ✅ |
| T8 | 认证失败不进 RS、不污染计数，只 `auth_fail+1` | `fcp_e2e_test`：`TestT8AuthFailDoesNotTouchSets`（14 项计数逐一不变） | ✅ |
| T9 | 非法 len / 非零填充 → `struct_fail+1`，不交付 | `fcp_frame_rx_test`：`TestStructFail` | ✅ |
| T10 | FRAMED_STATS：无 RS、无 parity、`k≡0` | `fcp_e2e_test`：`TestT10FramedStats` | ✅ |
| T11 | 超时/非法 caps → ERROR，不静默降级 | `fcp_handshake_test`：`TestTimeout` / `TestInvalidCaps` / `TestMissingCapability`；`fcp_session_test`：`TestHandshakeTimeout` | ✅ |
| T12 | 满组/空闲/异常三路径闭合的记账 | `fcp_frame_tx_test`：`TestFullClose` / `TestIdleCloseAndDecode`；`fcp_settle_test`：`TestTailDrop` | ✅ |
| T13 | 墓碑期迟到：首次计 `data_late_rx`、重复计 `late_dup` | `fcp_settle_test`：`TestLateAccounting` | ✅ |
| T14 | oob 不占槽、不占 index，`data_expected = D × sets_expected` | `fcp_session_test`：`TestHandshakeRidesOob` / `TestHandshakeAckRidesOob`；`fcp_frame_tx_test`：`TestKcpOutputIsAlwaysData` | ✅ |
| T15 | 区间自适应、60s 强制、≥256 才驱动状态机 | `fcp_reporter_test`：`TestTwoSecondCadence` / `TestForcedSixtySeconds`；`fcp_strategy_test`：`TestSmallSample` | ✅ |
| T16 | `type_k` 拆分 golden、`j≥k`/`n` 越界判 malformed、`k=0` 无 parity | `fcp_hdr_test`：`TestPackGolden` / `TestRoundTripAllFields` / `TestValidationOrder`；`fcp_frame_tx_test`：`TestZeroK` | ✅ |
| T17 | 空闲闭合 `n=3`、`k_eff` 缩放、码长恒 `n+k` 可解 | `fcp_frame_tx_test`：`TestIdleCloseAndDecode` / `TestKEffScaling`；`fcp_frame_rx_test`：`TestGhostParity` | ✅ |
| T18 | `(12,2)→n=10`、`(6,1)→5`、n 冲突失败、无 parity 不重建 | `fcp_frame_rx_test`：`TestNoParityNoDecode` / `TestGhostParity` / `TestRecoveryMasksDisjoint` | ✅ |
| T19 | 28B 信封、IV 方向隔离、tag 篡改、MSS 1312 | `fcp_envelope_test`：全部 5 例；`fcp_frame_tx_test`：`TestMtuLimits` | ✅ |
| T20 | `k_for` 反解表 1/1/2/3/4/4，20% 不回落 3 | `fcp_kfor_test`：`TestKForTable` / `TestCdfReference` / `TestKForEdges` | ✅ |
| T21 | 协商前 data 缓存、完成按序进集合、超限/失败丢弃 | `fcp_handshake_test`：`TestDataCache` / `TestCacheLimits`；`fcp_session_test`：`TestPreNegotiationCache` | ✅ |
| T22 | `rx + rec + lost + late = expect` fuzz 恒成立 | `fcp_settle_test`：`TestIdentityFuzz`；`fcp_rs_test`：`TestGhostParity`；`fcp_e2e_test`：`TestFuzzLoss20Percent` | ✅ |
| T23 | 握手 oob 化：HELLO/ACK type=2、`set_id=index=0`；type=3 未定义即 struct_fail；无内容分类；重传 Established 即停 | `fcp_handshake_test`：`TestWireGolden`（36B/52B，#31 后）/ `TestAckStopsRetries`；`fcp_session_test`：`TestHandshakeRidesOob` / `TestHandshakeAckRidesOob`；`fcp_frame_tx_test`：`TestKcpOutputIsAlwaysData`；`fcp_frame_rx_test`：`TestInvalidTypeAndOobBypass`；`fcp_adv_test` R2.5 | ✅ |

---

## 3. golden 冻结清单（全部随测试源码入库）

| 位置 | 冻结内容 | 来源 |
|---|---|---|
| `tests/cauchy_test.cc:12` `TestGoldenMatrix` | `C[r][c] = 1/(r ^ (k+c))`，n=10、k=3 的 3×10 系数表 | 自有参考值（设计勘误 #8 落码） |
| `tests/rs_test.cc:22` `TestGoldenParity` | RS(6,4,2) 两条 parity 的 6 字节 golden | 自有参考值（无外部互验） |
| `tests/aes_test.cc:7` `TestFips197AppendixC1` | FIPS 197 附录 C.1 的 128 位密钥/明文/密文 | 标准向量 |
| `tests/ghash_test.cc:45` `TestGhashGolden` | GHASH 单块 golden | 标准算法推导值 |
| `tests/gcm_test.cc:75` `TestNistVectors` | NIST GCM case 1–3（空消息、单零块、60B+20B AAD） | 标准向量 |
| `tests/envelope_test.cc:22` `TestEmptyAndRoundTrip` | 28B 空明文信封、tag 12、IV 方向隔离 | 规格 §4.1 |
| `tests/hdr_test.cc:7` `TestPackGolden` | `type_k = (k<<5)\|(j<<2)\|type` 的 0x20/0x21/0x25/0x89/0xFD 与 6B 头字节 | 规格 §4.2 |
| `tests/fecstat_test.cc:54` `TestGoldenLayout` | 128B FECSTAT 全字段字面偏移镜像（含 `data_late_rx@100`、`sets_partial@104`） | 规格 §7.1 |
| `tests/handshake_test.cc` `TestWireGolden` | HELLO/ACK **36/52** 字节十六进制 golden（16B magic + 16B×1/2 nonce + 4B caps，#31）；同用例断言 `FCP_HELLO_V3` 不再被识别 | 规格 §6.1 |
| `tests/kfor_test.cc:14` `TestKForTable` | loss→k 反解表与单组修复率参考值 | 规格 §8 |
| `src/fcp/frame_tx.h:57` `static_assert` | MTU 派生常量 1336/1312、1316/1292 | 规格 §4.1 表 |

> 说明：FCP 是自有新协议，清单中的"自有参考值"按任务清单 §6 的 2026-10-29 澄清执行——
> 不与 kcp-go/kcp-cpp 互验；A3 只依赖 FIPS/NIST 标准向量与双路径一致。

---

## 4. 附录 C 21 条逐条核验

| # | 修订要点 | 实现落点 | 验证 |
|---|---|---|---|
| 1 | 迟到原始 data 独立计 `data_late_rx`（offset 100），不变量含该项 | `settle.cc:92` 事件分类；`fecstat.h:44,76` | `settle_test` `TestLateAccounting`；`fecstat_test` golden 偏移 100 |
| 2 | （#25）HELLO/ACK 走 type=2 oob（原 type=3 控制通道已取消，收到即 struct_fail）；按类型分流；`data∧index≥D` malformed；锚点 = 最大 set_id − 256 | `session.cc` `send_oob`/`on_oob`、`kInvalidType` 分支；`frame_rx.cc` 锚点与窗口（畸形帧不推进锚点）；`hdr.cc` 校验 | `session_test` `TestHandshakeRidesOob` / `TestHandshakeAckRidesOob`；`frame_rx_test` `TestInvalidTypeAndOobBypass` / `TestStaleAnchor` / `TestMalformedDoesNotMoveAnchor` |
| 3 | 删除 LEGACY；握手失败即 ERROR；caps `D'≥1`、`D'+P'≤256`（u16） | `handshake.cc:11-20` `caps_valid`（u16 中间量）；`handshake.h:50` 仅两种模式 | `handshake_test` `TestInvalidCaps` / `TestTimeout` |
| 4 | 整组全丢的 `t_first` 取跳变观测时刻 | `frame_rx.cc:189-199` `create_placeholders(now)` | `settle_test` `TestKUnknownAndUntrusted` |
| 5 | FECSTAT 计数字段按"本区间"，每周期清零 | `reporter.cc:130-139` `reset_interval`（保留 `accounted_through_set_id`） | `reporter_test` `TestTwoSecondCadence`；`fecstat_test` `TestMonotonicKey` |
| 6 | oob（含 HELLO/ACK）不占 index、不进集合、不计数、无 len 前缀 | `session.cc` `send_oob` 固定 `set_id=index=0`；KCP 输出路径无 control 分支 | `session_test` `TestHandshakeRidesOob` / `TestHandshakeAckRidesOob`；`frame_tx_test` `TestKcpOutputIsAlwaysData` |
| 7 | （已被 #12 取代） | — | N/A（不适用） |
| 8 | 冻结"一 symbol = 一 KCP segment" | `session.cc` `on_kcp_output` 一对一（握手报文独立走 oob，不占 KCP 段）；`frame_tx.cc` | `frame_tx_test` `TestFullClose`；`session_test` `TestFullLoop` / `TestHandshakeRidesOob` |
| 9 | 每条新分片触发解码（无 4 次/秒限流）；`max_active_sets` 256；墓碑优先淘汰 | `frame_rx.h:28` `kMaxActiveSets=256`；`frame_rx.cc:237` 淘汰顺序；`frame_rx.cc` `try_decode` 每片 | `frame_rx_test` `TestIncrementalTrigger` / `TestCapacityEviction` |
| 10 | 上报 ≥2s 且 `data_expected≥256`，60s 封顶；策略样本门 | `reporter.h:27-29`；`reporter.cc:52-73`；`strategy.cc:24,71` | `reporter_test` `TestTwoSecondCadence` / `TestForcedSixtySeconds`；`strategy_test` `TestSmallSample` |
| 11 | 小项：magic 16B 只约束 oob；RTO 行标 M2；parity `index<D` malformed；同时 HELLO 幂等；默认 `FRAMED_REPAIR` | `session.cc` `send_oob`/`on_oob` magic；`hdr.cc` `kIndexPastS/kJNotBelowK`；`handshake.cc` 幂等分支；`handshake.h:50` | `handshake_test` `TestIdempotent` / `TestCapsNegotiation`；`hdr_test` `TestValidationOrder` |
| 12 | `k` 集合开始锁定且 data/parity 都携带；`sets_k_unknown`；恢复 `parity_rx≤parity_expected` | `frame_tx.cc:43-53`（组首锁 k，data 头带 k）；`frame_tx.cc` parity 同 k；`settle.cc:83` 计划值；`settle_test.cc:357` 断言 | `hdr_test` `TestRoundTripAllFields`；`settle_test` `TestGhostPlanValue` / `TestIdentityFuzz` |
| 13 | （#25 已作废逐段内容判定）KCP 输出无内容分类；`len` 前缀仍只用于 data | `frame_tx.cc` `on_kcp_output` 全部按 data 处理 | `frame_tx_test` `TestKcpOutputIsAlwaysData` / `TestFullClose` |
| 14 | 删除 `BARE_KCP` 与 `--fec off`，FEC 恒开恒成帧 | 无该模式/开关；`handshake.h:50` 仅 `kFramedRepair`/`kFramedStats`；`Session` 无裸 KCP 路径 | 全部 e2e/soak 测试均在成帧 FEC 路径上运行 |
| 15 | 允许不满 D：`T_flush` 闭合、parity 基址 `n`、`data_expected += n`、`sets_partial@104` | `frame_tx.cc` `maybe_flush`/`close_set`；`frame_rx.cc` `n = index − j`；`settle.cc:64-81`；`fecstat.h:45` | `frame_tx_test` `TestIdleCloseAndDecode`；`fecstat_test` golden 偏移 104 |
| 16 | 默认几何 8+2 → 10+3（Pmax=4） | `session.h:41-42` `d=10,p=3`；`strategy.h:20` `kDefaultPmax=4` | `handshake_test` `TestCapsNegotiation`；`session_test` `TestFullLoop`（日志 data=10 parity=3） |
| 17 | （已被 #20 取代） | — | N/A（不适用） |
| 18 | 信封 28B（salt8+nonce8+tag12）；FECSTAT salt 8B 且 u32 前移；MTU 1336/1312 | `envelope.h:26` `kOverhead=28`；`fecstat.h:21,53-76`；`frame_tx.h:57-62` | `envelope_test` 4 例；`fecstat_test` `TestGoldenLayout`；`frame_tx_test` `TestMtuLimits` |
| 19 | `eligible` 增加"收到本集合 parity 即闭合" | `settle.cc:40` `view.saw_parity \|\| anchor>id` | `e2e_test` `TestT7RecoveryRetransmitCollision`（1 data + 1 parity 的空闲闭合组凭 parity 结算）；`settle_test` `TestBasicAccounting` |
| 20 | 头字段拆 `k`(3)+`j`(3)，`n = index − j`；`k_eff` 缩放；`k_for` 反解；区间上限 60s | `hdr.h` `pack_type_k`；`frame_tx.cc` `close_set` 计算 `k_eff`；`strategy.cc:30-38` `k_for`；`reporter.h:28` | `hdr_test` 3 例；`frame_tx_test` `TestKEffScaling` / `TestIdleCloseAndDecode`；`kfor_test`；`reporter_test` `TestForcedSixtySeconds` |
| 21① | RS 码长恒 `n+k`，`k_eff` 只决定发送条数 | `frame_tx.cc` `close_set`（矩阵用计划 k，发送 k_eff 条） | `frame_tx_test` `TestIdleCloseAndDecode`；`frame_rx_test` `TestGhostParity` |
| 21② | `orig_mask`/`recov_mask` 分离，`data_rx_orig` 不含重建 | `frame_rx.cc` 三张位图；`settle.cc:70-75` | `frame_rx_test` `TestRecoveryMasksDisjoint` |
| 21③ | 整组全丢只计 `sets_k_unknown`，>10% 不可信 | `settle.cc:59-63,119-123`；`strategy.cc:66-69` | `settle_test` `TestKUnknownAndUntrusted` / `TestTrustedRatio`；`strategy_test` `TestUntrustedSample` |
| 21④ | 协商前只放行 oob（HELLO/ACK），data 缓存 64 段/64KB | `session.cc` `on_wire` 预协商分支；`handshake.cc` `cache_data` | `handshake_test` `TestDataCache` / `TestCacheLimits`；`session_test` `TestPreNegotiationCache` / `TestHandshakeRidesOob` |
| 21⑤ | 日志恒等式 `rx+rec+lost+late=expect` 与 ppm | `session.cc` FECSTAT 日志；`e2e_test.cc` `ParseFecstatLog` 逐字段核对 | `e2e_test` `TestT3LosslessKZero` / `TestT10FramedStats`；`session_test` `TestFullLoop` |
| 21⑥ | "clean 5" 按报告数计，不换算秒 | `strategy.cc:119-125` `clean_streak_` | `strategy_test` `TestCleanStreak` |
| 21⑦ | caps `D+P≤256` 用 u16 中间量 | `handshake.cc:17` | `handshake_test` `TestInvalidCaps`（含 255+63 边界） |

**统计**：21 条中 19 条有实现与测试双落点并核验通过；#7、#17 已被后续修订取代，记录为 N/A。

---

## 5. 覆盖率门禁

- 门禁值：**line ≥ 90% / branch ≥ 80%**（T0 决策 3）；
- 入口：`scripts/coverage.sh`（gcc/clang + gcovr；`FCP_COVERAGE=ON` 由 CMake 目录级
  `add_compile_options/add_link_options --coverage -O0` 打开，因静态库无链接步骤，
  PRIVATE link option 无法传播到测试可执行文件）；
- 脚本在 CI（Linux）上执行：configure → build → ctest → `gcovr --fail-under-line 90
  --fail-under-branch 80`，未达标即非零退出；
- **本机限制**：Windows 开发机为 VS 18 Community，随附 LLVM 只有 `clang-format/clang-tidy`，
  无 `gcov`/`llvm-cov`/`OpenCppCoverage`，`vsperfcmd` 已在新版 VS 移除。因此该项在 CI 上执行，
  本记录不伪造本地数字。

---

## 6. 三档丢包 10 分钟 soak（C3 ④）

```bat
set FCP_SOAK_MS=600000
set FCP_SOAK_REALTIME=1
build\windows-x64\tests\Debug\fcp_soak_test.exe
```

- 三档丢包（0%/5%/20%）三对独立 UDP 回环通道在同一进程内共享一条墙钟时间轴交错推进，
  总时长约 10 分钟（非 30 分钟）；每通道双向 4 段/tick（25ms tick，约 160 段/秒）；
- `realtime=1` 时每 4 个 tick（100ms）批量睡眠一次对齐墙钟，摊薄 Windows 定时器粒度开销；
- 每 tick 对三通道双端 `FcpSettle` 断言 `identity_ok()`，每个交付断言 payload 16 字节完整；
- KCP 侧 ARQ：300ms 未交付重发，最多 20 次；注入停止后三通道交错 drain（连续 40 tick
  重发队列为空即视为排空）再断言；
- 结束断言：累计 `FrameRx::data_delivered()` 等于各方向注入总数（替代对时序敏感的
  `delivered_le_sum` 快照）；0% 时策略保持 OFF、零 parity、零重建；5%/20% 时闭环把策略
  推入 ON、k≥1 且重建生效；所有注入段恰好交付一次、零放弃。

结果（10 分钟，`FCP_SOAK_MS=600000 FCP_SOAK_REALTIME=1`）：

```text
SOAK loss=0% sim=600s realtime=1 segs_per_tick=4 ticks=24040 tx=96000/96000 parity=0/0 delivered=96000/96000 rxdel=96000/96000 retx=0/0 recovered=0/0 k=0/0 state=OFF/OFF reports=600 identity=24040 viol=0 corrupt=0/0
SOAK loss=5% sim=600s realtime=1 segs_per_tick=4 ticks=24043 tx=97947/98008 parity=9924/10059 delivered=96000/96000 rxdel=96000/96000 retx=1947/2008 recovered=3059/2907 k=1/2 state=ON/ON reports=600 identity=24043 viol=0 corrupt=0/0
SOAK loss=20% sim=600s realtime=1 segs_per_tick=4 ticks=24053 tx=105280/105451 parity=31467/31519 delivered=96000/96000 rxdel=96000/96000 retx=9280/9451 recovered=11659/11858 k=3/3 state=ON/ON reports=600 identity=24053 viol=0 corrupt=0/0
PASS
```

- 该结果在 §9 的 10 处对抗性修复之后重新跑出（修复前的旧 soak 作废）；
- 三通道双向 `tx` 与 `delivered` 完全相等（96000/96000），`viol=0`、`corrupt=0/0`；
- 0% 通道全程 `k=0`、`state=OFF/OFF`、`parity=0`、`recovered=0`，策略无抖动；
- 5%/20% 通道 `state=ON/ON`、`k≥1`、`recovered>0`，且 `rxdel == tx` 说明重传兜底未产生重复交付。

---

## 7. M1 验收线核对（`FCP_M1_TASKS.md` §4）

| # | 验收线 | 状态 | 证据 |
|---|---|---|---|
| 1 | T1–T23 全部通过，golden 冻结入库 | ✅ | §1、§2、§3 |
| 2 | 20% 丢包下 `data_delivered == 注入总数`（重建 + 重传兜底） | ✅ | `e2e_test` fuzz（1000/1000 恰好一次）、`soak_test` 20% 通道 |
| 3 | 恒等式零违例 | ✅ | `settle_test` `TestIdentityFuzz`、`e2e_test` 逐 tick、`soak_test` 双端逐 tick |
| 4 | 覆盖率达门禁 | ⏳ CI | `scripts/coverage.sh`（本机无插桩工具链，见 §5） |
| 5 | 附录 C 21 条逐条核验归档 | ✅ | §4 |

---

## 8. 已知限制与后续

- 覆盖率数字必须在 CI（Linux gcc/clang）产生；本地 Windows 不会产出覆盖率数字。
- `soak_test` 在 ctest 中默认跑 8 秒模拟时长（快速模式）；10 分钟验收需显式设置
  `FCP_SOAK_MS=600000 FCP_SOAK_REALTIME=1`。
- 本记录只覆盖 M1 范围；`deadline` 统计（M2）、字节预算（M3）、KCP 行为改动（M4）不在内。

---

## 9. 对抗性审查记录（10 轮，2026-10-29）

每轮以"攻击者/异常网络能构造什么状态"为出发点审查实现，10 轮共确认 **9 处代码问题**
并全部修复，另补 8 个回归用例；修复后 Debug/Release 19/19 与 §6 的 10 分钟 soak 全部通过。

| # | 轮次审查面 | 问题（攻击面） | 修复 | 回归用例 |
|---|---|---|---|---|
| 1 | 密码学边界 | 接收侧接受 `nonce_ctr ≥ 2^48`：越过 nonce 上限仍在解密，密钥复用风险被静默吞掉 | `envelope.cc open()` 在认证通过后拒收越界 nonce | `envelope_test` `TestRecvNonceLimit`（2^48−1 接受 / 2^48 拒绝） |
| 2 | 缓冲放大 | 认证通过的超大报文会抬高集合 `symbol_max`，解码缓冲按 `(n+k)×symbol_max×集合数` 放大 | `session.cc:91` 在进 RX 前按 `kFecHdrLen + symbol_max` 拒收并计 `pre_struct_fail` | `session_test` 现有长包路径 + soak `corrupt=0/0` |
| 3 | 窗口锚点 | 畸形 symbol 也推进锚点、凭空建集合：伪造远未来 `set_id` 即可把合法流打成 stale | `frame_rx.cc` 先校验（头/长度前缀/parity n 一致性）再提交锚点与占位符 | `frame_rx_test` `TestMalformedDoesNotMoveAnchor` |
| 4 | OOB 契约 | OOB 回调携带 tx 端 `set_id`，上层可能误当集合标识 | `session.cc` OOB 回调固定 `set_id = 0`（§4.7） | `session_test` 既有 OOB 用例 |
| 5 | 上报完整性 | FECSTAT `data_bytes_rx`/`parity_bytes_rx` 恒为 0（字段未接线） | `session.cc on_wire` 按认证后类型累加 wire 字节（含头与 tag） | `session_test` `TestFullLoop`（52B 对齐、`parity_bytes_rx==0`） |
| 6 | 参数协商 | `p_max`/`pinned_k` 只受 3 位上限约束，可超过协商 P′，对端把 parity index≥S 判 struct_fail 并计入计数污染 | 以 `np.p` 夹紧 `p_max` 与 `pinned_k` | `session_test` `TestPinnedKClampedToNegotiatedP`、`strategy_test` `TestPinned` |
| 7 | 配置校验 | 非法本地 D/P（d=0、d+p>256）可构造除零/越界配置 | `local_caps_valid` + `start()` 拒绝 + `frame_tx.cc close_set` 的 `d_==0` 护栏 | `session_test` `TestInvalidLocalCaps` |
| 8 | 握手自锁 | KCP 输出的 HELLO/ACK 若进协商前 data 缓存，握手消息被扣住 → 双方永不成帧 | `on_kcp_output` 对 HELLO/ACK 前缀直接走 control 旁路（#25 后该旁路随内容分类一并删除：握手层直接以 oob 发送，凡 KCP 输出一律按 data 处理） | `session_test` `TestHandshakeRidesOob` |
| 9 | 计数一致性 | 尾丢集合的已收 data 计入 wire 字节但不计入 `data_rx_orig`，按 `52×data_rx_orig` 的假设会失真（审查中确认这是规格行为而非缺陷，记录以防误改） | 不改实现；用例改为 mod-52 + `sets_tail_dropped==1` + 区间约束 | `session_test` `TestFullLoop` |
| 10 | 回归矩阵 | 上述 8 条路径此前无固定断言，修复易被回退 | 新增/扩展 8 个用例 | 全量 `ctest`：Debug 19/19（1.28 s）、Release 19/19（0.37 s），CHECK 1047→1103 |

---

## 10. 对抗性审查记录（第二轮 10 轮，2026-10-30）

以"攻击者 / 异常网络 / 恶意对端（已认证）/ 边界几何 / 长期运行"为攻击面再做 10 轮，
探针固化为 `tests/adv_test.cc`（每轮一个 `ProbeR*` 函数，316 条 CHECK，`ADV_ONLY` 环境变量可单跑一轮）。
本轮确认 **5 处代码问题并全部修复**；R1–R3（AES/GCM/GHASH/信封/头部校验/RS-柯西）与
R7/R8（FECSTAT 节奏与单调键、k_for 反解表、OFF/ON 状态机）未发现库缺陷。

| # | 轮次 | 问题（攻击面） | 修复 | 回归用例（`fcp_adv_test`） |
|---|---|---|---|---|
| F1 | R4 | `FrameRx` 内嵌 64 KiB 的 `SnDedup::slots_`，按值放进栈对象（测试夹具）时函数入口一次性预留 ~800 KiB，Debug 下静默爆 1 MiB 默认栈——对库使用者是隐形脚枪 | `SnDedup` 槽表改为堆分配（`unique_ptr<std::array<...>>`），`FrameRx` 恢复小对象 | R4 全部 12 例在 Debug/Release 一致通过 |
| F2 | R4/R10 | 提不出 KCP sn 的短 payload（<16B）全部折进 `sn=0` 去重槽：第一个短段交付后，**后续所有短段被当重复吞掉**（协议上 control/keepalive 类短帧真实存在） | `SnFn` 契约改为 `bool(payload,len,sn*)`：提不出 sn 的 payload 跳过去重；`kcp_sn_of` 同步改 | R4.7（3 个不同短段全部交付）；`frame_rx_test`/`settle_test`/`reporter_test` 适配新签名 |
| F3 | R4 | 集合表满且**全部处于墓碑态**时 `get_or_create` 找不到可淘汰者仍继续 emplace：认证对端在两次 settle tick 之间可把 map 撑过 `kMaxActiveSets`（内存放大） | 无未结算集合可淘汰时改淘汰最老墓碑，容量硬上限恢复 | R4.10（300 个 set 后 `active_sets ≤ 256`） |
| F4 | R4/R7/R8 | 全部 u32 `set_id` 比较用普通整数序，**未实现 §14.5 半窗判据**：u32 回绕（50 天量级）后锚点不再前进、合法流被判 stale、FECSTAT 全部被拒、策略冻死 | 新增 `fcp::set_id_after(a,b)`（模半窗），接入 `frame_rx`（锚点推进/占位符/stale 判定）、`settle`（eligible、accounted_through）、`fecstat` 单调键、`strategy` 单调键；`create_placeholders` 支持跨回绕区间 | R4.6（0xFFFFFFF0 → 2 的回绕流正常收付）；R7.2/R8.4（单调键回绕接受/拒绝矩阵） |
| F5 | R10 | `k=0` 尾组（`tail_dropped`）的数据**已交付但永不进 `data_expected`**，规格 §7.1 的 `data_delivered ≤ rx_orig+rec+late` 校验恒等式被打破（`delivered_le_sum()` 可长期为假） | `SettleCounters` 新增本地诊断字段 `tail_delivered`（不占 128B 线格式），尾丢时累计该组已交付数，`delivered_le_sum()` 把它加回 | R10.3（尾组存在时恒等式成立；soak/identity 不变） |

另有 3 条**记录在案、不改实现**的边界结论（探针内注释固化）：

1. 共享 `(key,salt,direction)` 的"rogue 对端"与真实端在密码学上不可区分，可烧掉对方 nonce
   空间或污染 sn 去重槽——这是共享凭据场景的固有属性，不是协议缺陷（R10.2 以显式计数器绕开构造）。
2. 幽灵 parity 使可用冗余降为 `k_eff`，`丢失数 > k_eff` 时解码必然失败（R3 的"物理不可能"用例现在按
   `丢失数 > 可用 parity 行数 ⇒ 拒绝` 断言）。
3. `SnDedup` 槽 4096：sn 相差 4096 的两份数据共享槽位，4096 sn 之外的迟到重传会被当新包再交付
   ——KCP 重传间距远小于 4096，属可接受近似（时间戳字段保留未用）。

修复后全量回归：**Debug 20/20（1.7 s）/ Release 20/20（0.5 s）**，10 分钟 soak 三档丢包不变（viol=0）。

---

## 11. 文档审查后记（2026-10-30）

- 同日的文档审查产出规格附录 C #22 与设计附录 A #9–#11：`lost` 口径（统一为
  `expect − rx − rec − late`，与 `session.cc` 现实现一致）、§12.1 RS 接口（计划值 k）、
  慢链路 FEC 下限、例题数字等已在规格/设计中同步修正；本文件 §1–§10 无需改动。
- ~~对实现提出一项待落地改动（任务清单阶段 D D1）：成帧层 control 判定从"前缀命中 + len≥16"
  （`handshake.cc is_hello_prefix`）收紧为"与握手层在途 HELLO/ACK 登记整段字节相等"~~
  —— 该方案已随 #25 作废：原判定可被以 `FCP_HELLO_V3` 开头的用户段撞上（静默吞段、KCP 永不
  收到、重传继续命中，最终 dead_link）。#25 改为握手报文走 oob，内容分类与在途登记整体删除
  （见末条）。
- 慢链路 FEC 开启下限（~4.3 包/s）已澄清并列入规格 §14.8（任务 D3，M2/M3 可选）。
- 同日的对抗分析（规格附录 C #23、设计附录 A #12）：HELLO/ACK 注销统一为"KCP 确认或
  `max(3×srtt,2s)` 兜底"（该口径随 #25 一并作废——握手改由自身 3×300ms 定时器重传）；
  §7.1 校验项补 `tail_delivered` 尾丢豁免（本文 §10 F5 的规格落点）；§4.1 重放窗口（实现已有
  64 槽滑动窗口，此前规格未定义）等其余各项为规格与现有实现对齐，无新增代码工作。
- 同日的设计合理性复查与分叉裁定（规格 #24/#25）：#24 salt 职责更正、方向密钥列入 §14.9；
  **#25 control 通道改走 oob（type=2）**，D1 重定义为"握手通道 oob 化"。本文 §9 #8 的
  control 旁路 hack 与 #22①/#23① 的内容分类/登记机制随 #25 作废。
- **D1 已落地（2026-10-30）**：HELLO/ACK 以 type=2 oob、`set_id=index=0` 发送（HELLO magic
  补齐 16B，线上 20B；golden 重录为 `TestWireGolden` 的 20/20）；`type=3` 未定义、收到计
  `struct_fail`；KCP 输出无内容分类（`FCP_HELLO_V3` 前缀用户段按 data 正常进集合）；握手层自管
  3×300ms、Established 即停；协商前超 MTU 报文在进缓存前拒收。T23 双侧覆盖全绿
  （`TestHandshakeRidesOob` / `TestHandshakeAckRidesOob` / `TestKcpOutputIsAlwaysData` /
  `TestInvalidTypeAndOobBypass`）。
- 同轮补齐规格 §8 漏项：连续 3 个本地报告周期（按 2s/60s 估计）无 FECSTAT → 保持 `k` 并
  WARNING 一次（`session.cc` 看门狗，`TestMissingFecstatWarning`）；并按 §10 暴露
  `Session::fecstat_rx()` / `last_pre_ppm()` / `last_usable_ppm()`，供宿主拼装 `stats ...` 后缀
  （`fec_mode`/`fec_k` 复用 `mode()`/`k()`，丢弃与失败计数复用既有访问器）。

---

## 12. #26/#27/#28 网络专家评审与协议评审落地状态（2026-10-30）

> 规格 `FCP_PROTOCOL_V6.md` 附录 C #26（网络专家审查，4 项）与 #27（网络协议评审，1 项机制
> 变更 + 3 项边界入档）相对本验收记录 §1–§11 的增量。#26 的实现/测试证据见
> `FCP_M1_TASKS.md` 阶段记录（2026-10-30 #26 落地行）。

| 项 | 内容 | 状态 | 证据 |
|---|---|---|---|
| #26① | GCM 块预算终止线 2^48 → 2^32 包/方向（收发两侧拒收） | ✅ | `envelope.h kNonceLimit`；`envelope_test TestNonceLimit/TestRecvNonceLimit`；`adv_test` R1.5/R1.6 |
| #26② | 方向密钥 M1 强制（SP 800-108 KDF，label `fcp-c2`/`fcp-s2`） | ✅ | `envelope.cc derive_direction_keys` + `Session` 接线；`envelope_test TestDirectionKeyIsolation`（派生确定性、跨方向验签必败） |
| #26③ | 重放窗口 64 → 256 槽/方向 | ✅ | `envelope.h kReplayWindow`；`adv_test` R1.4（255 收 / 256 拒边界） |
| #26④ | `--fec-parity-max` 允许 5..7 | ✅ | `strategy.h kMaxParity=7` + `FecStrategyConfig.p_max`（配置项，库内钳到协商 P'） |
| T24/T25 | 对应新测试 | ✅ | 上表 ①–③ 的测试列；任务清单 §3 映射表已补 |
| #27① | 握手重传固定 300ms → 指数退避 300/600/1200ms（总等待 900ms → ~2.1s） | ✅ E1 | `handshake.cc on_tick`（`300 << (retries−1)`）；T26 = `handshake_test TestRetryBackoff`（退避序列/任意阶段 ACK 即停/RTT=500ms 仿真成功/重复 HELLO 仍重发 ACK）+ `TestTimeout`/R9.4/session `TestHandshakeTimeout` 时序同步；Debug/Release 20/20 |
| #27② | `k_for` i.i.d. 假设（§14.10）、拥塞冗余正反馈（§14.11）、无 PMTU 发现（§14.12） | ✅ E2（burst 实测）/ 边界入档 | 三项为已知边界入档，不改机制；burst 实测 = `e2e_test TestBurstLossRepairRate`（确定性 5 连丢/25 包、k=4）：实测单组修复率 **60.0% vs 二项 87.0%**（-27pp，命中组 5 连丢 > k 全部不可修、ARQ 兜底 1000/1000 恰好一次、恒等式零违例） |
| #28① | **P0：会话密钥按会话派生 `session_key = AES128(PSK, salt‖0×8)`**（§6.0 新增；规格原文"salt 是 KDF 熵源"与实现不符——salt 未参与任何派生，同一 PSK 的两会话密钥相同、IV 从 0 重叠 → GCM 跨会话 (key, IV) 重用） | ✅ F1 | `envelope.h/cc` 新增 `derive_session_key`（AES128(PSK, salt‖0×8)），构造函数先派生 session_key 再派生方向密钥；T27 = `envelope_test TestSessionKeyDerivation`（salt 隔离/确定性/PSK 隔离/旧方案报文拒收）+ `TestRecvNonceLimit` 同步为派生密钥；全量 Debug/Release 20/20 |
| #28② | 重放窗口 256 槽覆盖数字勘误：实际 ≈13–19 Mbps × 200ms（#26④ 原"25 Mbps"算错） | ✅ 文档勘误 | §4.1/设计 §4.1 已更正；20–25 Mbps × 200ms 区间自激未消除，自适应窗口对高吞吐部署应前置（M2） |
| #28③ | 握手缓存溢出×退避交互（§14.13） | ✅ F2 | 缓存默认 **512 段/512KB**（原 64/64KB）+ `SessionConfig.handshake_cache_*` 可配置，超限仍响亮失败；泵级反压需宿主配合，M2 宿主侧跟进 |
| #28④ | late_guard/墓碑上限口径（§14.14） | 边界入档 | 方向安全（高估丢包 → 偏保守），M2 标定 |
| #28⑤ | FECSTAT 无重传（§14.15） | ✅ F3 | 每报告连发两份（`reporter.cc`）；校验器 `kDuplicate` + `fecstat_dup` 计数，stale/dropped 口径不变 |
| #28⑥ | 短连接自适应盲区（§14.16） | 边界入档 | 短连接密集部署用 `--fec-parity-pinned`，跨连接继承留 M3 |

- 本表落定前，§7 验收线第 1 条口径由"T1–T23"扩展为"T1–T27"（T24/T25 随 #26、T26 随 E1、T27 随 F1 均已绿）；
- #27② 三项不改变任何已归档的回归结果（§1–§11 全部有效）。

---

## 13. 第三轮实现审查修复（2026-10-30）

| # | 问题（攻击面/失效域） | 修复 | 回归用例 |
|---|---|---|---|
| 1 | **协商前入站 data 反射**：`Session::on_wire` 把对端 data 段写入握手缓存，而该缓存只服务本端 KCP 输出的补发；`configure()` 时 `take_cached_data()` 将其回灌 `FrameTx`，对端业务段被当作本端数据重发（parity 则静默丢弃） | 按 §6.2"协商完成前只允许 oob 上线"直接丢弃入站 data/parity；握手缓存保持"仅出站 KCP 段"语义（T21 不变） | `session_test TestPreNegotiationInboundDropped`；`TestPreNegotiationMtuReject` 同步 |
| 2 | **§8 排队护栏基线错误**：`min_srtt_ms_` 固定初值 200ms，RTT > 240ms 链路上 `srtt − min_rtt ≥ 40ms` 恒真 → k 永久压到 1、FEC 在卫星/跨洲链路上失效 | `min_srtt_ms_` 以首个 `on_rtt_sample` 样本为基线（此后取更小值），无样本时护栏不生效 | `session_test TestQueuedGuardrailUsesObservedMinRtt` |

修复后全量回归：Debug 20/20、Release 20/20。

---

## 14. 第四轮对抗分析修复（2026-10-30）

按模块分 10 轮（头部/MTU、帧接收、RS、密码学、握手、结算、策略、报告、会话集成、跨模块收尾）对实现做定向攻击。第 1/3/4/5/7/8/10 轮未发现缺陷；确认并修复以下 3 项。

| # | 轮次 | 问题（攻击面/失效域） | 修复 | 回归用例 |
|---|---|---|---|---|
| C2 | 2 | **墓碑释放后迟到分片重算**：`release_set` 只删集合，槽位释放后任意迟到 data/parity 都能 `get_or_create` 重建状态；此时 anchor 已在前方，集合立即满足"被更高 set 超越"的 Eligible 条件，于 late_guard 后二次结算——重复计入 `sets_expected`/`data_expected`/`data_rx_orig`/`parity_rx`，并污染对端 FECSTAT 丢包率与策略 | `FrameRx` 维护有界 `retired_` 集合（已结算并释放的 set_id），入口在锚点更新前丢弃命中分片并计 `retired_dropped()`；仅保留半窗（256 id）内的 id，`prune_retired()` 随锚点推进回收。容量淘汰已结算集合时同样登记 | `settle_test TestNoReaccountAfterRelease`（迟到 data+parity 均被拒、不重建、不二次结算；尾丢集合仍可按 #23⑨ 重建） |
| C4 | 6 | **容量淘汰未告知结算**：`get_or_create` 在 256 组上限下淘汰最老未结算集合时只 `erase`，`FcpSettle` 不知道这次丢弃——该组已交付的 data 沉没、`sets_tail_dropped`/`tail_delivered` 少计，`delivered_le_sum()` 恒等式可能被打破 | 新增 `RxEvent::kSetTailDropped`（value=已交付符号数），淘汰未结算组时发出；settle 计入 `sets_tail_dropped` 与 `tail_delivered`；已结算组被淘汰时登记 `retired_` 而非重复记账 | `settle_test TestCapacityEvictionAccounting`（256 组满窗、淘汰结算墓碑不重算、淘汰未结算组计尾丢、恒等式成立） |
| C3 | 9 | **MTU 下界未覆盖 FECSTAT oob**：`start()` 只按数据/parity 几何校验 MTU（下界 89），而 128B 的 FECSTAT 以 oob 发送（线上 6+128+28+ip+8）：IPv4 需 ≥190、IPv6 需 ≥210。低于该值时本端报告恒发不出去（出站越界）或对端认证后按超 MTU 拒收，违反 T2 双向可达 | `Session::start()`/`ensure_configured()` 增加"MTU 必须容纳最大 oob"校验，非法配置响亮失败并保持 Idle（`FCP config invalid: MTU too small for a 128-byte FECSTAT oob`）；`compute_mtu_limits` 的 89 数据下界不变 | `session_test TestMtuMustCarryOob`（IPv4 189 拒/190 收，IPv6 209 拒/210 收） |

修复后全量回归：Debug 20/20、Release 20/20（20 个 ctest 目标，含上述 3 个新用例）。

---

## 15. Linux 编译与回归（2026-10-30）

环境：Ubuntu 24.04.5 LTS，g++ 13.3.0，CMake 3.28.3，Ninja 1.11.1（2 核 / 1GB 远程机）。

| 配置 | 命令 | 结果 |
|---|---|---|
| Debug | `cmake --preset linux-x64 && cmake --build --preset linux-x64-debug && ctest --preset linux-x64-debug` | 20/20 通过，零告警 |
| Release | `cmake -S . -B build/linux-x64-release -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build … && ctest --test-dir …` | 20/20 通过，零告警 |

GCC（`-Wall -Wextra -Wpedantic`）额外暴露 2 个仅 Linux 可见的测试问题，均已修复：

| # | 问题 | 修复 | 验证 |
|---|---|---|---|
| 1 | `TestRecvNonceLimit` 定义后从未注册进 `main()`——接收侧 nonce 上限（T24 改造）的回归在 Windows 上同样未执行，只是 MSVC 不报未使用函数 | `envelope_test.cc` 的 `main()` 增加调用 | 注册后在 Linux Debug/Release 通过 |
| 2 | `TestGoldenLayout` 用 `memcpy(expected, "FCP_FECSTAT_V6", 16)` 从 15 字节字面量越界读 1 字节（golden 第 16 字节实际依赖 `expected` 的零初始化） | 拷贝长度改为 15，剩余字节保持零初始化 | `fecstat_test` golden 128 字节逐字节一致 |

修复后复跑 Windows Debug/Release 仍 20/20；Linux 与 Windows 四套产物共 80 个测试实例全绿。

## 16. 真实网络吞吐基准（`tools/fcp_bench.cc`，2026-10-30）

新增独立基准工具 `tools/fcp_bench.cc`（不入库为测试目标，手动构建）：`--role server|client`、`--port`、`--mbps`、`--seg`（默认 1200）、`--mtu 1400`、`--pinned-k`（关闭策略）、`--progress`。客户端在自身握手完成后 1s 起以令牌桶按目标速率发送 7s；服务端不信任自身握手时钟，由**线上到达**的 data 尺寸报文（36+seg 字节）建立时间轴：首包、静默 500ms 判上传结束，再等 1s 发送 7s 下行。两端各打印一行 `RESULT`（含 wire 段数、丢包/陈旧/去重/尾丢、settle 期望与交付、k 等）。为避免 V3 三次 HELLO（总预算 2.1s）在 WAN 上被进程启动抖动击穿，两端先做 8 字节 `FCPBENCH` 魔法会合（15s 超时，exit 4）。

环境：服务端 Ubuntu 24.04（2 vCPU Sierra Forest，AES-NI，OpenSSL GCM ~2GB/s）；客户端本机 Windows（电信 119.97.231.26）。UDP/40000，payload 1200B，MTU 1400，统计窗口 7s。端到端建链 57–156ms。**同机回环**上限：Windows 双向各 48.4 Mbps；VPS 单线程 Session 在 >30 Mbps 饱和（吞吐天花板是单线程会话循环，不是密码学）。

| 方向 | 目标 Mbps | 实测 Mbps | 交付率 | 备注 |
|---|---|---|---|---|
| 上行 client→server | 10 / 15 / 20 / 30 / 40 | 9.68 / 14.51 / 19.37 / 29.00 / 37.69 | ≈100%（wire 计数与发送一致） | 40 时 `tx_fail=1806`（本机 UDP 发送缓冲溢出），上行链路本身干净 |
| 下行 k=0（固定） | 10 / 15 / 20 / 30 | 8.14 / 12.98 / 16.47 / 22.46 | 84% / 89% / 85% / 80.8% | 纯路径丢包，无修复 |
| 下行自适应 | 10 / 20 / 30 / 40 | 9.15 / 18.50 / 22.61 / 9.55 | 94.3% / 95.5% / 95.7% / —（饱和） | k=2/2/3/—；30 重复一次仍 22.61 |

交叉验证：python→node 原始 UDP（10 Mbps、无 FCP）服务端发出 5054 报，本机收到 4275（84.6%），即**服务端→本机方向路径固有丢包 ≈15%**，与 k=0 下行一致；客户端→服务端方向不丢。自适应 FEC 在该丢包率下把下行有效吞吐提高约 10 个百分点（20 Mbps 档 16.47→18.50，+12%），代价是 k=2–3 的 parity 开销；超过 ~30 Mbps 后瓶颈转为 VPS 单线程会话，继续加目标速率只会让 40 Mbps 档回落到 9.55。

部署发现：该云商在入方向拦截 UDP/53 与 UDP/443（报文到达网卡但不进 socket，iptables/nftables/rp_filter 均正常），UDP/40000 直通，基准因此使用 40000。Windows Debug/Release 与 Linux Debug/Release 四套 ctest 均 20/20（本工具仅改 `tools/fcp_bench.cc`，未触碰 `src/fcp/`）。

对抗审查后（2026-10-31，A2/A10/A20/P8-3/P8-5）：会合改为客户端发 16B（`FCPBENCH` + 8B 随机 salt）、服务端回 8B 魔法并采用该 salt，双方以同一 salt 建会话（原写死 salt 会导致跨轮 GCM (key,IV) 重用）；新增 `--key=HEX32`；`--seg` 限 16..1200、`--port/--mbps` 等数值全串解析并拒绝越界；RESULT 吞吐只计 `send()` 成功的报文。**新旧版本会合格式不兼容，不能混跑**。上表为改动前的历史数据。

---

## 17. Qt 桌面客户端（`apps/fcp-client`，2026-10-30）

范围：**连接与测速控制台**——复用 §16 的 `fcp_bench` 服务端协议，把命令行基准变成可视化的一次测速（上行/下行速率、实时曲线、握手与结算指标）。SOCKS5/隧道转发的 GUI 需要 KCP 栈与隧道服务端，本仓库尚无，列入 M2。

技术选型（用户确认）：Qt Widgets + QSS（vcpkg `x64-windows` 的 Qt 6.11.2，只用 Widgets/Network，无 Quick）；工程位置 `apps/fcp-client`；构建入口 `build_app.bat`（`cmake --preset windows-x64-app` + `--target fcp_client` + `windeployqt`）。库构建不受影响：`FCP_BUILD_APP` 默认 `OFF`，`src/fcp/` 一行未改。

| 文件 | 职责 |
|---|---|
| [apps/fcp-client/bench_engine.h](../apps/fcp-client/bench_engine.h) / [.cc](../apps/fcp-client/bench_engine.cpp) | 测速引擎：`FCPBENCH` 会合 → 握手 → 1–8s 上行令牌桶 → 检测下行 → 18s 收尾。GUI 线程单线程 5ms 定时器驱动 `QUdpSocket`（connected）+ `fcp::Session`，Stats 以 10Hz 上报 |
| [apps/fcp-client/main_window.h](../apps/fcp-client/main_window.h) / [.cpp](../apps/fcp-client/main_window.cpp) | 无边框主窗 + 自绘标题栏，三视图（概览 / 连接设置 / 运行日志），`QSettings` 持久化，`--host/--port/--mbps/--autostart` 覆盖参数 |
| [apps/fcp-client/sparkline.h](../apps/fcp-client/sparkline.h) / [.cpp](../apps/fcp-client/sparkline.cpp) | 120 点环形缓冲速率曲线（下载/上传各一条） |
| [apps/fcp-client/theme.qss](../apps/fcp-client/theme.qss) | 纸感墨白主题（参照 Electron 版配色），状态点用动态属性 `[tone=…]` 切换 |

两处与库互操作的关键决定：① `fcp::FrameTx::emit()` 与 Qt 的 `emit` 宏冲突，整个 target 编译期定义 `QT_NO_KEYWORDS`（改用 `Q_SIGNALS`/`Q_EMIT`/`Q_SLOTS`）；② 交付率口径——`FcpSettle::counters()` 是**每个 FECSTAT 区间**清零的，且 `data_delivered` 在符号到达时计数、`data_expected` 在集合结算时才计数，跨区间累加会让收尾处的尾部集合把比值顶到 101.2%。改为按测速流自身计数：服务端下行 `sn` 从 1 连续编号，客户端统计**校验通过的分段数 / 观测到的最大 `sn`**，回环实测恰好 100.0%。另外把仍在路上的 8 字节会合魔法包在进 `Session::on_wire` 前滤掉，不再虚报 `auth_fail`（`fcp_bench` 命令行版按原样计入并在 RESULT 里说明）。

联调验证（本机回环，服务端 `fcp_bench server --port=40007`，20 Mbps / seg 1200 / 自适应 FEC）：

| 指标 | 客户端显示 | 服务端 RESULT |
|---|---|---|
| 上行 / 下行 | 19.39 / 19.39 Mbps | 19.389 / 19.387 Mbps |
| 交付率 | 100.0 % | `down_tx_segs=14136`；客户端侧"校验通过段数 = 最大 `sn`"，无缺段 |
| 握手 | 140 ms（含会合等待） | `handshake_ms=16` |
| 授权 / 结构失败 | 0 / 0，结算一致 ✓ | `auth_fail=0 struct_fail=0 identity_ok=1` |
| 峰值 / 累计 | 下载 21.31 Mbps、上传 19.49 Mbps，各 16.2 MB | `up_bytes=16965600 down_bytes=16963200` |

构建与回归：`build_app.bat release` 与 `build_app.bat debug` 均通过并部署 Qt 运行时（exe 可独立启动）；库侧 Windows Debug/Release ctest 仍 20/20。界面按 1325×900 截图核对过三视图、实时曲线与结果卡（截图脚本为一次性验证工具，未入库）。未覆盖项：高 DPI/多显示器缩放、真实 WAN 下的 GUI 长稳、异常断线的重连策略（当前只报"会合超时/握手失败"，不自动重试）。

## 18. M2 代理引擎与 CLI 双端（`apps/fcp-proxy`，2026-10-30）

### 18.1 构建与门禁

| 配置 | 命令 | 结果 |
|---|---|---|
| Windows Debug | `build.bat Debug` | ctest **25/25**，2.33 s |
| Windows Release | `build.bat Release` | ctest **25/25**，0.57 s |
| CLI（独立构建目录） | `build/proxy-check` + `-DFCP_BUILD_PROXY=ON` | `fcp-proxy-client.exe` / `fcp-proxy-server.exe` 均通过 |

`FCP_BUILD_PROXY` 在 preset 里仍默认 OFF；`apps/fcp-proxy` 现在由
`FCP_BUILD_PROXY OR FCP_BUILD_APP OR FCP_BUILD_TESTS` 决定是否配置，这样
`fcp_proxy_core`（引擎，无 socket）与 `proxy_engine_test` 恒进门禁，而反应堆与两个
`main_*` 只在显式开 CLI 时编。

### 18.2 `tests/proxy_engine_test.cc`（T31b，9 场景）

双端各一个 `ProxyEngine`、中间内存管道对拷 datagram、25 ms/tick 虚拟时钟，逐场景断言：

| 场景 | 钉住的不变式 |
|---|---|
| `socks5_round_trip` | 问候回 `05 00`；IPv4 目标以**裸 4 字节**进 OPEN；隧道字节双向一致；请求后多余的 10 B 一个不吃 |
| `http_connect_round_trip` | `CONNECT host:port` → `HTTP/1.1 200 `；authority 落成 `kAtypDomain` |
| `open_error_maps_to_the_local_reply` | 5 组 `OpenError → SOCKS rep`（0x05/0x04/0x06/0x08/0x02）与 HTTP 侧 502；**一条隧道只拒一次**（迟到的 `on_dial_result(ok)` 不改写已发的 `open_failed`） |
| `malformed_local_requests` | 无共同方法 `05 FF`、UDP ASSOCIATE→`0x07`、 bogus ATYP→`0x08`、非 CONNECT 方法→405、缺端口→400 |
| `backpressure_closes_the_window` | 目标侧拒收 >60/120 轮；总推入量 `≤ rcv_buf + 2×send_window`；解除限制后逐字节有序全量交付 |
| `salt_routing_and_replay_binding` | 同 salt 换源地址 → `salt_clash=1` 且立刻关；2 字节短 stub → `unknown_salt=1`，不建会话 |
| `short_connections_leave_no_state_behind` | 20 条短连接后双端 `live=0`、`established=20`、预热缓存各 1 条 |
| `dial_timeout_and_grace_clock` | 无应答拨号 → `0x06` + 服务端理由"the peer stopped acknowledging"；应用 socket 卡死 → "the application socket stopped taking bytes" |
| `session_limits` | `max_sessions=2`：客户端第 3 条本地连接 `over_limit=1` 且由宿主直接关（不排队）；服务端第 3 个入站 HELLO 根本不建会话（`live=2`），客户端只能等满握手超时——服务端丢了这笔生意而非用协议报文拒绝，这是诚实的结果 |

### 18.3 由引擎测试逼出的两个真实缺陷

两处都**过了 CLI 回环联调**（活着的会话总会确认一次，队列还没无限堆积就结了尾），是
socket-free 驱动把它们逼出来的：

1. **`Stream::send_space()` 计量口径错**（`src/fcp/stream.cc`）：原按
   `in_flight_ + tx_pending_`。`pump()` 把待发字节切成段是无条件的，被对端窗口挡住的那批
   段既不在 `in_flight_` 也不在 `tx_pending_`，写侧因此一直被通知"还有空间"。缺陷表现：
   `backpressure_closes_the_window` 报 `pushed=409600 refused=0 pending=21810`（发送队列
   无上限堆积）。改为 `bytes_queued_ - bytes_acked_`（"已写未确认"）后，每连接每侧内存
   上界回到 `send_window_bytes + rcv_buf_bytes`。同一个缺陷还让 Debug 全量回归跑到
   136 s（发送侧不看窗口的循环在虚拟时钟里要 tick 成千上万次；配合把测试自身的
   32 轮/400 步预算收紧到 8 轮，`proxy_engine_test` 单例降到 ~60 ms），门禁总时长随之
   落到 2.4 s。
   回归守卫：`tests/stream_test.cc` 新增 `TestStalledReaderBoundsTheSendQueue`（读者只
   `set_delivery_pending` 不放行 → 积压恒 `≤ window` 且 `write()` 最终开始返 0；解除后
   全量按序交付）。
2. **`ProxyEngine::on_tick` 的 grace 截止读不到**（`apps/fcp-proxy/engine.cc:248`）：
   `kDialing && now >= dial_deadline` 分支在会话已被判死（`closing`）后仍每 tick 赢下
   `else if`，于是 `flush_deadline_ms` 永不被读，服务端 `live` 卡在 1 直到 idle 超时。
   加 `!closing` 守卫，`dial_timeout_and_grace_clock` 的 `live` 断言随即转绿。

### 18.4 回环端到端（T32 的本地半边，`build/proxy-live/suite.sh`，git 忽略）

| # | 检查 | 结果 |
|---|---|---|
| 1 | `curl --socks5` 普通 GET（IP 目标） | `code=200` |
| 2 | `/big` 5400 B 直连 vs 代理 | `cmp` **逐字节一致**（`big.proxy` 5400 B） |
| 3 | `/huge` 2 MiB 直连 vs 代理 | `cmp` **逐字节一致**（2097152 B），`t=0.366 s` — 即 18.3① 改口的关键回归风险点 |
| 4 | `/slow` 分块流（41 chunk） | `chunks=41`、318 B 完整 |
| 5 | `--proxy http://` CONNECT + TLS | `code=200`、577 B |
| 6 | 目标拒绝（closed 端口） | `curl exit=97`（SOCKS5 无法建到目标），`t=2.087 s` |
| 7 | 20 串行 + 10 并发 | 串行失败 0、并发 `ok=10/10` |

服务端收尾统计：`stats 12.0s live=0 up=36 tunnels=35 tx=2195686B rx=100472B
bad_entry=0 refused=1 hs_failed=0 reset=0 idle=0 clash=0 over=0 unknown=0`——会话表零泄漏、
零 salt 冲突、零越限，`tunnels=35` 与 `refused=1` 恰与第 6 项对上。

### 18.5 Windows 被拒 connect 的 2.05 s 是 OS 行为（实测，非缺陷）

第 6 项的 2.087 s 拆了三条独立路径实测（回环打向 closed 端口）：

| 路径 | 观测 |
|---|---|
| 非阻塞 `connect()` + `select` 异常集 | ~2047 ms |
| `WSAEventSelect(FD_CONNECT)` 等事件 | ~2047 ms |
| **阻塞** `connect()` 直接计时 | ~2047 ms |

三条同值 ⇒ 这 2 s 由 Windows TCP 栈自身决定（Linux 立即返回 `ECONNREFUSED`），代理侧只占
~0.1 s。真正可修且已修的是**通知位置**：Winsock 把失败的 connect 报在 `exceptfds` 而非
`writefds`，漏查会把"目标拒绝"退化成等满 5 s 拨号超时并给出错的 SOCKS 应答码。已入
`docs/FCP_M2_PROXY.md` §7 第 9 条。

### 18.6 未覆盖项

M2 验收线已全部落地：#22（WAN 半边 + T33 预热 A/B + Linux 回归，2026-10-31，见
`FCP_M2_PROXY.md` §8.1）与 #23（GUI 代理页 + Qt 适配器，同日，见 §8.2——顺带修掉
子段窗口死锁与 Qt 关闭排空竞态两个真实缺陷，修复后 WAN 8MiB 由 1.29 提到
8.5–10.6 Mbps）。后续项：快速重传/多洞 SACK（§7 第 2 条，M3）。

---

## 19. R3-1「握手无新鲜性」关闭（v7 密钥编排 + 握手 V4，2026-10-31）

来源：`docs/FCP_ADVERSARIAL_REVIEW.md` 第二轮对抗分析 R3-1（当时唯一未关的 Critical），
与 R3-23（salt 仅 64 位）、R3-24（已建立会话被一个 HELLO 打死）同批处理。

### 19.1 缺陷本质

v6 的 `session_key = AES128(PSK, salt‖0×8)` **只依赖 `(PSK, salt)`**，而 salt 是线上明文字段
（§4.1 的会话查找键）。攻击者录下一条完整握手后重放：

1. 双方按同一 `(PSK, salt)` 派生出**同一把** `session_key`；
2. 反重放窗口是**每会话新建**的（256 槽、`highest=0`），历史密文整段落回窗口内；
3. 结果：历史密文可被重放、被解密（若攻击者还知道任一明文块）、甚至伪造报文注入。

"缩小窗口""加大 salt"类修补全部无效——窗口本来就是新的，salt 也本来就在线上。
唯一出路是让密钥依赖**本次运行新抽的随机量**，因此必须动线格式。

### 19.2 落地内容

| # | 改动 | 位置 |
|---|---|---|
| 1 | `random_bytes` / `random_u32`（Windows `BCryptGenRandom`、POSIX `/dev/urandom`；失败返回 false，不静默降级） | `src/fcp/random.h`、`random.cc`（新增），`CMakeLists.txt` 链接 `bcrypt` |
| 2 | `derive_session_key_v7(psk, salt, c_nonce, s_nonce, out)`：三块定长 CBC-MAC | `envelope.h/.cc` |
| 3 | `Envelope::rekey(session_key)`：装新键并归零 `send_nonce_` / 重放窗口 | `envelope.h/.cc` |
| 4 | 握手 V4 线格式（36/52 字节）、`build_hello` / `build_hello_ack`、`HandshakeRole`、`kBadNonce` | `handshake.h` |
| 5 | 状态机：nonce 抽取与校验、ACK echo 绑定、established 拒新 nonce（R3-24）、零 nonce 拒绝 | `handshake.cc`（重写） |
| 6 | 双 envelope：`hs_env_`（键 = `(PSK,salt)`，只收发 HELLO/ACK，永不 rekey）+ `env_`（`configure()` 时 rekey） | `session.h/.cc` |
| 7 | `on_wire` 两次尝试（先数据后握手），握手命中的只放行 oob 握手载荷；`emit_symbol`/`send_oob` 按 epoch 分流 | `session.cc` |
| 8 | 握手信封发送计数器起点 `random_u32()`（防重放 HELLO 让同一 (key, IV) 封出第二条 ACK） | `session.cc` 构造函数 |
| 9 | `SessionConfig.handshake_nonce[16]`（全零 = 让 CSPRNG 抽）、`handshake_nonce()` / `nonce_mismatch()` 诊断口 | `session.h` |

### 19.3 验证

| 门禁 | 结果 |
|---|---|
| `fcp_envelope_test` | PASS（10 例：v7 黄金向量 + `(0,0)`/交换 nonce 反例 + `rekey` 归零 + CSPRNG 可用性） |
| `fcp_handshake_test` | PASS（17 例：密钥协商一致、echo 不匹配、established 拒新 HELLO、零 nonce、随机性、36/52 golden、v3 不识别） |
| `fcp_session_test` | PASS（16 例：含新增 `TestReplayCannotReviveSession`） |
| `ctest -C Debug` | **27/27 通过**（15.5 s） |
| `ctest -C Release` | **27/27 通过**（3.7 s） |
| `FCP_BUILD_PROXY=ON` 构建 | 通过（`build/proxy-check`，Debug 全目标，无 error） |

**黄金向量**（外部 openssl 独立算出，锁在 `envelope_test.cc::TestV7KeyVector`）：
psk `0f1e…e1f0`、salt `1122334455667788`、c `0001…0e0f`、s `f0e0…1000` →
`X0 = 18e6cda19e4e7799e2f2e18874e4c2d6`、`v7 = 54986bbc5ccc12b8666f56c7a5d6eb8d`、
交换 nonce = `fce3349c24a2ee4b0a0a4c096c1f55af`、双零 nonce = `7363d57e850ce2d2f301b80bae264112`。

**变异验证**（证明重放用例真的在测这件事）：把 `handshake.cc` 的 echo 校验临时改成
`if (false && ...)`，`TestReplayCannotReviveSession` 立刻报 `!a2.established()` 失败；
恢复后复绿。

### 19.4 代价与兼容性

- **v7 与 v6 不互通**，两端必须同时升级（magic V3 → V4 硬断，无降级协商）。
  升级顺序与误混版本的两种症状见 `DEPLOY.md` §1.1。
- **salt 宽度维持 8B**（决策：不加宽到 16B）——KDF 已混入双向 16B nonce，salt 只承担会话查找键，
  加宽只增线上字节、不增实际安全性。
- **PSK 与配网零改动**：密钥材料、端口、MTU、参数全不变，只换二进制。
- 仍无前向保密（PSK 泄露 → 历史全解），与 v6 一致，已作为接受取舍入档（规格 §6.0）。
- 残余：服务端对重放的 HELLO 仍会建立一个"空会话"（它用自己抽的 `s_nonce`，与录制方不同键，
  送不进任何数据），成本等价于伪造 HELLO（需 PSK），由 `max_sessions` + idle 回收承担。
