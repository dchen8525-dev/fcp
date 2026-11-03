// 线框几何上限的单一 home（对抗分析第九轮）。
//
//   kMaxS      —— u8 索引 ⇒ 代码长（D + P）≤ 256。之前拼写于 frame_rx.h。
//   kMaxParity —— 3 位 wire 字段 ⇒ parity ≤ 7。之前拼写于 strategy.h。
//
// rs.h 用 static_assert 把 kRsMaxShards/kRsMaxParity 钉到这两个值上：
// `add one, fix the other` 不能再静默。strategy / hdr 的旧独立上限
// （此前一处=7、一处=7 各自收紧）现在都读这里。

#ifndef FCP_LIMITS_H_
#define FCP_LIMITS_H_

#include <cstddef>

namespace fcp {

constexpr size_t kMaxS = 256;      // index is u8; D + P <= 256
constexpr uint8_t kMaxParity = 7;  // k occupies 3 header bits

}  // namespace fcp

#endif  // FCP_LIMITS_H_
