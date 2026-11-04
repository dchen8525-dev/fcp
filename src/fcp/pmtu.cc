#include "fcp/pmtu.h"

#include <cstring>

#include "fcp/wire.h"

namespace fcp {

bool pmtu_parse(const uint8_t* payload, size_t len, PmtuMessage* out) {
  if (payload == nullptr || out == nullptr || len < kPmtuHeaderLen) {
    return false;
  }
  if (std::memcmp(payload, kPmtuMagic, kPmtuMagicLen) != 0) {
    return false;
  }
  const uint8_t type = payload[8];
  if (type != kPmtuProbe && type != kPmtuAck) {
    return false;
  }
  out->type = type;
  out->token = get_le32(payload + 10);
  out->mtu = get_le16(payload + 14);
  return true;
}

void pmtu_build(const PmtuMessage& msg, uint8_t* out, size_t out_len) {
  if (out == nullptr || out_len < kPmtuHeaderLen) {
    return;
  }
  std::memset(out, 0, out_len);
  std::memcpy(out, kPmtuMagic, kPmtuMagicLen);
  out[8] = msg.type;
  out[9] = 0;
  put_le32(msg.token, out + 10);
  put_le16(msg.mtu, out + 14);
}

}  // namespace fcp
