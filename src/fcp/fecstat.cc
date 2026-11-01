#include "fcp/fecstat.h"

#include <cstring>

#include "fcp/hdr.h"
#include "fcp/wire.h"

namespace fcp {
namespace {

}  // namespace

FecstatPacket MakeFecstatPacket(const uint8_t salt[8]) {
  FecstatPacket packet{};
  std::memcpy(packet.magic, kFecstatMagic, sizeof(packet.magic));
  std::memcpy(packet.session_salt, salt, sizeof(packet.session_salt));
  packet.ver = kFecstatVersion;
  return packet;
}

void encode_fecstat(const FecstatPacket& packet, uint8_t out[kFecstatLen]) {
  std::memset(out, 0, kFecstatLen);
  std::memcpy(out + offsetof(FecstatPacket, magic), packet.magic, sizeof(packet.magic));
  std::memcpy(out + offsetof(FecstatPacket, session_salt), packet.session_salt,
              sizeof(packet.session_salt));
  out[offsetof(FecstatPacket, ver)] = packet.ver;
  out[offsetof(FecstatPacket, flg)] = packet.flg;
  put_le16(packet.interval_ms, out + offsetof(FecstatPacket, interval_ms));
  put_le32(packet.accounted_through_set_id,
           out + offsetof(FecstatPacket, accounted_through_set_id));
  put_le32(packet.sets_expected, out + offsetof(FecstatPacket, sets_expected));
  put_le32(packet.data_expected, out + offsetof(FecstatPacket, data_expected));
  put_le32(packet.data_rx_orig, out + offsetof(FecstatPacket, data_rx_orig));
  put_le32(packet.data_recovered_dl, out + offsetof(FecstatPacket, data_recovered_dl));
  put_le32(packet.data_recovered_late, out + offsetof(FecstatPacket, data_recovered_late));
  put_le32(packet.data_delivered, out + offsetof(FecstatPacket, data_delivered));
  put_le32(packet.parity_rx, out + offsetof(FecstatPacket, parity_rx));
  put_le32(packet.parity_expected, out + offsetof(FecstatPacket, parity_expected));
  put_le32(packet.sets_k_unknown, out + offsetof(FecstatPacket, sets_k_unknown));
  put_le32(packet.sets_full, out + offsetof(FecstatPacket, sets_full));
  put_le32(packet.auth_fail, out + offsetof(FecstatPacket, auth_fail));
  put_le32(packet.late_dup, out + offsetof(FecstatPacket, late_dup));
  put_le32(packet.struct_fail, out + offsetof(FecstatPacket, struct_fail));
  put_le16(packet.repair_lat_p50_ms, out + offsetof(FecstatPacket, repair_lat_p50_ms));
  put_le16(packet.repair_lat_p95_ms, out + offsetof(FecstatPacket, repair_lat_p95_ms));
  put_le32(packet.data_bytes_rx, out + offsetof(FecstatPacket, data_bytes_rx));
  put_le32(packet.parity_bytes_rx, out + offsetof(FecstatPacket, parity_bytes_rx));
  put_le32(packet.sets_tail_dropped, out + offsetof(FecstatPacket, sets_tail_dropped));
  put_le32(packet.data_late_rx, out + offsetof(FecstatPacket, data_late_rx));
  put_le32(packet.sets_partial, out + offsetof(FecstatPacket, sets_partial));
  put_le32(packet.ledger_groups, out + offsetof(FecstatPacket, ledger_groups));
  put_le32(packet.ledger_fail_ppm, out + offsetof(FecstatPacket, ledger_fail_ppm));
  put_le32(packet.ledger_meta, out + offsetof(FecstatPacket, ledger_meta));
  for (size_t i = 0; i < sizeof(packet.reserved) / sizeof(packet.reserved[0]); ++i) {
    put_le32(packet.reserved[i], out + offsetof(FecstatPacket, reserved) + 4 * i);
  }
}

FecstatStatus decode_fecstat(const uint8_t* in, size_t len, const uint8_t salt[8],
                             FecstatPacket* out) {
  if (in == nullptr || out == nullptr || len != kFecstatLen) {
    return FecstatStatus::kBadLength;
  }
  if (std::memcmp(in, kFecstatMagic, sizeof(kFecstatMagic)) != 0) {
    return FecstatStatus::kBadMagic;
  }
  if (std::memcmp(in + offsetof(FecstatPacket, session_salt), salt,
                  sizeof(out->session_salt)) != 0) {
    return FecstatStatus::kBadSalt;
  }
  if (in[offsetof(FecstatPacket, ver)] != kFecstatVersion) {
    return FecstatStatus::kBadVer;
  }

  FecstatPacket packet{};
  std::memcpy(packet.magic, in + offsetof(FecstatPacket, magic), sizeof(packet.magic));
  std::memcpy(packet.session_salt, in + offsetof(FecstatPacket, session_salt),
              sizeof(packet.session_salt));
  packet.ver = in[offsetof(FecstatPacket, ver)];
  packet.flg = in[offsetof(FecstatPacket, flg)];
  packet.interval_ms = get_le16(in + offsetof(FecstatPacket, interval_ms));
  packet.accounted_through_set_id = get_le32(in + offsetof(FecstatPacket, accounted_through_set_id));
  packet.sets_expected = get_le32(in + offsetof(FecstatPacket, sets_expected));
  packet.data_expected = get_le32(in + offsetof(FecstatPacket, data_expected));
  packet.data_rx_orig = get_le32(in + offsetof(FecstatPacket, data_rx_orig));
  packet.data_recovered_dl = get_le32(in + offsetof(FecstatPacket, data_recovered_dl));
  packet.data_recovered_late = get_le32(in + offsetof(FecstatPacket, data_recovered_late));
  packet.data_delivered = get_le32(in + offsetof(FecstatPacket, data_delivered));
  packet.parity_rx = get_le32(in + offsetof(FecstatPacket, parity_rx));
  packet.parity_expected = get_le32(in + offsetof(FecstatPacket, parity_expected));
  packet.sets_k_unknown = get_le32(in + offsetof(FecstatPacket, sets_k_unknown));
  packet.sets_full = get_le32(in + offsetof(FecstatPacket, sets_full));
  packet.auth_fail = get_le32(in + offsetof(FecstatPacket, auth_fail));
  packet.late_dup = get_le32(in + offsetof(FecstatPacket, late_dup));
  packet.struct_fail = get_le32(in + offsetof(FecstatPacket, struct_fail));
  packet.repair_lat_p50_ms = get_le16(in + offsetof(FecstatPacket, repair_lat_p50_ms));
  packet.repair_lat_p95_ms = get_le16(in + offsetof(FecstatPacket, repair_lat_p95_ms));
  packet.data_bytes_rx = get_le32(in + offsetof(FecstatPacket, data_bytes_rx));
  packet.parity_bytes_rx = get_le32(in + offsetof(FecstatPacket, parity_bytes_rx));
  packet.sets_tail_dropped = get_le32(in + offsetof(FecstatPacket, sets_tail_dropped));
  packet.data_late_rx = get_le32(in + offsetof(FecstatPacket, data_late_rx));
  packet.sets_partial = get_le32(in + offsetof(FecstatPacket, sets_partial));
  packet.ledger_groups = get_le32(in + offsetof(FecstatPacket, ledger_groups));
  packet.ledger_fail_ppm = get_le32(in + offsetof(FecstatPacket, ledger_fail_ppm));
  packet.ledger_meta = get_le32(in + offsetof(FecstatPacket, ledger_meta));
  for (size_t i = 0; i < sizeof(packet.reserved) / sizeof(packet.reserved[0]); ++i) {
    packet.reserved[i] = get_le32(in + offsetof(FecstatPacket, reserved) + 4 * i);
  }
  *out = packet;
  return FecstatStatus::kOk;
}

FecstatStatus FecstatValidator::validate(const uint8_t* in, size_t len, const uint8_t salt[8],
                                         FecstatPacket* out) {
  const FecstatStatus status = decode_fecstat(in, len, salt, out);
  if (status != FecstatStatus::kOk) {
    return status;
  }
  // Monotonic key over the modular half-window (spec §14.5): a report is stale
  // when its key equals or precedes the last accepted one, including across
  // the u32 wrap. #28⑤ (F3): an exact repeat of the last accepted key is the
  // second copy of a double-sent report — ignored as a duplicate so the stale
  // counter keeps meaning "genuinely behind".
  if (have_last_) {
    if (out->accounted_through_set_id == last_set_id_) {
      return FecstatStatus::kDuplicate;
    }
    if (!set_id_after(last_set_id_, out->accounted_through_set_id)) {
      return FecstatStatus::kStale;
    }
    // P6' N8: "forward" must also be bounded. A signed neighbour can claim
    // last + 2^31 - 1, which passes the half-window test and then makes every
    // genuine report stale for the rest of the session (k frozen until the
    // u32 wrap). The sender's own set counter is at most a handful of sets
    // ahead of anything it could legitimately report.
    const uint32_t forward =
        out->accounted_through_set_id - last_set_id_;
    if (forward > kFecstatMaxForwardSets) {
      ++future_rejects_;
      return FecstatStatus::kStale;
    }
  }
  have_last_ = true;
  last_set_id_ = out->accounted_through_set_id;
  return FecstatStatus::kOk;
}

}  // namespace fcp
