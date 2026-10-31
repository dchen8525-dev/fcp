#include "fcp/fecstat.h"

#include <cstring>

#include "fcp/hdr.h"

namespace fcp {
namespace {

void write16(uint8_t* out, uint16_t value) {
  out[0] = static_cast<uint8_t>(value);
  out[1] = static_cast<uint8_t>(value >> 8);
}

void write32(uint8_t* out, uint32_t value) {
  out[0] = static_cast<uint8_t>(value);
  out[1] = static_cast<uint8_t>(value >> 8);
  out[2] = static_cast<uint8_t>(value >> 16);
  out[3] = static_cast<uint8_t>(value >> 24);
}

uint16_t read16(const uint8_t* in) {
  return static_cast<uint16_t>(static_cast<uint16_t>(in[0]) |
                               (static_cast<uint16_t>(in[1]) << 8));
}

uint32_t read32(const uint8_t* in) {
  return static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
         (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);
}

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
  write16(out + offsetof(FecstatPacket, interval_ms), packet.interval_ms);
  write32(out + offsetof(FecstatPacket, accounted_through_set_id),
          packet.accounted_through_set_id);
  write32(out + offsetof(FecstatPacket, sets_expected), packet.sets_expected);
  write32(out + offsetof(FecstatPacket, data_expected), packet.data_expected);
  write32(out + offsetof(FecstatPacket, data_rx_orig), packet.data_rx_orig);
  write32(out + offsetof(FecstatPacket, data_recovered_dl), packet.data_recovered_dl);
  write32(out + offsetof(FecstatPacket, data_recovered_late), packet.data_recovered_late);
  write32(out + offsetof(FecstatPacket, data_delivered), packet.data_delivered);
  write32(out + offsetof(FecstatPacket, parity_rx), packet.parity_rx);
  write32(out + offsetof(FecstatPacket, parity_expected), packet.parity_expected);
  write32(out + offsetof(FecstatPacket, sets_k_unknown), packet.sets_k_unknown);
  write32(out + offsetof(FecstatPacket, sets_full), packet.sets_full);
  write32(out + offsetof(FecstatPacket, auth_fail), packet.auth_fail);
  write32(out + offsetof(FecstatPacket, late_dup), packet.late_dup);
  write32(out + offsetof(FecstatPacket, struct_fail), packet.struct_fail);
  write16(out + offsetof(FecstatPacket, repair_lat_p50_ms), packet.repair_lat_p50_ms);
  write16(out + offsetof(FecstatPacket, repair_lat_p95_ms), packet.repair_lat_p95_ms);
  write32(out + offsetof(FecstatPacket, data_bytes_rx), packet.data_bytes_rx);
  write32(out + offsetof(FecstatPacket, parity_bytes_rx), packet.parity_bytes_rx);
  write32(out + offsetof(FecstatPacket, sets_tail_dropped), packet.sets_tail_dropped);
  write32(out + offsetof(FecstatPacket, data_late_rx), packet.data_late_rx);
  write32(out + offsetof(FecstatPacket, sets_partial), packet.sets_partial);
  write32(out + offsetof(FecstatPacket, ledger_groups), packet.ledger_groups);
  write32(out + offsetof(FecstatPacket, ledger_fail_ppm), packet.ledger_fail_ppm);
  write32(out + offsetof(FecstatPacket, ledger_meta), packet.ledger_meta);
  for (size_t i = 0; i < sizeof(packet.reserved) / sizeof(packet.reserved[0]); ++i) {
    write32(out + offsetof(FecstatPacket, reserved) + 4 * i, packet.reserved[i]);
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
  packet.interval_ms = read16(in + offsetof(FecstatPacket, interval_ms));
  packet.accounted_through_set_id = read32(in + offsetof(FecstatPacket, accounted_through_set_id));
  packet.sets_expected = read32(in + offsetof(FecstatPacket, sets_expected));
  packet.data_expected = read32(in + offsetof(FecstatPacket, data_expected));
  packet.data_rx_orig = read32(in + offsetof(FecstatPacket, data_rx_orig));
  packet.data_recovered_dl = read32(in + offsetof(FecstatPacket, data_recovered_dl));
  packet.data_recovered_late = read32(in + offsetof(FecstatPacket, data_recovered_late));
  packet.data_delivered = read32(in + offsetof(FecstatPacket, data_delivered));
  packet.parity_rx = read32(in + offsetof(FecstatPacket, parity_rx));
  packet.parity_expected = read32(in + offsetof(FecstatPacket, parity_expected));
  packet.sets_k_unknown = read32(in + offsetof(FecstatPacket, sets_k_unknown));
  packet.sets_full = read32(in + offsetof(FecstatPacket, sets_full));
  packet.auth_fail = read32(in + offsetof(FecstatPacket, auth_fail));
  packet.late_dup = read32(in + offsetof(FecstatPacket, late_dup));
  packet.struct_fail = read32(in + offsetof(FecstatPacket, struct_fail));
  packet.repair_lat_p50_ms = read16(in + offsetof(FecstatPacket, repair_lat_p50_ms));
  packet.repair_lat_p95_ms = read16(in + offsetof(FecstatPacket, repair_lat_p95_ms));
  packet.data_bytes_rx = read32(in + offsetof(FecstatPacket, data_bytes_rx));
  packet.parity_bytes_rx = read32(in + offsetof(FecstatPacket, parity_bytes_rx));
  packet.sets_tail_dropped = read32(in + offsetof(FecstatPacket, sets_tail_dropped));
  packet.data_late_rx = read32(in + offsetof(FecstatPacket, data_late_rx));
  packet.sets_partial = read32(in + offsetof(FecstatPacket, sets_partial));
  packet.ledger_groups = read32(in + offsetof(FecstatPacket, ledger_groups));
  packet.ledger_fail_ppm = read32(in + offsetof(FecstatPacket, ledger_fail_ppm));
  packet.ledger_meta = read32(in + offsetof(FecstatPacket, ledger_meta));
  for (size_t i = 0; i < sizeof(packet.reserved) / sizeof(packet.reserved[0]); ++i) {
    packet.reserved[i] = read32(in + offsetof(FecstatPacket, reserved) + 4 * i);
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
  }
  have_last_ = true;
  last_set_id_ = out->accounted_through_set_id;
  return FecstatStatus::kOk;
}

}  // namespace fcp
