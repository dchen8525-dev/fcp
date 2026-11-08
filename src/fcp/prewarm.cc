#include "fcp/prewarm.h"

#include <algorithm>

#include "fcp/limits.h"
#include "fcp/session.h"
#include "fcp/stream.h"
#include "fcp/wire.h"

namespace fcp {

// The field offsets below are written out by hand so the layout stays explicit
// on the wire; this keeps the length constant from drifting away from them
// (a 12-byte layout declared as 11 wrote one byte past the vector).
static_assert(kPrewarmTlvLen == 1 + 1 + 2 + 3 + 3 + 2,
              "kPrewarmTlvLen must match the field offsets in encode_prewarm_tlv");

std::vector<uint8_t> encode_prewarm_tlv(const PeerProfile& profile) {
  std::vector<uint8_t> out(kPrewarmTlvLen);
  const auto clamp_u16 = [](int64_t v) -> uint16_t {
    return v < 0 ? 0 : (v > 65535 ? 65535 : static_cast<uint16_t>(v));
  };
  // k is a 3-bit field on the wire (kMaxParity == 7), so nothing above 7 is a
  // real value this protocol can produce; the field's spare 8..14 range carries
  // nothing, and 15 stays the "unknown" marker the profile's -1 encodes to.
  const uint8_t k_byte =
      profile.initial_k < 0
          ? kPrewarmTlvKUnknown
          : static_cast<uint8_t>(std::min<int64_t>(profile.initial_k, kMaxParity));
  const auto clamp_k24 = [](uint64_t v) -> uint32_t {
    return v > 0xFFFFFFull ? 0xFFFFFFu : static_cast<uint32_t>(v);
  };
  out[0] = kPrewarmTlvVersion;
  out[1] = k_byte;
  put_le16(clamp_u16(profile.srtt_ms), out.data() + 2);
  put_le24(clamp_k24(profile.window_bytes / 1024), out.data() + 4);
  put_le24(clamp_k24(profile.bw_bps / 1000), out.data() + 7);
  put_le16(clamp_u16(profile.min_rtt_ms), out.data() + 10);
  return out;
}

bool decode_prewarm_tlv(const std::vector<uint8_t>& value, PeerProfile* out) {
  if (value.size() != kPrewarmTlvLen || value[0] != kPrewarmTlvVersion ||
      value[1] > kPrewarmTlvKUnknown) {
    return false;
  }
  // k above kMaxParity is not something this protocol can produce (it is a
  // 3-bit field), and the spare bytes stay rejected: a value that cannot be a
  // measurement is a malformed ticket, not a seed worth honouring.
  if (value[1] != kPrewarmTlvKUnknown && value[1] > kMaxParity) {
    return false;
  }
  out->initial_k = value[1] == kPrewarmTlvKUnknown ? -1 : static_cast<int>(value[1]);
  out->srtt_ms = get_le16(value.data() + 2);
  // Both products are bounded by the 24-bit field times its unit; the casts are
  // widened first so a 32-bit size_t platform cannot truncate the 16 GiB form.
  out->window_bytes = static_cast<size_t>(static_cast<uint64_t>(get_le24(value.data() + 4)) * 1024u);
  out->bw_bps = static_cast<uint64_t>(get_le24(value.data() + 7)) * 1000u;
  out->min_rtt_ms = get_le16(value.data() + 10);
  return true;
}

std::string peer_key(const std::string& host, uint16_t port) {
  std::string key;
  key.reserve(host.size() + 8);
  if (!host.empty() && host.find(':') != std::string::npos && host.front() != '[') {
    key.push_back('[');
    key += host;
    key.push_back(']');
  } else {
    key += host;
  }
  key.push_back(':');
  key += std::to_string(port);
  return key;
}

PrewarmCache::PrewarmCache(int64_t ttl_ms, size_t max_entries)
    : ttl_ms_(ttl_ms > 0 ? ttl_ms : kPrewarmTtlMs),
      max_entries_(max_entries > 0 ? max_entries : kPrewarmMaxEntries) {}

bool PrewarmCache::put(const std::string& key, const PeerProfile& profile, int64_t now_ms,
                       PrewarmSource source) {
  if (by_key_.find(key) == by_key_.end() && by_key_.size() >= max_entries_) {
    // Expire what is already dead first, then refuse outright. Evicting a live
    // entry would throw away the freshest snapshots exactly when a peer set is
    // churning fastest, and a refused write only costs this one session its
    // warm start.
    prune(now_ms);
    if (by_key_.size() >= max_entries_) {
      return false;
    }
  }
  const auto it = by_key_.find(key);
  // A ticket describes a path the peer's controller measured. Where this end
  // has its own live measurement, that measurement stays: otherwise the two
  // sides would keep overwriting each other with each other's view and the
  // entry would drift away from anything actually observed.
  if (it != by_key_.end() && source == PrewarmSource::kTicket &&
      !expired(it->second, now_ms, ttl_ms_) &&
      it->second.source == PrewarmSource::kMeasured) {
    return true;
  }
  by_key_[key] = Entry{profile, now_ms, source};
  return true;
}

bool PrewarmCache::get(const std::string& key, int64_t now_ms, PeerProfile* out) const {
  const auto it = by_key_.find(key);
  if (it == by_key_.end() || expired(it->second, now_ms, ttl_ms_)) {
    return false;
  }
  if (out != nullptr) {
    *out = it->second.profile;
  }
  return true;
}

size_t PrewarmCache::prune(int64_t now_ms) {
  size_t dropped = 0;
  for (auto it = by_key_.begin(); it != by_key_.end();) {
    if (expired(it->second, now_ms, ttl_ms_)) {
      it = by_key_.erase(it);
      ++dropped;
    } else {
      ++it;
    }
  }
  return dropped;
}

void PrewarmCache::clear() { by_key_.clear(); }

bool PrewarmCache::expired(const Entry& entry, int64_t now_ms, int64_t ttl_ms) {
  // Deadline arithmetic instead of a difference: a host clock that steps back
  // leaves the entry readable a little longer rather than expiring the cache.
  return now_ms >= entry.seen_ms + ttl_ms;
}

void apply_prewarm(const PeerProfile& profile, SessionConfig* session, StreamConfig* stream) {
  // The two priors are independent: a link that produced RTT samples but never
  // engaged parity still warms the timers, and one that engaged parity before
  // the first sample still seeds k.
  if (session != nullptr) {
    if (profile.srtt_ms > 0) {
      session->initial_srtt_ms = profile.srtt_ms;
    }
    if (profile.initial_k > 0) {
      session->initial_k = profile.initial_k;
    }
  }
  if (stream != nullptr) {
    if (profile.srtt_ms > 0) {
      // The stream keeps its own smoothed value: RTO is derived from it on the
      // very first segment, long before the session has a sample to hand over.
      stream->initial_srtt_ms = profile.srtt_ms;
    }
    // Only seed the autotuner's start. A fixed window is the operator's choice
    // and an explicit --window overrides even the prior: precedence is
    // explicit CLI > prewarm > default. The prior is also capped at this end's
    // own ceiling (#87): the wire clamp admits up to 16 GiB, which describes no
    // link this end is willing to buffer for, and the entry may have come from
    // the peer's ticket rather than from a local measurement.
    if (profile.window_bytes > 0 && stream->auto_window &&
        !stream->send_window_explicit) {
      stream->send_window_bytes =
          std::min(profile.window_bytes, stream->window_max_bytes);
    }
    // The controller priors are only meaningful for the controller they came
    // from, and only when the operator did not pin the start.
    if (stream->auto_window && stream->bbr && !stream->send_window_explicit) {
      if (profile.bw_bps > 0) {
        stream->initial_bw_bps = profile.bw_bps;
      }
      if (profile.min_rtt_ms > 0) {
        stream->initial_min_rtt_ms = profile.min_rtt_ms;
      }
    }
  }
}

}  // namespace fcp
