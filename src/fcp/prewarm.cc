#include "fcp/prewarm.h"

#include "fcp/session.h"
#include "fcp/stream.h"

namespace fcp {

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

bool PrewarmCache::put(const std::string& key, const PeerProfile& profile, int64_t now_ms) {
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
  by_key_[key] = Entry{profile, now_ms};
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
    // explicit CLI > prewarm > default.
    if (profile.window_bytes > 0 && stream->auto_window &&
        !stream->send_window_explicit) {
      stream->send_window_bytes = profile.window_bytes;
    }
  }
}

}  // namespace fcp
