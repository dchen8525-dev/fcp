// Link-parameter prewarm (docs/FCP_M2_PROXY.md §5).
//
// A fresh session starts blind: srtt is assumed at kDefaultSrttMs and the FEC
// state machine is OFF, so the first k decision waits for the first FECSTAT
// report (2s and 256 accounted data symbols, or the 60s forced cadence). One
// session per proxy connection pays that per connection, which is exactly the
// short-traffic blind spot the spec calls out (§14.13). The values a previous
// session to the same peer converged to are the best prior there is.
//
// Priors, nothing more: every field here only sets an initial value, the
// closed loop keeps its own direction, and an absent or expired entry leaves
// the config at the M1 cold-start behaviour. Each side caches its own
// SEND-side k, because k is chosen by whoever sends FECSTAT-driven parity.

#ifndef FCP_PREWARM_H_
#define FCP_PREWARM_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace fcp {

struct SessionConfig;
struct StreamConfig;

// Long enough to cover a burst of connections to one peer, short enough that
// a link change or a peer restart is not carried around for hours.
constexpr int64_t kPrewarmTtlMs = 600000;
// Ceiling on distinct keys. A server-side cache is keyed by the client address,
// which is whatever the other end chooses, so the entry count is attacker-chosen
// too unless it is bounded.
constexpr size_t kPrewarmMaxEntries = 4096;

struct PeerProfile {
  int64_t srtt_ms = 0;  // 0 = unknown
  // -1 = unknown. A converged k of 0 (clean link) already is the cold default,
  // so it is stored as -1 rather than as a third state.
  int initial_k = -1;
};

// Cache key "host:port". A bare IPv6 literal is bracketed first so the key
// stays one colon-separated field pair.
std::string peer_key(const std::string& host, uint16_t port);

class PrewarmCache {
 public:
  explicit PrewarmCache(int64_t ttl_ms = kPrewarmTtlMs,
                        size_t max_entries = kPrewarmMaxEntries);

  // Stores a snapshot and stamps it with now_ms; last write wins, because a
  // finished session describes the link as it is now and there is nothing to
  // average across generations. Returns false -- without touching the cache --
  // when the table is full and nothing had expired.
  bool put(const std::string& key, const PeerProfile& profile, int64_t now_ms);

  // False for an unknown or expired key, which is how a session ends up
  // cold-starting. Expired entries are not erased here (get() stays const);
  // hosts that care about the footprint call prune().
  bool get(const std::string& key, int64_t now_ms, PeerProfile* out) const;

  // Drops every expired entry and returns how many went.
  size_t prune(int64_t now_ms);
  void clear();

  size_t size() const { return by_key_.size(); }
  int64_t ttl_ms() const { return ttl_ms_; }
  size_t max_entries() const { return max_entries_; }

 private:
  struct Entry {
    PeerProfile profile;
    int64_t seen_ms = 0;
  };

  static bool expired(const Entry& entry, int64_t now_ms, int64_t ttl_ms);

  int64_t ttl_ms_;
  size_t max_entries_;
  std::unordered_map<std::string, Entry> by_key_;
};

// Seeds a config pair from a profile. Unknown fields leave the target alone,
// so this is a no-op for an absent or expired entry. p_max needs no argument:
// FecStrategy clamps the seeded k against the negotiated budget itself.
void apply_prewarm(const PeerProfile& profile, SessionConfig* session, StreamConfig* stream);

}  // namespace fcp

#endif  // FCP_PREWARM_H_
