#include "fcp/trace.h"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <utility>

namespace fcp {
namespace {

// Every field rides as one flat `"key":<number>` pair; u32 and smaller fit
// exactly in a double, and int64 now_ms stays exact below 2^53 ms (292k years).
struct Field {
  const char* key;
  double value;
};

void append_fields(std::string* out, const std::vector<Field>& fields) {
  for (const Field& f : fields) {
    char num[32];
    if (f.value == static_cast<int64_t>(f.value)) {
      std::snprintf(num, sizeof(num), "%lld",
                    static_cast<long long>(f.value));
    } else {
      std::snprintf(num, sizeof(num), "%.9g", f.value);
    }
    out->append("\"");
    out->append(f.key);
    out->append("\":");
    out->append(num);
    out->push_back(',');
  }
}

// Flat scanner: `{ "key":number, ... }`. Returns the key/value pairs, or
// false on any structural violation. No whitespace, no strings, no nesting —
// encode never produces them.
bool scan_fields(const std::string& line,
                 std::vector<std::pair<std::string, double>>* out) {
  size_t i = 0;
  auto skip_ws = [&] {
    while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) {
      ++i;
    }
  };
  skip_ws();
  if (i >= line.size() || line[i] != '{') {
    return false;
  }
  ++i;
  for (;;) {
    skip_ws();
    if (i < line.size() && line[i] == '}') {
      return true;
    }
    if (i >= line.size() || line[i] != '"') {
      return false;
    }
    const size_t key_begin = ++i;
    while (i < line.size() && line[i] != '"') {
      ++i;
    }
    if (i >= line.size()) {
      return false;
    }
    std::string key(line, key_begin, i - key_begin);
    ++i;
    skip_ws();
    if (i >= line.size() || line[i] != ':') {
      return false;
    }
    ++i;
    skip_ws();
    const char* begin = line.c_str() + i;
    char* end = nullptr;
    const double value = std::strtod(begin, &end);
    if (end == begin) {
      return false;
    }
    // #30: 1e999 turns into HUGE_VAL; a non-finite field would become UB in
    // the int casts downstream. Encode never emits one, so reject the line.
    if (!std::isfinite(value)) {
      return false;
    }
    i += static_cast<size_t>(end - begin);
    out->emplace_back(std::move(key), value);
    skip_ws();
    if (i < line.size() && line[i] == ',') {
      ++i;
      continue;
    }
    if (i < line.size() && line[i] == '}') {
      // #30: the object must end the line — trailing garbage after the close
      // would let a second object ride inside one trace line.
      ++i;
      skip_ws();
      return i >= line.size();
    }
    return false;
  }
}

double field_or(const std::vector<std::pair<std::string, double>>& fields,
                const char* key, double fallback) {
  // Last one wins, matching how a JSON object parser would fold duplicates.
  for (auto it = fields.rbegin(); it != fields.rend(); ++it) {
    if (it->first == key) {
      return it->second;
    }
  }
  return fallback;
}

}  // namespace

void encode_trace_line(const TraceEntry& e, std::string* out) {
  const TraceConfigSnapshot& c = e.snapshot;
  out->clear();
  out->push_back('{');
  const FecstatPacket& s = e.stat;
  // Function-style construction sidesteps the brace-init narrowing rules:
  // every width below is exact in a double.
  auto fld = [](const char* key, double value) { return Field{key, value}; };
  append_fields(out,
                {
                    fld("ver", kTraceVersion),
                    fld("now", static_cast<double>(e.now_ms)),
                    fld("queued", e.window_queued ? 1.0 : 0.0),
                    fld("k", e.k_after),
                    fld("state", static_cast<double>(e.state_after)),
                    fld("loss", e.last_loss),
                    fld("c_d", c.d),
                    fld("c_pmax", c.p_max),
                    fld("c_target", c.target_recovery),
                    fld("c_budget", c.budget),
                    fld("c_ik", c.initial_k),
                    fld("c_pin", c.pinned),
                    fld("s_ver", s.ver),
                    fld("s_flg", s.flg),
                    fld("s_ivl", s.interval_ms),
                    fld("s_setid", s.accounted_through_set_id),
                    fld("s_sets", s.sets_expected),
                    fld("s_exp", s.data_expected),
                    fld("s_rx", s.data_rx_orig),
                    fld("s_rec", s.data_recovered_dl),
                    fld("s_reclate", s.data_recovered_late),
                    fld("s_deliv", s.data_delivered),
                    fld("s_prx", s.parity_rx),
                    fld("s_pexp", s.parity_expected),
                    fld("s_kunk", s.sets_k_unknown),
                    fld("s_full", s.sets_full),
                    fld("s_auth", s.auth_fail),
                    fld("s_dup", s.late_dup),
                    fld("s_struct", s.struct_fail),
                    fld("s_lat50", s.repair_lat_p50_ms),
                    fld("s_lat95", s.repair_lat_p95_ms),
                    fld("s_dbytes", s.data_bytes_rx),
                    fld("s_pbytes", s.parity_bytes_rx),
                    fld("s_tdrop", s.sets_tail_dropped),
                    fld("s_late", s.data_late_rx),
                    fld("s_partial", s.sets_partial),
                    fld("s_lgroups", s.ledger_groups),
                    fld("s_lfail", s.ledger_fail_ppm),
                    fld("s_lmeta", s.ledger_meta),
                });
  out->back() = '}';  // replace the trailing comma
}

bool decode_trace_line(const std::string& line, TraceEntry* e) {
  std::vector<std::pair<std::string, double>> fields;
  if (!scan_fields(line, &fields)) {
    return false;
  }
  if (static_cast<int>(field_or(fields, "ver", 0)) != kTraceVersion) {
    return false;
  }
  *e = TraceEntry{};
  TraceConfigSnapshot& c = e->snapshot;
  c.d = static_cast<uint8_t>(field_or(fields, "c_d", 10));
  c.p_max = static_cast<uint8_t>(field_or(fields, "c_pmax", kDefaultPmax));
  c.target_recovery = field_or(fields, "c_target", kTargetRecovery);
  c.budget = field_or(fields, "c_budget", 0.50);
  c.initial_k = static_cast<int>(field_or(fields, "c_ik", -1));
  c.pinned = static_cast<int>(field_or(fields, "c_pin", -1));

  e->now_ms = static_cast<int64_t>(field_or(fields, "now", 0));
  e->window_queued = field_or(fields, "queued", 0.0) != 0.0;
  e->k_after = static_cast<uint8_t>(field_or(fields, "k", 0));
  e->state_after = static_cast<FecState>(
      static_cast<uint8_t>(field_or(fields, "state", 0)));
  e->last_loss = field_or(fields, "loss", 0.0);

  FecstatPacket& s = e->stat;
  s = MakeFecstatPacket(s.session_salt);
  s.ver = static_cast<uint8_t>(field_or(fields, "s_ver", kFecstatVersion));
  s.flg = static_cast<uint8_t>(field_or(fields, "s_flg", 0));
  s.interval_ms = static_cast<uint16_t>(field_or(fields, "s_ivl", 0));
  s.accounted_through_set_id =
      static_cast<uint32_t>(field_or(fields, "s_setid", 0));
  s.sets_expected = static_cast<uint32_t>(field_or(fields, "s_sets", 0));
  s.data_expected = static_cast<uint32_t>(field_or(fields, "s_exp", 0));
  s.data_rx_orig = static_cast<uint32_t>(field_or(fields, "s_rx", 0));
  s.data_recovered_dl = static_cast<uint32_t>(field_or(fields, "s_rec", 0));
  s.data_recovered_late =
      static_cast<uint32_t>(field_or(fields, "s_reclate", 0));
  s.data_delivered = static_cast<uint32_t>(field_or(fields, "s_deliv", 0));
  s.parity_rx = static_cast<uint32_t>(field_or(fields, "s_prx", 0));
  s.parity_expected = static_cast<uint32_t>(field_or(fields, "s_pexp", 0));
  s.sets_k_unknown = static_cast<uint32_t>(field_or(fields, "s_kunk", 0));
  s.sets_full = static_cast<uint32_t>(field_or(fields, "s_full", 0));
  s.auth_fail = static_cast<uint32_t>(field_or(fields, "s_auth", 0));
  s.late_dup = static_cast<uint32_t>(field_or(fields, "s_dup", 0));
  s.struct_fail = static_cast<uint32_t>(field_or(fields, "s_struct", 0));
  s.repair_lat_p50_ms = static_cast<uint16_t>(field_or(fields, "s_lat50", 0));
  s.repair_lat_p95_ms = static_cast<uint16_t>(field_or(fields, "s_lat95", 0));
  s.data_bytes_rx = static_cast<uint32_t>(field_or(fields, "s_dbytes", 0));
  s.parity_bytes_rx = static_cast<uint32_t>(field_or(fields, "s_pbytes", 0));
  s.sets_tail_dropped = static_cast<uint32_t>(field_or(fields, "s_tdrop", 0));
  s.data_late_rx = static_cast<uint32_t>(field_or(fields, "s_late", 0));
  s.sets_partial = static_cast<uint32_t>(field_or(fields, "s_partial", 0));
  s.ledger_groups = static_cast<uint32_t>(field_or(fields, "s_lgroups", 0));
  s.ledger_fail_ppm = static_cast<uint32_t>(field_or(fields, "s_lfail", 0));
  s.ledger_meta = static_cast<uint32_t>(field_or(fields, "s_lmeta", 0));
  return true;
}

std::vector<ReplayStep> replay_trace(const std::vector<TraceEntry>& entries,
                                     const TraceConfigSnapshot& cfg) {
  FecStrategyConfig sc;
  sc.d = cfg.d;
  sc.p_max = cfg.p_max;
  sc.target_recovery = cfg.target_recovery;
  sc.budget_ratio = cfg.budget;
  sc.initial_k = cfg.initial_k;
  sc.pinned_k = cfg.pinned;
  FecStrategy strategy(sc);
  std::vector<ReplayStep> steps;
  steps.reserve(entries.size());
  for (const TraceEntry& e : entries) {
    strategy.on_report(e.stat, e.window_queued);
    steps.push_back(ReplayStep{strategy.k(), strategy.state()});
  }
  return steps;
}

}  // namespace fcp
