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
    // Integral doubles print as integers for readability; everything else
    // needs %.17g, the shortest width that round-trips every double. %.9g
    // used to drop the low bits of target_recovery/budget, so a replayed
    // candidate could take a different branch than the recording did.
    // The integral branch is capped at 2^53 because casting a double outside
    // the exact-integer range (or int64) to int64 is undefined behavior.
    if (std::fabs(f.value) <= 9007199254740992.0 && f.value == std::trunc(f.value)) {
      std::snprintf(num, sizeof(num), "%lld", static_cast<long long>(f.value));
    } else {
      std::snprintf(num, sizeof(num), "%.17g", f.value);
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

// Every integer field is range-checked before its cast: a negative count or a
// 1e300 in a hand-edited trace would otherwise be an out-of-range double ->
// integer conversion, which is undefined behavior. A field outside its wire
// width rejects the whole line, like any other structural violation.
bool field_in_range(const std::vector<std::pair<std::string, double>>& fields,
                    const char* key, double lo, double hi, double fallback,
                    double* out) {
  const double v = field_or(fields, key, fallback);
  if (!(v >= lo && v <= hi)) {
    return false;
  }
  *out = v;
  return true;
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
  // P8' N9: a failed decode used to leave the previous entry's ver intact while
  // every other failure cleared it. Make the contract uniform: failure leaves a
  // default-initialised entry.
  TraceEntry scratch;
  TraceEntry& out = e != nullptr ? *e : scratch;
  out = TraceEntry{};
  if (!scan_fields(line, &fields)) {
    return false;
  }
  double v = 0;
  if (!field_in_range(fields, "ver", 0.0, 2147483647.0, 0.0, &v) ||
      v != std::trunc(v) || static_cast<int>(v) != kTraceVersion) {
    return false;
  }
  // Every integer field in a trace line is one JSON number that has to land in
  // a range and be integral; the four widths only differ in those two numbers,
  // so the range and the truncation check live here (the same truncation test
  // the ver field above applies).
  auto int_field = [&fields](const char* key, double lo, double hi, double fallback,
                             double* out) {
    if (!field_in_range(fields, key, lo, hi, fallback, out)) {
      return false;
    }
    return *out == std::trunc(*out);
  };
  auto u8 = [&int_field](const char* key, uint8_t fallback, uint8_t* out) {
    double raw = 0;
    if (!int_field(key, 0.0, 255.0, fallback, &raw)) {
      return false;
    }
    *out = static_cast<uint8_t>(raw);
    return true;
  };
  auto u16 = [&int_field](const char* key, uint16_t fallback, uint16_t* out) {
    double raw = 0;
    if (!int_field(key, 0.0, 65535.0, fallback, &raw)) {
      return false;
    }
    *out = static_cast<uint16_t>(raw);
    return true;
  };
  auto u32 = [&int_field](const char* key, uint32_t fallback, uint32_t* out) {
    double raw = 0;
    if (!int_field(key, 0.0, 4294967295.0, fallback, &raw)) {
      return false;
    }
    *out = static_cast<uint32_t>(raw);
    return true;
  };
  auto i32 = [&int_field](const char* key, int fallback, int* out) {
    double raw = 0;
    if (!int_field(key, -2147483648.0, 2147483647.0, fallback, &raw)) {
      return false;
    }
    *out = static_cast<int>(raw);
    return true;
  };

  TraceConfigSnapshot& c = out.snapshot;
  if (!u8("c_d", 10, &c.d) || !u8("c_pmax", kDefaultPmax, &c.p_max) ||
      !i32("c_ik", -1, &c.initial_k) || !i32("c_pin", -1, &c.pinned)) {
    return false;
  }
  c.target_recovery = field_or(fields, "c_target", kTargetRecovery);
  c.budget = field_or(fields, "c_budget", kDefaultFecBudget);

  if (!field_in_range(fields, "now", -9007199254740992.0, 9007199254740992.0, 0.0, &v)) {
    return false;
  }
  out.now_ms = static_cast<int64_t>(v);
  out.window_queued = field_or(fields, "queued", 0.0) != 0.0;
  if (!u8("k", 0, &out.k_after)) {
    return false;
  }
  uint8_t state = 0;
  if (!u8("state", 0, &state)) {
    return false;
  }
  if (state > static_cast<uint8_t>(FecState::kCapped)) {
    return false;  // P8' N8: reject a non-enum state instead of casting it
  }
  out.state_after = static_cast<FecState>(state);
  out.last_loss = field_or(fields, "loss", 0.0);

  FecstatPacket& s = out.stat;
  s = MakeFecstatPacket(s.session_salt);
  if (!u8("s_ver", kFecstatVersion, &s.ver) || !u8("s_flg", 0, &s.flg) ||
      !u16("s_ivl", 0, &s.interval_ms) ||
      !u32("s_setid", 0, &s.accounted_through_set_id) ||
      !u32("s_sets", 0, &s.sets_expected) || !u32("s_exp", 0, &s.data_expected) ||
      !u32("s_rx", 0, &s.data_rx_orig) || !u32("s_rec", 0, &s.data_recovered_dl) ||
      !u32("s_reclate", 0, &s.data_recovered_late) ||
      !u32("s_deliv", 0, &s.data_delivered) || !u32("s_prx", 0, &s.parity_rx) ||
      !u32("s_pexp", 0, &s.parity_expected) || !u32("s_kunk", 0, &s.sets_k_unknown) ||
      !u32("s_full", 0, &s.sets_full) || !u32("s_auth", 0, &s.auth_fail) ||
      !u32("s_dup", 0, &s.late_dup) || !u32("s_struct", 0, &s.struct_fail) ||
      !u16("s_lat50", 0, &s.repair_lat_p50_ms) ||
      !u16("s_lat95", 0, &s.repair_lat_p95_ms) ||
      !u32("s_dbytes", 0, &s.data_bytes_rx) ||
      !u32("s_pbytes", 0, &s.parity_bytes_rx) ||
      !u32("s_tdrop", 0, &s.sets_tail_dropped) || !u32("s_late", 0, &s.data_late_rx) ||
      !u32("s_partial", 0, &s.sets_partial) ||
      !u32("s_lgroups", 0, &s.ledger_groups) ||
      !u32("s_lfail", 0, &s.ledger_fail_ppm) || !u32("s_lmeta", 0, &s.ledger_meta)) {
    return false;
  }
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
