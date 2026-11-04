// Argument parsing shared by the proxy CLI (apps/cli/cli.cc) and the two
// tools (fcp-bench, fcp-replay).
//
// Two things live here, for the same reason: they are a single fact written
// once instead of a copy per binary that drifts in its diagnostics.
//
//   1. Range-checked numbers. atoi()/atof() let --seg=-1 become SIZE_MAX and
//      --port=70000 wrap to 4464, so a value only survives if the whole string
//      was consumed and the result is in range (the A10/P8-3 fix).
//   2. `Name[:Field]=Value` matching, so a related pair can be one option
//      (--window=256:1024, --fec=10:3) and old flags can keep working as
//      documented aliases of it.

#ifndef FCP_TOOLS_CLI_PARSE_H
#define FCP_TOOLS_CLI_PARSE_H

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace fcp::tools {

// A number in [lo, hi]. `text` is the value the caller wants to mean `flag`, so
// every diagnostic names the option the user typed (not "d" for "--d").
// Two forms: the four-argument one prints to stderr (the tools exit right
// after), the five-argument one writes the same sentence into `*error` (the
// proxy CLI reports it itself and must not print a second, empty line).
inline std::string RangeError(const char* flag, const char* text, long lo, long hi) {
  char buf[256];
  std::snprintf(buf, sizeof(buf), "%s must be an integer in %ld..%ld (got '%s')", flag, lo, hi,
                text);
  return buf;
}

inline bool ParseLong(const char* flag, const char* text, long lo, long hi, long* out) {
  if (text == nullptr) {
    std::fprintf(stderr, "%s requires a value\n", flag);
    return false;
  }
  char* end = nullptr;
  errno = 0;
  const long v = std::strtol(text, &end, 10);
  if (*text == '\0' || errno != 0 || end == text || *end != '\0' || v < lo || v > hi) {
    std::fprintf(stderr, "%s\n", RangeError(flag, text, lo, hi).c_str());
    return false;
  }
  *out = v;
  return true;
}

inline bool ParseLong(const char* flag, const char* text, long lo, long hi, long* out,
                      std::string* error) {
  if (text == nullptr) {
    *error = std::string(flag) + " requires a value";
    return false;
  }
  char* end = nullptr;
  errno = 0;
  const long v = std::strtol(text, &end, 10);
  if (*text == '\0' || errno != 0 || end == text || *end != '\0' || v < lo || v > hi) {
    *error = RangeError(flag, text, lo, hi);
    return false;
  }
  *out = v;
  return true;
}

inline std::string RateError(const char* flag, const char* text, double lo, double hi) {
  char buf[256];
  std::snprintf(buf, sizeof(buf), "%s must be a number in %g..%g (got '%s')", flag, lo, hi, text);
  return buf;
}

inline bool ParseDouble(const char* flag, const char* text, double lo, double hi, double* out) {
  if (text == nullptr) {
    std::fprintf(stderr, "%s requires a value\n", flag);
    return false;
  }
  char* end = nullptr;
  errno = 0;
  const double v = std::strtod(text, &end);
  if (*text == '\0' || errno != 0 || end == text || *end != '\0' || !std::isfinite(v) || v < lo ||
      v > hi) {
    std::fprintf(stderr, "%s\n", RateError(flag, text, lo, hi).c_str());
    return false;
  }
  *out = v;
  return true;
}

inline bool ParseDouble(const char* flag, const char* text, double lo, double hi, double* out,
                        std::string* error) {
  if (text == nullptr) {
    *error = std::string(flag) + " requires a value";
    return false;
  }
  char* end = nullptr;
  errno = 0;
  const double v = std::strtod(text, &end);
  if (*text == '\0' || errno != 0 || end == text || *end != '\0' || !std::isfinite(v) || v < lo ||
      v > hi) {
    *error = RateError(flag, text, lo, hi);
    return false;
  }
  *out = v;
  return true;
}

// Splits a compound value on ':' ("256:1024" -> {"256", "1024"}). The caller
// decides how many parts each option accepts.
inline std::vector<std::string> SplitFields(const std::string& value) {
  std::vector<std::string> parts;
  size_t begin = 0;
  while (true) {
    const size_t colon = value.find(':', begin);
    if (colon == std::string::npos) {
      parts.push_back(value.substr(begin));
      return parts;
    }
    parts.push_back(value.substr(begin, colon - begin));
    begin = colon + 1;
  }
}

// One spelling of one option.
struct Alias {
  const char* name;
  bool takes_value;
};

// Where a matched argument landed: which alias matched, what was given.
struct Match {
  const char* name = nullptr;
  bool takes_value = false;
  std::string value;
  bool has_value = false;
};

// Longest-prefix matching, so `--key-env` is never reported as `--key`.
// A registered value-option given bare is an error rather than an empty value:
// `--window` with no `=` would otherwise mean 0 KiB. `arg` must start with
// "--"; the caller rewrites the short spellings (-h/-V/-v) first.
inline bool MatchOption(const std::vector<Alias>& aliases, const std::string& arg, Match* out,
                        std::string* error) {
  // Longest match wins, not first-in-list: the list is written in --help order
  // and a longer alias added later (say --window-max next to --window) must
  // still win regardless of where it is placed.
  const Alias* best = nullptr;
  size_t best_len = 0;
  for (const Alias& a : aliases) {
    const std::string name = a.name;
    const size_t n = name.size();
    if (n <= best_len || arg.compare(0, n, name) != 0) {
      continue;
    }
    if (arg.size() > n && arg[n] != '=') {
      continue;
    }
    best = &a;
    best_len = n;
  }
  if (best == nullptr) {
    *error = "unknown argument: --" + arg.substr(2);
    return false;
  }
  // `best->name` already carries the leading "--"; prepending another one
  // produced diagnostics like "----window requires a value".
  const std::string name = best->name;
  const bool has_value = arg.size() > best_len;
  if (best->takes_value && !has_value) {
    *error = name + " requires a value";
    return false;
  }
  if (!best->takes_value && has_value) {
    *error = name + " takes no value; got '" + arg + "'";
    return false;
  }
  out->name = best->name;
  out->takes_value = best->takes_value;
  out->has_value = has_value;
  out->value = has_value ? arg.substr(best_len + 1) : std::string();
  return true;
}

// Records that `name` was set and refuses a second member of the same group.
// Groups are how two spellings of one setting share a slot (--key and
// --key-file pass "key"); silently letting the last one win is how a script
// ends up running something its author cannot explain.
inline bool MarkSeen(std::vector<std::string>* seen, const std::string& name,
                     std::string* error) {
  for (const std::string& s : *seen) {
    if (s == name) {
      *error = "option --" + name + " given more than once";
      return false;
    }
  }
  seen->push_back(name);
  return true;
}

}  // namespace fcp::tools

#endif  // FCP_TOOLS_CLI_PARSE_H
