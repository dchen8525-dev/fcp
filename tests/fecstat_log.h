// Parser for the one-line `FECSTAT ...` report that Session writes through its
// log callback. Shared by the session, e2e and soak tests: they all assert on
// the same operator-visible line, so they should all read it the same way.
//
// Kept out of e2e_link.h deliberately -- that header pulls in winsock, and a
// unit test that only wants to parse a log line should not link sockets.

#ifndef FCP_TESTS_FECSTAT_LOG_H_
#define FCP_TESTS_FECSTAT_LOG_H_

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace fcp_test {

struct FecstatLogFields {
  uint32_t sets = 0;
  uint32_t expect = 0;
  uint32_t rx = 0;
  uint32_t rec = 0;
  uint32_t late = 0;
  uint32_t lost = 0;
  uint32_t pre = 0;
  uint32_t usable = 0;
  unsigned k = 0;
  std::string state;
};

// Returns true and fills *out from the first FECSTAT line in `logs`. False when
// no line parses -- e.g. the format drifted, which is itself worth failing on.
inline bool ParseFecstatLog(const std::vector<std::string>& logs, FecstatLogFields* out) {
  for (const std::string& line : logs) {
    if (line.rfind("FECSTAT sets=", 0) != 0) {
      continue;
    }
    char state[8] = {};
    const int n = std::sscanf(
        line.c_str(),
        "FECSTAT sets=%u expect=%u rx=%u rec=%u late=%u lost=%u pre=%uppm "
        "usable=%uppm -> k=%u state=%7s",
        &out->sets, &out->expect, &out->rx, &out->rec, &out->late, &out->lost,
        &out->pre, &out->usable, &out->k, state);
    if (n == 10) {
      out->state = state;
      return true;
    }
  }
  return false;
}

}  // namespace fcp_test

#endif  // FCP_TESTS_FECSTAT_LOG_H_