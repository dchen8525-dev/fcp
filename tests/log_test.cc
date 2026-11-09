#include <cstring>
#include <string>
#include <vector>

#include "fcp/fecstat.h"
#include "fcp/log_level.h"
#include "fcp/session_log.h"
#include "fcp/strategy.h"
#include "test_util.h"

namespace {

const uint8_t kSalt[8] = {1, 2, 3, 4, 5, 6, 7, 8};

// The tag contract the whole logging path rides on: a four-character prefix
// ([d]/[i]/[w]/[e] + space) maps to a severity, anything else is an untagged
// info line.
void TestTaggedLine() {
  int sev = 0;
  CHECK(fcp::TaggedLine("[d] body", &sev));
  CHECK_EQ(sev, fcp::Severity(fcp::LogLevel::kDebug));
  CHECK(fcp::TaggedLine("[i] body", &sev));
  CHECK_EQ(sev, fcp::Severity(fcp::LogLevel::kInfo));
  CHECK(fcp::TaggedLine("[w] body", &sev));
  CHECK_EQ(sev, fcp::Severity(fcp::LogLevel::kWarn));
  CHECK(fcp::TaggedLine("[e] body", &sev));
  CHECK_EQ(sev, fcp::Severity(fcp::LogLevel::kError));

  // Every structural rejection falls back to info.
  CHECK(!fcp::TaggedLine("[x] body", &sev));   // unknown tag letter
  CHECK_EQ(sev, fcp::Severity(fcp::LogLevel::kInfo));
  CHECK(!fcp::TaggedLine("[i", &sev));         // too short
  CHECK(!fcp::TaggedLine("x]  body", &sev));   // no opening bracket
  CHECK(!fcp::TaggedLine("[i} body", &sev));   // no closing bracket
  CHECK(!fcp::TaggedLine("[ix body", &sev));   // no space after the tag
  CHECK_EQ(sev, fcp::Severity(fcp::LogLevel::kInfo));
}

void TestLineBody() {
  CHECK_EQ(fcp::LineBody("[i] hello"), std::string("hello"));
  CHECK_EQ(fcp::LineBody("plain text"), std::string("plain text"));
  CHECK_EQ(fcp::LineBody("[x] hello"), std::string("[x] hello"));
  CHECK_EQ(fcp::LineBody("[d]"), std::string("[d]"));  // too short to be tagged
}

void TestLevelName() {
  CHECK_EQ(std::string(fcp::LevelName(fcp::Severity(fcp::LogLevel::kDebug))),
           std::string("DEBUG"));
  CHECK_EQ(std::string(fcp::LevelName(fcp::Severity(fcp::LogLevel::kWarn))),
           std::string("WARN"));
  CHECK_EQ(std::string(fcp::LevelName(fcp::Severity(fcp::LogLevel::kError))),
           std::string("ERROR"));
  CHECK_EQ(std::string(fcp::LevelName(fcp::Severity(fcp::LogLevel::kInfo))),
           std::string("INFO"));
  // An unknown severity still renders as something a human can read.
  CHECK_EQ(std::string(fcp::LevelName(7)), std::string("INFO"));
}

void TestWanted() {
  CHECK(fcp::Wanted(fcp::Severity(fcp::LogLevel::kError),
                    fcp::Severity(fcp::LogLevel::kInfo)));
  CHECK(fcp::Wanted(fcp::Severity(fcp::LogLevel::kInfo),
                    fcp::Severity(fcp::LogLevel::kInfo)));
  CHECK(!fcp::Wanted(fcp::Severity(fcp::LogLevel::kDebug),
                     fcp::Severity(fcp::LogLevel::kInfo)));
  CHECK(!fcp::Wanted(fcp::Severity(fcp::LogLevel::kInfo),
                     fcp::Severity(fcp::LogLevel::kOff)));
}

void TestLogStampAndLine() {
  const std::string stamp = fcp::LogStamp();
  // "YYYY-MM-DD HH:MM:SS.mmm" is 23 characters; a failed clock leaves it empty.
  CHECK(stamp.empty() || stamp.size() >= 19);
  const std::string line = fcp::LogLine(fcp::Severity(fcp::LogLevel::kWarn), "text");
  CHECK(line.find(" [WARN] ") != std::string::npos);
  CHECK(line.rfind("text") != std::string::npos);
}

void TestSessionLogLines() {
  std::vector<std::string> lines;
  auto cap = [&lines](const std::string& s) { lines.push_back(s); };

  // A missing sink is a no-op, not a crash.
  fcp::log_fecstat_dropped(fcp::SessionLogFn{}, fcp::FecstatStatus::kBadLength);
  fcp::log_fecstat_untrusted(fcp::SessionLogFn{},
                             fcp::MakeFecstatPacket(kSalt));
  fcp::log_fecstat_too_small(fcp::SessionLogFn{},
                             fcp::MakeFecstatPacket(kSalt));
  fcp::log_fecstat_report(fcp::SessionLogFn{}, fcp::MakeFecstatPacket(kSalt),
                          fcp::FecSampleRates{}, 0, fcp::FecState::kOff);
  fcp::log_fec_ledger(fcp::SessionLogFn{}, fcp::MakeFecstatPacket(kSalt),
                      fcp::FecLedgerView{});
  fcp::log_fec_budget_transitions(fcp::SessionLogFn{}, fcp::FecState::kOn,
                                  fcp::FecState::kCapped, 0.6, 0.5, 3, 0.1);
  CHECK(lines.empty());

  // Every rejection reason has its own word.
  struct Reason {
    fcp::FecstatStatus status;
    const char* word;
  };
  const Reason reasons[] = {
      {fcp::FecstatStatus::kOk, "ok"},
      {fcp::FecstatStatus::kBadLength, "bad_length"},
      {fcp::FecstatStatus::kBadMagic, "bad_magic"},
      {fcp::FecstatStatus::kBadSalt, "bad_salt"},
      {fcp::FecstatStatus::kBadVer, "bad_ver"},
      {fcp::FecstatStatus::kStale, "stale"},
      {fcp::FecstatStatus::kDuplicate, "duplicate"},
  };
  for (const Reason& r : reasons) {
    lines.clear();
    fcp::log_fecstat_dropped(cap, r.status);
    CHECK_EQ(lines.size(), 1u);
    CHECK(lines[0].find("FECSTAT dropped: reason=") != std::string::npos);
    CHECK(lines[0].find(r.word) != std::string::npos);
    CHECK(lines[0].rfind(fcp::kTagDebug, 0) == 0);
  }

  fcp::FecstatPacket stat = fcp::MakeFecstatPacket(kSalt);
  stat.sets_k_unknown = 3;
  stat.sets_expected = 40;
  stat.data_expected = 17;
  stat.data_rx_orig = 11;
  stat.data_recovered_dl = 2;
  stat.data_late_rx = 1;
  stat.ledger_groups = 5;
  stat.ledger_fail_ppm = 250000;
  stat.ledger_meta = 3u | (150u << 16);

  lines.clear();
  fcp::log_fecstat_untrusted(cap, stat);
  fcp::log_fecstat_too_small(cap, stat);
  fcp::log_fecstat_report(cap, stat,
                          fcp::FecSampleRates{4, 120000, 90000}, 3,
                          fcp::FecState::kOn);
  fcp::FecLedgerView view;
  view.k = 3;
  view.p_eff = 0.21;
  view.loss = 0.18;
  view.reports = 9;
  view.skipped = 2;
  fcp::log_fec_ledger(cap, stat, view);
  CHECK_EQ(lines.size(), 4u);
  CHECK(lines[0].find("FEC sample untrusted: k_unknown=3/40") != std::string::npos);
  CHECK(lines[1].find("FEC sample too small: expected=17") != std::string::npos);
  CHECK(lines[2].find("FECSTAT sets=40 expect=17 rx=11 rec=2 late=1 lost=4") !=
        std::string::npos);
  CHECK(lines[2].find("state=ON") != std::string::npos);
  CHECK(lines[3].find("FEC ledger: groups=5 fail=250000ppm") != std::string::npos);
  CHECK(lines[3].find("applied=9 skipped=2") != std::string::npos);

  // The three budget transitions plus the two that must stay silent.
  lines.clear();
  fcp::log_fec_budget_transitions(cap, fcp::FecState::kOn, fcp::FecState::kCapped,
                                  0.60, 0.50, 4, 0.10);
  fcp::log_fec_budget_transitions(cap, fcp::FecState::kCapped, fcp::FecState::kOn,
                                  0.40, 0.50, 2, 0.05);
  fcp::log_fec_budget_transitions(cap, fcp::FecState::kOn, fcp::FecState::kOff,
                                  0.10, 0.50, 1, 0.001);
  const size_t before_silent = lines.size();
  fcp::log_fec_budget_transitions(cap, fcp::FecState::kOff, fcp::FecState::kOn,
                                  0.10, 0.50, 1, 0.001);
  fcp::log_fec_budget_transitions(cap, fcp::FecState::kCapped, fcp::FecState::kOff,
                                  0.10, 0.50, 1, 0.001);
  CHECK_EQ(before_silent, 3u);
  CHECK_EQ(lines.size(), 3u);
  CHECK(lines[0].find("FEC capped: parity/data=60.0% > budget=50.0%") !=
        std::string::npos);
  CHECK(lines[1].find("FEC budget restored: parity/data=40.0% <= budget=50.0%") !=
        std::string::npos);
  CHECK(lines[2].find("FEC off: pre<0.30% for 5 reports") != std::string::npos);
}

}  // namespace

int main() {
  TestTaggedLine();
  TestLineBody();
  TestLevelName();
  TestWanted();
  TestLogStampAndLine();
  TestSessionLogLines();
  return fcp_test::finish();
}
