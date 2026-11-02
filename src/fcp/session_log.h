// FECSTAT-related log lines (session.cc stage-2 split).
//
// The format strings here are load-bearing: adv_test's ten probes match the
// session log character by character, so these are copies of the lines that
// used to sit inline in Session::on_oob, punctuation included. They live in
// their own translation unit so on_oob() reads as dispatch (validate -> feed
// the strategy -> report what happened) instead of nine snprintf blocks.
//
// Every function takes the caller's LogFn rather than a Session; nothing here
// touches session state.

#ifndef FCP_SESSION_LOG_H_
#define FCP_SESSION_LOG_H_

#include <cstdint>
#include <functional>
#include <string>

#include "fcp/fecstat.h"
#include "fcp/strategy.h"

namespace fcp {

using SessionLogFn = std::function<void(const std::string& line)>;

// Rates derived from one report, as printed on the FECSTAT line. Computed by
// the caller because they are also kept as session state (last_pre_ppm_ /
// last_usable_ppm_).
struct FecSampleRates {
  uint32_t lost = 0;
  uint32_t pre_ppm = 0;
  uint32_t usable_ppm = 0;
};

// Strategy-side values that only the ledger line needs.
struct FecLedgerView {
  uint8_t k = 0;
  double p_eff = 0.0;   // strategy last_p_eff()
  double loss = 0.0;    // strategy last_loss()
  uint32_t reports = 0;  // ledger_reports()
  uint32_t skipped = 0;  // ledger_skipped()
};

// "FECSTAT dropped: reason=<why> count=1"
void log_fecstat_dropped(const SessionLogFn& log, FecstatStatus status);

// "FEC sample untrusted: k_unknown=<n>/<sets> (>10%%)"
void log_fecstat_untrusted(const SessionLogFn& log, const FecstatPacket& stat);

// "FEC sample too small: expected=<n>"
void log_fecstat_too_small(const SessionLogFn& log, const FecstatPacket& stat);

// The per-report summary line (§10 format, kept verbatim).
void log_fecstat_report(const SessionLogFn& log, const FecstatPacket& stat,
                        const FecSampleRates& rates, uint8_t k, FecState state);

// "FEC ledger: ..." (M3 R(k) correction).
void log_fec_ledger(const SessionLogFn& log, const FecstatPacket& stat,
                    const FecLedgerView& view);

// The three byte-budget transitions of one report (§2). `ratio` is the
// interval's parity/data ratio, `budget` the configured ceiling.
void log_fec_budget_transitions(const SessionLogFn& log, FecState before, FecState after,
                                double ratio, double budget, uint8_t k, double last_loss);

}  // namespace fcp

#endif  // FCP_SESSION_LOG_H_
