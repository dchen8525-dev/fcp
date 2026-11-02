#include "fcp/session_log.h"

#include <cstdio>

#include "fcp/strategy.h"  // FecState and fec_state_name()

namespace fcp {
namespace {

// Verbatim from the pre-split session.cc; the words are part of the log
// contract adv_test matches on.
const char* fecstat_reason(FecstatStatus status) {
  switch (status) {
    case FecstatStatus::kOk:
      return "ok";
    case FecstatStatus::kBadLength:
      return "bad_length";
    case FecstatStatus::kBadMagic:
      return "bad_magic";
    case FecstatStatus::kBadSalt:
      return "bad_salt";
    case FecstatStatus::kBadVer:
      return "bad_ver";
    case FecstatStatus::kStale:
      return "stale";
    case FecstatStatus::kDuplicate:
      return "duplicate";
  }
  return "unknown";
}

}  // namespace

void log_fecstat_dropped(const SessionLogFn& log, FecstatStatus status) {
  if (!log) {
    return;
  }
  char line[96];
  std::snprintf(line, sizeof(line), "FECSTAT dropped: reason=%s count=1",
                fecstat_reason(status));
  log(line);
}

void log_fecstat_untrusted(const SessionLogFn& log, const FecstatPacket& stat) {
  if (!log) {
    return;
  }
  char line[96];
  std::snprintf(line, sizeof(line), "FEC sample untrusted: k_unknown=%u/%u (>10%%)",
                stat.sets_k_unknown, stat.sets_expected);
  log(line);
}

void log_fecstat_too_small(const SessionLogFn& log, const FecstatPacket& stat) {
  if (!log) {
    return;
  }
  char line[96];
  std::snprintf(line, sizeof(line), "FEC sample too small: expected=%u",
                stat.data_expected);
  log(line);
}

void log_fecstat_report(const SessionLogFn& log, const FecstatPacket& stat,
                        const FecSampleRates& rates, uint8_t k, FecState state) {
  if (!log) {
    return;
  }
  char line[512];
  std::snprintf(line, sizeof(line),
                "FECSTAT sets=%u expect=%u rx=%u rec=%u late=%u lost=%u pre=%uppm "
                "usable=%uppm -> k=%u state=%s",
                stat.sets_expected, stat.data_expected, stat.data_rx_orig,
                stat.data_recovered_dl, stat.data_late_rx, rates.lost, rates.pre_ppm,
                rates.usable_ppm, k, fec_state_name(state));
  log(line);
}

void log_fec_ledger(const SessionLogFn& log, const FecstatPacket& stat,
                    const FecLedgerView& view) {
  if (!log) {
    return;
  }
  char line[512];
  std::snprintf(line, sizeof(line),
                "FEC ledger: groups=%u fail=%uppm k=%u peff=%.4f "
                "(binomial %.4f) kl=%.2f applied=%u skipped=%u",
                stat.ledger_groups, stat.ledger_fail_ppm, ledger_k(stat), view.p_eff,
                view.loss, ledger_burst_kl(stat) / 100.0, view.reports, view.skipped);
  log(line);
}

void log_fec_budget_transitions(const SessionLogFn& log, FecState before, FecState after,
                                double ratio, double budget, uint8_t k, double last_loss) {
  if (!log) {
    return;
  }
  char line[512];
  if (before != FecState::kCapped && after == FecState::kCapped) {
    std::snprintf(line, sizeof(line),
                  "FEC capped: parity/data=%.1f%% > budget=%.1f%% (k=%u)",
                  ratio * 100.0, budget * 100.0, k);
    log(line);
  } else if (before == FecState::kCapped && after == FecState::kOn) {
    std::snprintf(line, sizeof(line),
                  "FEC budget restored: parity/data=%.1f%% <= budget=%.1f%% (k=%u)",
                  ratio * 100.0, budget * 100.0, k);
    log(line);
  }
  if (before == FecState::kOn && after == FecState::kOff) {
    std::snprintf(line, sizeof(line),
                  "FEC off: pre<0.30%% for 5 reports (last %.2f%%)",
                  last_loss * 100.0);
    log(line);
  }
}

}  // namespace fcp
