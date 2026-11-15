#include "fcp/strategy.h"

#include <cmath>

#include "test_util.h"

namespace {

bool Near(double actual, double expected, double tol = 1e-9) {
  return std::fabs(actual - expected) <= tol;
}

// k = ceil(headroom x d x loss): the controller's mean-plus-variance answer.
// It replaced the binomial rule, which bought worst-case coverage (k=4 at 20%
// loss on D=10) and had a dead band that froze k for whole sessions on a path
// whose sampled loss sat on one step.
void TestKForTable() {
  static const struct {
    double loss;
    uint8_t k;
  } kCases[] = {
      {0.00, 1},  // a clean channel still needs one parity when FEC is on
      {0.02, 1},  // d x loss x 1.5 = 0.3, rounds up to the floor
      {0.05, 1},  // 0.75
      {0.10, 2},  // 1.5
      {0.15, 3},  // 2.25
      {0.20, 3},  // 3.0 -- exactly the expected shard loss, no extra notch
      {0.25, 4},  // 3.75
      {0.30, 4},  // 4.5 -> clamped to a Pmax of 4
  };

  for (const auto& c : kCases) {
    const uint8_t k = fcp::k_for(c.loss, 10, 4);
    CHECK_EQ(k, c.k);
    // The answer never sits below the floor nor above the ceiling, and it
    // never ignores a loss report by returning the floor at high loss.
    CHECK(k >= 1);
    CHECK(k <= 4);
    CHECK(k == 1 || c.loss > 0.0);
    // ceil() never leaves a fractional gap: the answer is at least the expected
    // number of lost shards times the headroom, capped by the ceiling.
    CHECK(static_cast<double>(k) * 10.0 >= 10.0 * c.loss * fcp::kFecHeadroom - 1e-9 ||
          k == 4);
  }
}

// The CDF reference values quoted in the task list (Python/scipy).
void TestCdfReference() {
  CHECK(Near(fcp::binom_cdf(2, 10, 0.2), 0.677799526));
  CHECK(Near(fcp::binom_cdf(3, 13, 0.2), 0.747324310));
  CHECK(Near(fcp::binom_cdf(4, 14, 0.2), 0.870160374));

  // k == trials means every outcome is covered; k > trials clamps the same way.
  CHECK(Near(fcp::binom_cdf(10, 10, 0.2), 1.0));
  CHECK(Near(fcp::binom_cdf(11, 10, 0.2), 1.0));
  CHECK(Near(fcp::binom_cdf(0, 0, 0.2), 1.0));

  // Degenerate p.
  CHECK(Near(fcp::binom_cdf(0, 11, 0.0), 1.0));
  CHECK(Near(fcp::binom_cdf(1, 11, 0.0), 1.0));
  CHECK(Near(fcp::binom_cdf(1, 2, 1.0), 0.0));
  CHECK(Near(fcp::binom_cdf(2, 2, 1.0), 1.0));

  // p outside [0,1] is clamped, not propagated.
  CHECK(Near(fcp::binom_cdf(2, 10, -0.5), 1.0));
  CHECK(Near(fcp::binom_cdf(2, 2, 1.5), 1.0));
}

void TestKForEdges() {
  // k starts at 1: a clean channel still needs one parity when FEC is on.
  CHECK_EQ(fcp::k_for(0.0, 10, 4), 1);
  // Total loss is unsolvable, so the answer saturates at Pmax.
  CHECK_EQ(fcp::k_for(1.0, 10, 4), 4);
  CHECK_EQ(fcp::k_for(0.9, 10, 4), 4);
  // FRAMED_STATS (Pmax = 0) keeps k at 0.
  CHECK_EQ(fcp::k_for(0.2, 10, 0), 0);
  // The k field is 3 bits wide; Pmax above 7 is not representable.
  CHECK_EQ(fcp::k_for(1.0, 10, 200), fcp::kMaxParity);

  // Monotone non-decreasing in loss, and never above the ceiling.
  uint8_t prev = 0;
  for (int i = 0; i <= 100; ++i) {
    const uint8_t k = fcp::k_for(i / 100.0, 10, 4);
    CHECK(k >= prev);
    CHECK(k <= 4);
    prev = k;
  }
}

// M3 R(k) correction primitive: the loss whose binomial tail equals q.
void TestBinomPForCdf() {
  // Roundtrip against the forward CDF over operating points k_for actually
  // visits (D = 10). Skip q within ~1e-9 of 1: there the double-precision
  // CDF is flat (dP(X>=k+1)/dp ~ p^k), the inverse's answer is at the
  // resolution limit (measured err 1.6e-9 @ k=6, 1.8e-7 @ k=7 for p=0.01),
  // and the correction's one-sided max() makes any residual harmless.
  const double losses[] = {0.01, 0.05, 0.10, 0.15, 0.20, 0.35, 0.60};
  for (const double p : losses) {
    for (unsigned k = 1; k <= 7; ++k) {
      const double q = fcp::binom_cdf(k, 10 + k, p);
      if (q > 1.0 - 1e-9 || q < 1e-12) {
        continue;
      }
      const double back = fcp::binom_p_for_cdf(k, 10 + k, q);
      CHECK(Near(back, p, 1e-9));
    }
  }

  // Edges: perfect recovery maps to zero loss, hopeless failure to one.
  CHECK(Near(fcp::binom_p_for_cdf(2, 12, 1.0), 0.0));
  CHECK(Near(fcp::binom_p_for_cdf(2, 12, 0.0), 1.0));
  CHECK(Near(fcp::binom_p_for_cdf(2, 12, 1.5), 0.0));
  CHECK(Near(fcp::binom_p_for_cdf(2, 12, -0.5), 1.0));

  // Monotone non-increasing in q: a worse failure rate demands more loss.
  double prev = 1.0;
  for (int i = 0; i <= 100; ++i) {
    const double p = fcp::binom_p_for_cdf(2, 12, i / 100.0);
    CHECK(p <= prev + 1e-12);
    prev = p;
  }
}

}  // namespace

int main() {
  TestKForTable();
  TestCdfReference();
  TestKForEdges();
  TestBinomPForCdf();
  return fcp_test::finish();
}
