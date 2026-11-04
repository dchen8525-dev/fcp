// Path-MTU discovery, upward only (protocol capability kCapPmtud).
//
// The configured MTU is what the operator knows the path can carry, and a
// session never sends anything larger until the path proves it can. A probe is
// an ordinary oob frame: it rides the same AEAD envelope, carries a 16-byte
// header and zero padding out to the candidate IP size. The ack is evidence
// that the datagram actually arrived at that size -- the receiver compares the
// envelope length against the advertised number before answering -- so a
// black-holed probe (the usual failure mode of an MTU that is one step too
// large) simply never gets an ack.
//
// Two independent bounds move as a result:
//   * receive: accepts data/parity symbols up to the probed size once the probe
//     itself arrived. It must move first: its ack is what tells the peer to
//     start sending larger symbols.
//   * send: raises payload_max when the matching ack comes back.
// A path can be asymmetric, so each direction proves itself. Sizes only ever
// grow; a session never lowers a bound that is already in use.
//
// For the ack to mean anything the socket must set DF (reactor.cc): without it
// a router fragments the oversized probe instead of dropping it, the probe
// arrives, and the session raises its MTU to a size the path cannot carry
// whole.

#ifndef FCP_PMTU_H_
#define FCP_PMTU_H_

#include <cstddef>
#include <cstdint>

#include "fcp/envelope.h"
#include "fcp/hdr.h"

namespace fcp {

constexpr size_t kPmtuMagicLen = 8;
constexpr char kPmtuMagic[] = "FCP_PMTU";
// magic8 | type1 | reserved1 | token4 (LE) | mtu2 (LE)
constexpr size_t kPmtuHeaderLen = 16;
constexpr uint8_t kPmtuProbe = 0;
constexpr uint8_t kPmtuAck = 1;
// Hard ceiling independent of configuration: an authenticated peer must not be
// able to make the receive path accept (and buffer) a datagram beyond a jumbo
// frame, whatever its own config says.
constexpr uint16_t kPmtuAbsoluteMaxMtu = 9000;

struct PmtuMessage {
  uint8_t type = 0;
  uint32_t token = 0;
  uint16_t mtu = 0;
};

// UDP payload length of an IP datagram of `mtu` bytes: the number the envelope
// sees. 0 when the MTU cannot carry the IP/UDP headers.
constexpr size_t pmtu_udp_payload(size_t mtu, size_t ip_hdr_len) {
  return mtu > ip_hdr_len + 8 ? mtu - ip_hdr_len - 8 : 0;
}

// oob payload length (header + zero padding) that makes the datagram exactly
// `mtu` bytes on the wire. 0 when the size cannot carry the header.
constexpr size_t pmtu_probe_len(size_t mtu, size_t ip_hdr_len) {
  const size_t udp = pmtu_udp_payload(mtu, ip_hdr_len);
  const size_t need = Envelope::kOverhead + kFecHdrLen + kPmtuHeaderLen;
  return udp >= need ? udp - Envelope::kOverhead - kFecHdrLen : 0;
}

// False for anything that is not a well-formed PMTU message (wrong magic, an
// unknown type, or a truncated header). The caller treats false as "not ours"
// and keeps routing.
bool pmtu_parse(const uint8_t* payload, size_t len, PmtuMessage* out);

// Writes the header and zero-fills the padding up to `out_len` (which must be
// at least kPmtuHeaderLen). `out_len` is what sets the datagram size, so the
// probe path passes pmtu_probe_len() and the ack path passes
// kPmtuHeaderLen.
void pmtu_build(const PmtuMessage& msg, uint8_t* out, size_t out_len);

}  // namespace fcp

#endif  // FCP_PMTU_H_
