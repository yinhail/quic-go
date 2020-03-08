package qlog

import (
	"fmt"
	"strconv"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

func toString(i int64) string {
	return strconv.FormatInt(i, 10)
}

type versionNumber protocol.VersionNumber

func (v versionNumber) String() string {
	return fmt.Sprintf("%x", uint32(v))
}

type streamType protocol.StreamType

func (s streamType) String() string {
	switch protocol.StreamType(s) {
	case protocol.StreamTypeUni:
		return "unidirectional"
	case protocol.StreamTypeBidi:
		return "bidirectional"
	default:
		panic("unknown stream type")
	}
}

type connectionID protocol.ConnectionID

func (c connectionID) String() string {
	return fmt.Sprintf("%x", []byte(c))
}

// category is the qlog event category.
type category uint8

const (
	categoryConnectivity category = iota
	categoryTransport
	categorySecurity
	categoryRecovery
)

func (c category) String() string {
	switch c {
	case categoryConnectivity:
		return "connectivity"
	case categoryTransport:
		return "transport"
	case categorySecurity:
		return "security"
	case categoryRecovery:
		return "recovery"
	default:
		panic("unknown category")
	}
}

// PacketType is the packet type of a QUIC packet
type PacketType protocol.PacketType

const (
	// PacketTypeInitial: Initial packet
	PacketTypeInitial PacketType = iota
	// PacketTypeHandshake: Handshake packet
	PacketTypeHandshake
	// PacketTypeRetry: Retry packet
	PacketTypeRetry
	// PacketType0RTT: 0-RTT packet
	PacketType0RTT
	// PacketTypeVersionNegotiation: Version Negotiation packet
	PacketTypeVersionNegotiation
	// PacketType1RTT: 1-RTT packet
	PacketType1RTT
)

func (t PacketType) String() string {
	switch t {
	case PacketTypeInitial:
		return "initial"
	case PacketTypeHandshake:
		return "handshake"
	case PacketTypeRetry:
		return "retry"
	case PacketType0RTT:
		return "0RTT"
	case PacketTypeVersionNegotiation:
		return "version_negotiation"
	case PacketType1RTT:
		return "1RTT"
	default:
		panic("unknown packet type")
	}
}

type PacketLossReason uint8

const (
	// PacketLossReorderingThreshold: when a packet is deemed lost due to reordering threshold
	PacketLossReorderingThreshold PacketLossReason = iota
	// PacketLossTimeThreshold: when a packet is deemed lost due to time threshold
	PacketLossTimeThreshold
)

func (r PacketLossReason) String() string {
	switch r {
	case PacketLossReorderingThreshold:
		return "reordering_threshold"
	case PacketLossTimeThreshold:
		return "time_threshold"
	default:
		panic("unknown loss reason")
	}
}

type PacketDropReason uint8

const (
	// PacketDropKeyUnavailable: when a packet is dropped because keys are unavailable
	PacketDropKeyUnavailable PacketDropReason = iota
	// PacketDropUnknownConnectionID: when a packet is dropped because the connection ID is unknown
	PacketDropUnknownConnectionID
	// PacketDropHeaderParseError: when a packet is dropped because header parsing failed
	PacketDropHeaderParseError
	// PacketDropPayloadDecryptError: when a packet is dropped because decrypting the payload failed
	PacketDropPayloadDecryptError
	// PacketDropProtocolViolation: when a packet is dropped due to a protocol violation
	PacketDropProtocolViolation
	// PacketDropDOSPrevention: when a packet is dropped to mitigate a DoS attack
	PacketDropDOSPrevention
	// PacketDropUnsupportedVersion: when a packet is dropped because the version is not supported
	PacketDropUnsupportedVersion
)

func (r PacketDropReason) String() string {
	switch r {
	case PacketDropKeyUnavailable:
		return "key_unavailable"
	case PacketDropUnknownConnectionID:
		return "unknown_connection_id"
	case PacketDropHeaderParseError:
		return "header_parse_error"
	case PacketDropPayloadDecryptError:
		return "payload_decrypt_error"
	case PacketDropProtocolViolation:
		return "protocol_violation"
	case PacketDropDOSPrevention:
		return "dos_prevention"
	case PacketDropUnsupportedVersion:
		return "unsupported_version"
	default:
		panic("unknown packet drop reason")
	}
}
