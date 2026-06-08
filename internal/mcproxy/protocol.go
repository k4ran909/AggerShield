// Package mcproxy is a protocol-aware TCP proxy for Minecraft (Java edition).
//
// The Minecraft protocol frames every packet as: VarInt length, then that
// many bytes of payload. The very first packet a client sends is the
// Handshake (packet id 0x00):
//
//	VarInt  protocol version
//	String  server address (VarInt length + UTF-8)
//	u16     server port
//	VarInt  next state   (1 = status/ping, 2 = login)
//
// We parse exactly this first packet to make a decision, then splice the TCP
// streams together. Parsing the handshake lets us drop malformed/abusive
// connections (ping floods, bot-join floods, junk) before they reach the
// game server.
package mcproxy

import (
	"errors"
	"io"
)

const (
	stateStatus = 1
	stateLogin  = 2

	maxVarIntBytes = 5
	maxPacketBytes = 2048 // a legit handshake is tiny; cap to bound memory
)

var (
	errVarIntTooBig = errors.New("mcproxy: VarInt too big")
	errPacketTooBig = errors.New("mcproxy: handshake packet too large")
	errBadPacket    = errors.New("mcproxy: malformed handshake")
)

// handshake holds the fields we care about.
type handshake struct {
	protocol  int
	address   string
	port      uint16
	nextState int
}

// readVarInt reads a Minecraft VarInt from r, returning the value and the raw
// bytes consumed (so the caller can replay them to the upstream).
func readVarInt(r io.Reader) (value int, raw []byte, err error) {
	var b [1]byte
	for i := 0; i < maxVarIntBytes; i++ {
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return 0, raw, err
		}
		raw = append(raw, b[0])
		value |= int(b[0]&0x7F) << (7 * i)
		if b[0]&0x80 == 0 {
			return value, raw, nil
		}
	}
	return 0, raw, errVarIntTooBig
}

// readHandshake reads exactly the first (handshake) packet from r without
// over-reading subsequent packets. It returns the parsed fields plus the raw
// bytes of the whole packet (length prefix + payload) for replay upstream.
func readHandshake(r io.Reader) (*handshake, []byte, error) {
	length, lenRaw, err := readVarInt(r)
	if err != nil {
		return nil, nil, err
	}
	if length <= 0 || length > maxPacketBytes {
		return nil, nil, errPacketTooBig
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, err
	}
	raw := append(append([]byte{}, lenRaw...), payload...)

	c := &cursor{b: payload}
	pktID, err := c.varInt()
	if err != nil || pktID != 0x00 {
		return nil, raw, errBadPacket
	}
	hs := &handshake{}
	if hs.protocol, err = c.varInt(); err != nil {
		return nil, raw, errBadPacket
	}
	if hs.address, err = c.str(); err != nil {
		return nil, raw, errBadPacket
	}
	if hs.port, err = c.u16(); err != nil {
		return nil, raw, errBadPacket
	}
	if hs.nextState, err = c.varInt(); err != nil {
		return nil, raw, errBadPacket
	}
	if hs.nextState != stateStatus && hs.nextState != stateLogin {
		return nil, raw, errBadPacket
	}
	return hs, raw, nil
}

// cursor is a bounds-checked reader over an in-memory byte slice.
type cursor struct {
	b []byte
	i int
}

func (c *cursor) varInt() (int, error) {
	var value int
	for n := 0; n < maxVarIntBytes; n++ {
		if c.i >= len(c.b) {
			return 0, errBadPacket
		}
		bv := c.b[c.i]
		c.i++
		value |= int(bv&0x7F) << (7 * n)
		if bv&0x80 == 0 {
			return value, nil
		}
	}
	return 0, errVarIntTooBig
}

func (c *cursor) str() (string, error) {
	n, err := c.varInt()
	if err != nil {
		return "", err
	}
	if n < 0 || c.i+n > len(c.b) {
		return "", errBadPacket
	}
	s := string(c.b[c.i : c.i+n])
	c.i += n
	return s, nil
}

func (c *cursor) u16() (uint16, error) {
	if c.i+2 > len(c.b) {
		return 0, errBadPacket
	}
	v := uint16(c.b[c.i])<<8 | uint16(c.b[c.i+1])
	c.i += 2
	return v, nil
}
