package client

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/ameshkov/gocurl/internal/config"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// h2PseudoOrderConn rewrites the first client SETTINGS and/or request HEADERS. The forced
// HTTP/2 transport creates one connection per request, so HPACK state is fresh.
// Re-encoded fields are never indexed to avoid diverging dynamic tables.
type h2PseudoOrderConn struct {
	net.Conn
	mu              sync.Mutex
	pending         []byte
	preface         bool
	rewritten       bool
	settingsDone    bool
	streamID        uint32
	endStream       bool
	block           []byte
	order           []string
	headerOrder     []string
	settingsOrder   []uint16
	dataFrameSize   uint32
	headerFrameSize uint32
	framePadding    uint8
	priority        *config.HTTP2Priority
	priorityDone    bool
}

func (c *h2PseudoOrderConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = append(c.pending, p...)
	for {
		if !c.preface {
			if len(c.pending) < len(http2.ClientPreface) {
				return len(p), nil
			}
			if string(c.pending[:len(http2.ClientPreface)]) != http2.ClientPreface {
				return 0, fmt.Errorf("HTTP/2 client preface mismatch")
			}
			if err := writeH2Bytes(c.Conn, c.pending[:len(http2.ClientPreface)]); err != nil {
				return 0, err
			}
			c.pending = c.pending[len(http2.ClientPreface):]
			c.preface = true
		}
		if len(c.pending) < 9 {
			return len(p), nil
		}
		length := int(c.pending[0])<<16 | int(c.pending[1])<<8 | int(c.pending[2])
		if len(c.pending) < 9+length {
			return len(p), nil
		}
		frame := c.pending[:9+length]
		frameType, flags := frame[3], frame[4]
		streamID := binary.BigEndian.Uint32(frame[5:9]) & 0x7fffffff
		if c.streamID != 0 && (frameType != 9 || streamID != c.streamID) {
			return 0, fmt.Errorf("unexpected frame within HTTP/2 HEADERS continuation")
		}
		if err := c.writeFrame(frame, frameType, flags, streamID); err != nil {
			return 0, err
		}
		c.pending = c.pending[9+length:]
	}
}

// Called with c.mu held and a complete frame extracted from c.pending.
func (c *h2PseudoOrderConn) writeFrame(frame []byte, frameType, flags byte, streamID uint32) error {
	if len(c.settingsOrder) != 0 && !c.settingsDone && frameType == 4 && flags&0x1 == 0 {
		reordered, err := reorderH2SettingsFrame(frame, c.settingsOrder)
		if err != nil {
			return err
		}
		if err = writeH2Bytes(c.Conn, reordered); err != nil {
			return err
		}
		c.settingsDone = true
		return nil
	}
	if c.needsHeaderRewrite() && !c.rewritten && (frameType == 1 || c.streamID != 0) {
		return c.writeRequestHeaders(frame, frameType, flags, streamID)
	}
	if c.priority != nil && !c.priorityDone && frameType == 1 {
		if streamID == 0 {
			return fmt.Errorf("invalid stream ID for HTTP/2 request PRIORITY")
		}
		if err := writeH2PriorityFrame(c.Conn, streamID, c.priority); err != nil {
			return err
		}
		c.priorityDone = true
		return writeH2Bytes(c.Conn, frame)
	}
	if frameType == 0 && (c.framePadding != 0 || c.dataFrameSize != 0 && len(frame)-9 > int(c.dataFrameSize)) {
		return c.writeRequestData(frame[9:], flags, streamID)
	}
	return writeH2Bytes(c.Conn, frame)
}

func (c *h2PseudoOrderConn) needsHeaderRewrite() bool {
	return len(c.order) != 0 || len(c.headerOrder) != 0 || c.headerFrameSize != 0 || c.framePadding != 0
}

func (c *h2PseudoOrderConn) writeRequestHeaders(frame []byte, frameType, flags byte, streamID uint32) error {
	if frameType == 1 {
		if streamID == 0 || flags&0x28 != 0 {
			return fmt.Errorf("unsupported HTTP/2 request HEADERS framing")
		}
		c.streamID = streamID
		c.endStream = flags&0x1 != 0
	}
	c.block = append(c.block, frame[9:]...)
	if len(c.block) > 16<<20 {
		return fmt.Errorf("HTTP/2 request HEADERS block is too large")
	}
	if flags&0x4 == 0 {
		return nil
	}
	if c.priority != nil && !c.priorityDone {
		if err := writeH2PriorityFrame(c.Conn, c.streamID, c.priority); err != nil {
			return err
		}
		c.priorityDone = true
	}
	encoded := c.block
	if len(c.order) != 0 || len(c.headerOrder) != 0 {
		var err error
		encoded, err = reorderH2PseudoHeaders(c.block, c.order, c.headerOrder)
		if err != nil {
			return err
		}
	}
	if err := writeH2HeaderBlock(
		c.Conn,
		c.streamID,
		c.endStream,
		encoded,
		c.headerFrameSize,
		c.framePadding,
	); err != nil {
		return err
	}
	c.block = nil
	c.streamID = 0
	c.rewritten = true
	return nil
}

func (c *h2PseudoOrderConn) writeRequestData(payload []byte, flags byte, streamID uint32) error {
	if flags&^byte(0x1) != 0 || streamID == 0 {
		return fmt.Errorf("unsupported HTTP/2 DATA frame flags for padding or fragmentation")
	}
	maxPayload := 16384
	if c.framePadding != 0 {
		maxPayload -= int(c.framePadding) + 1
	}
	if c.dataFrameSize != 0 && int(c.dataFrameSize) < maxPayload {
		maxPayload = int(c.dataFrameSize)
	}
	return writeH2DataFragments(c.Conn, streamID, flags&0x1 != 0, payload, maxPayload, c.framePadding)
}

func writeH2PriorityFrame(conn net.Conn, streamID uint32, priority *config.HTTP2Priority) error {
	if priority == nil || priority.Weight < 1 || priority.Weight > 256 {
		return fmt.Errorf("HTTP/2 priority weight must be in 1..256")
	}
	var wire bytes.Buffer
	framer := http2.NewFramer(&wire, nil)
	if err := framer.WritePriority(streamID, http2.PriorityParam{
		StreamDep: priority.Dependency,
		Exclusive: priority.Exclusive,
		Weight:    uint8(priority.Weight - 1),
	}); err != nil {
		return err
	}
	return writeH2Bytes(conn, wire.Bytes())
}

func writeH2DataFragments(
	conn net.Conn,
	streamID uint32,
	endStream bool,
	data []byte,
	maxPayload int,
	padding uint8,
) error {
	if maxPayload < 1 {
		return fmt.Errorf("HTTP/2 DATA padding leaves no room for data")
	}
	var wire bytes.Buffer
	framer := http2.NewFramer(&wire, nil)
	pad := make([]byte, int(padding))
	if len(data) == 0 {
		if padding == 0 {
			if err := framer.WriteData(streamID, endStream, nil); err != nil {
				return err
			}
		} else if err := framer.WriteDataPadded(streamID, endStream, nil, pad); err != nil {
			return err
		}
		return writeH2Bytes(conn, wire.Bytes())
	}
	for offset := 0; offset < len(data); {
		end := offset + maxPayload
		if end > len(data) {
			end = len(data)
		}
		if padding == 0 {
			if err := framer.WriteData(streamID, endStream && end == len(data), data[offset:end]); err != nil {
				return err
			}
		} else if err := framer.WriteDataPadded(streamID, endStream && end == len(data), data[offset:end], pad); err != nil {
			return err
		}
		offset = end
	}
	return writeH2Bytes(conn, wire.Bytes())
}

func reorderH2SettingsFrame(frame []byte, order []uint16) ([]byte, error) {
	if len(frame) < 9 || frame[3] != 4 || frame[4] != 0 ||
		binary.BigEndian.Uint32(frame[5:9]) != 0 || (len(frame)-9)%6 != 0 {
		return nil, fmt.Errorf("invalid initial HTTP/2 SETTINGS frame")
	}
	entries := map[uint16][]byte{}
	original := make([]uint16, 0, (len(frame)-9)/6)
	for offset := 9; offset < len(frame); offset += 6 {
		id := binary.BigEndian.Uint16(frame[offset : offset+2])
		if _, exists := entries[id]; exists {
			return nil, fmt.Errorf("duplicate HTTP/2 SETTINGS ID %d", id)
		}
		entries[id] = frame[offset : offset+6]
		original = append(original, id)
	}
	result := append([]byte(nil), frame[:9]...)
	used := map[uint16]bool{}
	for _, id := range order {
		entry, ok := entries[id]
		if !ok {
			return nil, fmt.Errorf("requested HTTP/2 SETTINGS ID %d is not advertised by the transport", id)
		}
		result = append(result, entry...)
		used[id] = true
	}
	for _, id := range original {
		if !used[id] {
			result = append(result, entries[id]...)
		}
	}
	return result, nil
}

func writeH2Bytes(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func reorderH2PseudoHeaders(block []byte, order, headerOrder []string) ([]byte, error) {
	fields, err := hpack.NewDecoder(4096, nil).DecodeFull(block)
	if err != nil {
		return nil, fmt.Errorf("decode HTTP/2 request HEADERS: %w", err)
	}
	pseudo := make(map[string]hpack.HeaderField, 4)
	var originalPseudo []string
	regular := make([]hpack.HeaderField, 0, len(fields))
	for _, field := range fields {
		if len(field.Name) > 0 && field.Name[0] == ':' {
			if _, exists := pseudo[field.Name]; exists {
				return nil, fmt.Errorf("duplicate HTTP/2 pseudo-header %q", field.Name)
			}
			pseudo[field.Name] = field
			originalPseudo = append(originalPseudo, field.Name)
		} else {
			regular = append(regular, field)
		}
	}
	if len(order) == 0 {
		order = originalPseudo
	} else if len(pseudo) != len(order) {
		return nil, fmt.Errorf("HTTP/2 request pseudo-headers do not match requested order")
	}
	var encoded bytes.Buffer
	encoder := hpack.NewEncoder(&encoded)
	for _, name := range order {
		field, ok := pseudo[name]
		if !ok {
			return nil, fmt.Errorf("HTTP/2 request missing pseudo-header %q", name)
		}
		field.Sensitive = true
		if err := encoder.WriteField(field); err != nil {
			return nil, err
		}
	}
	prioritized := make(map[string]bool, len(headerOrder))
	for _, name := range headerOrder {
		for _, field := range regular {
			if field.Name == name {
				field.Sensitive = true
				if err := encoder.WriteField(field); err != nil {
					return nil, err
				}
			}
		}
		prioritized[name] = true
	}
	for _, field := range regular {
		if prioritized[field.Name] {
			continue
		}
		field.Sensitive = true
		if err := encoder.WriteField(field); err != nil {
			return nil, err
		}
	}
	return encoded.Bytes(), nil
}

func writeH2HeaderBlock(
	conn net.Conn,
	streamID uint32,
	endStream bool,
	block []byte,
	maxFragment uint32,
	padding uint8,
) error {
	var wire bytes.Buffer
	framer := http2.NewFramer(&wire, nil)
	if maxFragment == 0 {
		maxFragment = 16384
	}
	firstFragmentLimit := int(maxFragment) - int(padding)
	if padding != 0 {
		firstFragmentLimit-- // HEADERS payload includes the Pad Length byte.
	}
	if firstFragmentLimit < 1 {
		return fmt.Errorf("HTTP/2 HEADERS padding leaves no room for the header block")
	}
	first := len(block)
	if first > firstFragmentLimit {
		first = firstFragmentLimit
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: streamID, BlockFragment: block[:first],
		EndStream: endStream, EndHeaders: first == len(block), PadLength: padding,
	}); err != nil {
		return err
	}
	for offset := first; offset < len(block); {
		end := offset + int(maxFragment)
		if end > len(block) {
			end = len(block)
		}
		if err := framer.WriteContinuation(streamID, end == len(block), block[offset:end]); err != nil {
			return err
		}
		offset = end
	}
	return writeH2Bytes(conn, wire.Bytes())
}
