package wire

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

func TestReorderTransportParametersKeepsGreaseAndUnlistedOrder(t *testing.T) {
	var encoded []byte
	for _, item := range []struct {
		id    uint64
		value byte
	}{
		{id: 58, value: 0xaa}, // QUIC grease parameter
		{id: 5, value: 0x55},
		{id: 4, value: 0x44},
		{id: 1, value: 0x11},
		{id: 7, value: 0x77},
	} {
		encoded = quicvarint.Append(encoded, item.id)
		encoded = quicvarint.Append(encoded, 1)
		encoded = append(encoded, item.value)
	}

	ordered := reorderTransportParameters(encoded, []uint64{4, 1})
	var gotIDs []uint64
	for len(ordered) > 0 {
		id, idLen, err := quicvarint.Parse(ordered)
		if err != nil {
			t.Fatal(err)
		}
		valueLen, valueLenLen, err := quicvarint.Parse(ordered[idLen:])
		if err != nil {
			t.Fatal(err)
		}
		entryLen := idLen + valueLenLen + int(valueLen)
		gotIDs = append(gotIDs, id)
		ordered = ordered[entryLen:]
	}
	if want := []uint64{58, 4, 1, 5, 7}; len(gotIDs) != len(want) {
		t.Fatalf("ordered IDs = %v, want %v", gotIDs, want)
	} else {
		for i := range want {
			if gotIDs[i] != want[i] {
				t.Fatalf("ordered IDs = %v, want %v", gotIDs, want)
			}
		}
	}
}

func TestTransportParametersMarshalUsesConfiguredOrder(t *testing.T) {
	params := &TransportParameters{
		InitialMaxData:          1234,
		MaxIdleTimeout:          5_000_000_000,
		TransportParameterOrder: []uint64{4, 1},
	}
	encoded := params.Marshal(protocol.PerspectiveClient)
	var gotIDs []uint64
	for len(encoded) > 0 {
		id, idLen, err := quicvarint.Parse(encoded)
		if err != nil {
			t.Fatal(err)
		}
		valueLen, valueLenLen, err := quicvarint.Parse(encoded[idLen:])
		if err != nil {
			t.Fatal(err)
		}
		entryLen := idLen + valueLenLen + int(valueLen)
		gotIDs = append(gotIDs, id)
		encoded = encoded[entryLen:]
	}
	if len(gotIDs) < 3 || gotIDs[1] != 4 || gotIDs[2] != 1 {
		t.Fatalf("marshaled parameter order = %v, want grease followed by [4 1]", gotIDs)
	}
}

func TestTransportParametersMarshalPreservesExplicitZeroValues(t *testing.T) {
	params := &TransportParameters{
		InitialMaxStreamDataBidiLocal:  0,
		InitialMaxStreamDataBidiRemote: 0,
		InitialMaxStreamDataUni:        0,
		InitialMaxData:                 0,
		AckDelayExponent:               0,
		MaxAckDelay:                    0,
	}
	encoded := params.Marshal(protocol.PerspectiveClient)
	expectedIDs := map[uint64]bool{
		uint64(initialMaxStreamDataBidiLocalParameterID):  true,
		uint64(initialMaxStreamDataBidiRemoteParameterID): true,
		uint64(initialMaxStreamDataUniParameterID):        true,
		uint64(initialMaxDataParameterID):                 true,
		uint64(ackDelayExponentParameterID):               true,
		uint64(maxAckDelayParameterID):                    true,
	}
	values := make(map[uint64]uint64)
	for len(encoded) > 0 {
		id, idLen, err := quicvarint.Parse(encoded)
		if err != nil {
			t.Fatalf("parse transport parameter ID: %v", err)
		}
		valueLen, valueLenLen, err := quicvarint.Parse(encoded[idLen:])
		if err != nil {
			t.Fatalf("parse transport parameter length: %v", err)
		}
		valueStart := idLen + valueLenLen
		if valueLen > uint64(len(encoded)-valueStart) {
			t.Fatalf("transport parameter %d length %d exceeds remaining bytes %d", id, valueLen, len(encoded)-valueStart)
		}
		if expectedIDs[id] {
			valueBytes := encoded[valueStart : valueStart+int(valueLen)]
			value, valueSize, err := quicvarint.Parse(valueBytes)
			if err != nil || valueSize != len(valueBytes) {
				t.Fatalf("parse value for transport parameter %d: value=%d bytes=%d error=%v", id, valueSize, len(valueBytes), err)
			}
			values[id] = value
		}
		encoded = encoded[valueStart+int(valueLen):]
	}

	for _, id := range []uint64{
		uint64(initialMaxStreamDataBidiLocalParameterID),
		uint64(initialMaxStreamDataBidiRemoteParameterID),
		uint64(initialMaxStreamDataUniParameterID),
		uint64(initialMaxDataParameterID),
		uint64(ackDelayExponentParameterID),
		uint64(maxAckDelayParameterID),
	} {
		if value, ok := values[id]; !ok || value != 0 {
			t.Errorf("transport parameter %d = %d, present %t; want explicitly encoded zero", id, value, ok)
		}
	}
}
