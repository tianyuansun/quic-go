package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

// An ImmediateAckFrame is an IMMEDIATE_ACK frame
type ImmediateAckFrame struct{}

func (f *ImmediateAckFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	quicvarint.Write(b, 0xac)
	return nil
}

// Length of a written frame
func (f *ImmediateAckFrame) Length(protocol.VersionNumber) protocol.ByteCount {
	return 2
}
