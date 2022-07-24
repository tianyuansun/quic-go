package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

// An ImmediateAckFrame is an IMMEDIATE_ACK frame
type ImmediateAckFrame struct{}

func parseImmediateAckFrame(r *bytes.Reader, _ protocol.VersionNumber) (*ImmediateAckFrame, error) {
	if _, err := quicvarint.Read(r); err != nil {
		return nil, err
	}
	return &ImmediateAckFrame{}, nil
}

func (f *ImmediateAckFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	quicvarint.Write(b, 0xac)
	return nil
}

// Length of a written frame
func (f *ImmediateAckFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	return 2
}
