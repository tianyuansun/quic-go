package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// A PingFrame is a PING frame
type PingFrame struct{}

func (f *PingFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	b.WriteByte(0x1)
	return nil
}

// Length of a written frame
func (f *PingFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	return 1
}
