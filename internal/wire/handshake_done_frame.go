package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// A HandshakeDoneFrame is a HANDSHAKE_DONE frame
type HandshakeDoneFrame struct{}

func (f *HandshakeDoneFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	b.WriteByte(0x1e)
	return nil
}

// Length of a written frame
func (f *HandshakeDoneFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	return 1
}
