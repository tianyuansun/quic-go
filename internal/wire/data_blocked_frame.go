package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

// A DataBlockedFrame is a DATA_BLOCKED frame
type DataBlockedFrame struct {
	MaximumData protocol.ByteCount
}

func parseDataBlockedFrame(r *bytes.Reader, _ protocol.VersionNumber) (*DataBlockedFrame, error) {
	offset, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	return &DataBlockedFrame{
		MaximumData: protocol.ByteCount(offset),
	}, nil
}

func (f *DataBlockedFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	b.WriteByte(0x14)
	quicvarint.Write(b, uint64(f.MaximumData))
	return nil
}

// Length of a written frame
func (f *DataBlockedFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	return 1 + quicvarint.Len(uint64(f.MaximumData))
}
