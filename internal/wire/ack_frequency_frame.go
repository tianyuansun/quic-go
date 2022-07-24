package wire

import (
	"bytes"
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

type AckFrequencyFrame struct {
	SequenceNumber    uint64
	Threshold         uint64
	UpdateMaxAckDelay time.Duration
	IgnoreCE          bool
	IgnoreOrder       bool
}

func parseAckFrequencyFrame(r *bytes.Reader, _ protocol.VersionNumber) (*AckFrequencyFrame, error) {
	seq, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	th, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	// TODO: fix possible overflow here by imposing a limit (see https://github.com/janaiyengar/ack-frequency/issues/43).
	mad, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	opts, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if opts&0b11111100 != 0 {
		return nil, errors.New("invalid reserved bits")
	}
	return &AckFrequencyFrame{
		SequenceNumber:    seq,
		Threshold:         th,
		UpdateMaxAckDelay: time.Duration(mad) * time.Microsecond,
		IgnoreCE:          opts&0b10 > 0,
		IgnoreOrder:       opts&0b01 > 0,
	}, nil
}

func (f *AckFrequencyFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	quicvarint.Write(b, 0xaf)
	quicvarint.Write(b, f.SequenceNumber)
	quicvarint.Write(b, f.Threshold)
	quicvarint.Write(b, uint64(f.UpdateMaxAckDelay/time.Microsecond))
	var opts uint8
	if f.IgnoreCE {
		opts |= 0b10
	}
	if f.IgnoreOrder {
		opts |= 0b01
	}
	b.WriteByte(opts)
	return nil
}

func (f *AckFrequencyFrame) Length(protocol.VersionNumber) protocol.ByteCount {
	return 2 + quicvarint.Len(f.SequenceNumber) + quicvarint.Len(f.Threshold) + quicvarint.Len(uint64(f.UpdateMaxAckDelay/time.Microsecond)) + 1
}
