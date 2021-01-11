package wire

import (
	"bytes"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go/quicvarint"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ACK_FREQUENCY frame", func() {
	var frameType []byte

	BeforeEach(func() {
		buf := &bytes.Buffer{}
		quicvarint.Write(buf, 0xaf)
		frameType = buf.Bytes()
	})

	Context("when parsing", func() {
		It("parses", func() {
			data := frameType
			data = append(data, encodeVarInt(0xdeadbeef)...) // sequence number
			data = append(data, encodeVarInt(0xcafe)...)     // threshold
			data = append(data, encodeVarInt(1337)...)       // update max ack delay
			data = append(data, 3)
			b := bytes.NewReader(data)
			frame, err := parseAckFrequencyFrame(b, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.SequenceNumber).To(Equal(uint64(0xdeadbeef)))
			Expect(frame.Threshold).To(Equal(uint64(0xcafe)))
			Expect(frame.UpdateMaxAckDelay).To(Equal(1337 * time.Microsecond))
			Expect(frame.IgnoreCE).To(BeTrue())
			Expect(frame.IgnoreOrder).To(BeTrue())
		})

		It("errors when the reserved bits are set", func() {
			data := frameType
			data = append(data, encodeVarInt(0xdeadbeef)...) // sequence number
			data = append(data, encodeVarInt(0)...)          // threshold
			data = append(data, encodeVarInt(1337)...)       // update max ack delay
			data = append(data, 0b100)
			b := bytes.NewReader(data)
			_, err := parseAckFrequencyFrame(b, protocol.Version1)
			Expect(err).To(MatchError("invalid reserved bits"))
		})

		It("errors on EOFs", func() {
			data := frameType
			data = append(data, encodeVarInt(0xdeadbeef)...) // sequence number
			data = append(data, encodeVarInt(0xcafe)...)     // threshold
			data = append(data, encodeVarInt(1337)...)       // update max ack delay
			data = append(data, 0)
			_, err := parseAckFrequencyFrame(bytes.NewReader(data), protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseAckFrequencyFrame(bytes.NewReader(data[0:i]), protocol.Version1)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("when writing", func() {
		It("writes a frame with IgnoreCE", func() {
			frame := &AckFrequencyFrame{
				SequenceNumber:    0xdecafbad,
				Threshold:         0xdeadbeef,
				UpdateMaxAckDelay: 12345 * time.Microsecond,
				IgnoreOrder:       true,
			}
			buf := &bytes.Buffer{}
			Expect(frame.Write(buf, protocol.Version1)).To(Succeed())
			expected := frameType
			expected = append(expected, encodeVarInt(0xdecafbad)...)
			expected = append(expected, encodeVarInt(0xdeadbeef)...)
			expected = append(expected, encodeVarInt(12345)...)
			expected = append(expected, 1)
			Expect(buf.Bytes()).To(Equal(expected))
			Expect(frame.Length(protocol.Version1)).To(BeEquivalentTo(buf.Len()))
			f, err := parseAckFrequencyFrame(bytes.NewReader(buf.Bytes()), protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(f).To(Equal(frame))
			Expect(f.Length(protocol.Version1)).To(Equal(protocol.ByteCount(buf.Len())))
		})

		It("writes a frame with IgnoreCE", func() {
			frame := &AckFrequencyFrame{
				SequenceNumber:    0xdecafbad,
				Threshold:         0xdeadbeef,
				UpdateMaxAckDelay: 1337 * time.Microsecond,
				IgnoreCE:          true,
			}
			buf := &bytes.Buffer{}
			Expect(frame.Write(buf, protocol.Version1)).To(Succeed())
			expected := frameType
			expected = append(expected, encodeVarInt(0xdecafbad)...)
			expected = append(expected, encodeVarInt(0xdeadbeef)...)
			expected = append(expected, encodeVarInt(1337)...)
			expected = append(expected, 2)
			Expect(buf.Bytes()).To(Equal(expected))
			Expect(frame.Length(protocol.Version1)).To(BeEquivalentTo(buf.Len()))
			f, err := parseAckFrequencyFrame(bytes.NewReader(buf.Bytes()), protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(f).To(Equal(frame))
			Expect(f.Length(protocol.Version1)).To(Equal(protocol.ByteCount(buf.Len())))
		})
	})
})
