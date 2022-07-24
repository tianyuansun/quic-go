package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("IMMEDIATE_ACK frame", func() {
	var frameType []byte

	BeforeEach(func() {
		buf := &bytes.Buffer{}
		quicvarint.Write(buf, 0xac)
		frameType = buf.Bytes()
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := ImmediateAckFrame{}
			frame.Write(b, protocol.VersionWhatever)
			Expect(b.Bytes()).To(Equal(frameType))
		})

		It("has the correct min length", func() {
			frame := ImmediateAckFrame{}
			Expect(frame.Length(protocol.VersionWhatever)).To(Equal(protocol.ByteCount(len(frameType))))
		})
	})
})
