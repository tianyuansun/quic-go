package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PingFrame", func() {
	Context("when writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := PingFrame{}
			frame.Write(b, protocol.VersionWhatever)
			Expect(b.Bytes()).To(Equal([]byte{0x1}))
		})

		It("has the correct min length", func() {
			frame := PingFrame{}
			Expect(frame.Length(protocol.VersionWhatever)).To(Equal(protocol.ByteCount(1)))
		})
	})
})
