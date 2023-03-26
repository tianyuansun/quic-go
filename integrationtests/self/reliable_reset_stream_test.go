package self_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Reliable stream resets tests", func() {
	It("resets streams - reliably!", func() {
		const num = 4
		const max = 2 << 10
		offsets := make([]int, num)
		for i := 0; i < num; i++ {
			offsets[i] = rand.Intn(max-1) + 1
		}
		fmt.Println("Offsets:", offsets)

		server, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
		Expect(err).ToNot(HaveOccurred())
		defer server.Close()

		serverPort := server.Addr().(*net.UDPAddr).Port
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
			DropPacket: func(_ quicproxy.Direction, b []byte) bool {
				if wire.IsLongHeaderPacket(b[0]) {
					return false
				}
				return rand.Int()%5 == 0
			},
			DelayPacket: func(dir quicproxy.Direction, packet []byte) time.Duration {
				return 10 * time.Millisecond
			},
		})
		Expect(err).ToNot(HaveOccurred())

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var serverWG sync.WaitGroup
		serverWG.Add(num + 1)
		go func() {
			defer GinkgoRecover()
			defer serverWG.Done()
			conn, err := server.Accept(ctx)
			Expect(err).ToNot(HaveOccurred())

			for i := 0; i < num; i++ {
				str, err := conn.AcceptUniStream(ctx)
				Expect(err).ToNot(HaveOccurred())
				go func(i int, str quic.ReceiveStream) {
					defer GinkgoRecover()
					defer serverWG.Done()
					b, err := io.ReadAll(str)
					fmt.Printf("stream %d, read %d, error: %v\n", str.StreamID(), len(b), err)
					Expect(err).To(HaveOccurred())
					var serr *quic.StreamError
					Expect(errors.As(err, &serr)).To(BeTrue())
					Expect(serr.ErrorCode).To(BeEquivalentTo(i))
					Expect(len(b)).To(BeNumerically(">=", offsets[i]))
				}(i, str)
			}
		}()

		conn, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{MaxIdleTimeout: 10 * time.Second}),
		)
		Expect(err).ToNot(HaveOccurred())

		var clientWG sync.WaitGroup
		clientWG.Add(num)
		for i := 0; i < num; i++ {
			str, err := conn.OpenUniStreamSync(ctx)
			Expect(err).ToNot(HaveOccurred())

			go func(i int, str quic.SendStream) {
				defer GinkgoRecover()
				defer clientWG.Done()
				target := offsets[i]
				data := GeneratePRData(4 * target)
				defer GinkgoRecover()

				var offset int
				for offset < target {
					r := target - offset
					if r > 20 {
						r = rand.Intn(target - offset)
						if r == 0 {
							continue
						}
					}
					n, err := str.Write(data[offset : offset+r])
					Expect(err).ToNot(HaveOccurred())
					offset += n
				}
				Expect(offset).To(Equal(target))
				str.(interface{ SetResetBarrier() }).SetResetBarrier()
				_, err = str.Write(data[target:])
				Expect(err).ToNot(HaveOccurred())
				str.CancelWrite(quic.StreamErrorCode(i))
			}(i, str)
		}

		clientWG.Wait()
		serverWG.Wait()
	})
})
