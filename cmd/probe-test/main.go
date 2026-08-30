package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"time"

	"github.com/quic-go/quic-go"
)

// Simulates an active prober: dials QUIC with ALPN h3, opens a stream, sends
// an HTTP-like request, prints whatever the server answers.
func main() {
	addr := "127.0.0.1:49443"
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, tlsConf, nil)
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	defer conn.CloseWithError(0, "")
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		fmt.Println("stream:", err)
		return
	}
	st.Write([]byte("GET / HTTP/1.1\r\nHost: www.cloudflare.com\r\n\r\n"))
	st.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf, _ := io.ReadAll(st)
	out := string(buf)
	if len(out) > 300 {
		out = out[:300]
	}
	fmt.Printf("probe got %d bytes:\n%s\n", len(buf), out)
}
