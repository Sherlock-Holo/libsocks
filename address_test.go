package libsocks

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

func TestDecodeFrom(t *testing.T) {
	address1 := Address{
		Type: 1,
		IP:   net.IP{127, 0, 0, 1},
		Port: 80,
	}

	address3 := Address{
		Type: 3,
		Host: "www.qq.com",
		Port: 80,
	}

	address4 := Address{
		Type: 4,
		IP:   net.IPv6loopback,
		Port: 80,
	}

	reader1 := bytes.NewReader(address1.Bytes())
	reader3 := bytes.NewReader(address3.Bytes())
	reader4 := bytes.NewReader(address4.Bytes())

	r1, err := DecodeFrom(reader1)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(r1)

	r3, err := DecodeFrom(reader3)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(r3)

	r4, err := DecodeFrom(reader4)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(r4)
}
