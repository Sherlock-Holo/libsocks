package libsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/pkg/errors"
)

type AddressType = uint8

const (
	IPv4   AddressType = 1
	IPv6   AddressType = 4
	Domain AddressType = 3
)

type Address struct {
	Type AddressType
	IP   net.IP
	Host string
	Port uint16
}

func (address Address) Bytes() []byte {
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, address.Port)
	bytes := []byte{address.Type}

	switch address.Type {
	case IPv4, IPv6:
		bytes = append(bytes, address.IP...)

	case Domain:
		bytes = append(bytes, byte(len([]byte(address.Host))))
		bytes = append(bytes, []byte(address.Host)...)

	default:
		panic(fmt.Sprintf("error addr type %d", address.Type))
	}

	bytes = append(bytes, pb...)
	return bytes
}

func Decode(b []byte) (Address, error) {
	if b == nil {
		return Address{}, errors.New("empty []byte")
	}

	if len(b) <= 1+1+2 {
		return Address{}, errors.New("not enough bytes")
	}

	var address Address
	address.Type = b[0]

	switch address.Type {
	case IPv4:
		if len(b) < 1+net.IPv4len+2 {
			return Address{}, errors.New("not enough bytes")
		}

		address.IP = b[1 : 1+net.IPv4len]
		b = b[1+net.IPv4len:]

	case IPv6:
		if len(b) < 1+net.IPv6len+2 {
			return Address{}, errors.New("not enough bytes")
		}

		address.IP = b[1 : 1+net.IPv6len]
		b = b[1+net.IPv6len:]

	case Domain:
		length := int(b[1])
		if len(b) < 2+length+2 {
			return Address{}, errors.New("not enough bytes")
		}
		address.Host = string(b[2 : 2+length])
		b = b[2+length:]

	default:
		return Address{}, errors.New("address type not support")
	}

	address.Port = binary.BigEndian.Uint16(b)

	return address, nil
}

func DecodeFrom(r io.Reader) (Address, error) {
	addrType := make([]byte, 1)
	if _, err := r.Read(addrType); err != nil {
		return Address{}, errors.Wrap(err, "decode socks address from io.Reader failed")
	}

	var b []byte
	switch addrType[0] {
	case IPv4:
		b = make([]byte, net.IPv4len+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return Address{}, errors.Wrap(err, "read ipv4 addr from io.Reader failed")
		}
		b = append(addrType, b...)

	case IPv6:
		b = make([]byte, net.IPv6len+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return Address{}, errors.Wrap(err, "read ipv6 addr from io.Reader failed")
		}
		b = append(addrType, b...)

	case Domain:
		addrLen := make([]byte, 1)
		if _, err := r.Read(addrLen); err != nil {
			return Address{}, errors.Wrap(err, "read domain length from io.Reader failed")
		}
		b = make([]byte, addrLen[0]+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return Address{}, errors.Wrap(err, "read domain addr from io.Reader failed")
		}
		b = append(addrLen, b...)
		b = append(addrType, b...)

	default:
		return Address{}, errors.Errorf("not support addr type %d", addrType[0])
	}

	return Decode(b)
}

func (address Address) String() string {
	switch address.Type {
	case IPv4, IPv6:
		return net.JoinHostPort(address.IP.String(), strconv.Itoa(int(address.Port)))

	case Domain:
		return net.JoinHostPort(address.Host, strconv.Itoa(int(address.Port)))

	default:
		return ""
	}
}
