package libsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"golang.org/x/xerrors"
)

type AddressType = uint8

const (
	TypeIPv4   AddressType = 1
	TypeIPv6   AddressType = 4
	TypeDomain AddressType = 3
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
	case TypeIPv4, TypeIPv6:
		bytes = append(bytes, address.IP...)

	case TypeDomain:
		bytes = append(bytes, byte(len([]byte(address.Host))))
		bytes = append(bytes, []byte(address.Host)...)

	default:
		panic(fmt.Sprintf("error addr type %d", address.Type))
	}

	bytes = append(bytes, pb...)
	return bytes
}

func UnmarshalAddress(b []byte) (Address, error) {
	if b == nil {
		return Address{}, xerrors.New("unmarshal address failed: empty []byte")
	}

	if len(b) <= 1+1+2 {
		return Address{}, xerrors.New("unmarshal address failed: not enough bytes")
	}

	var address Address
	address.Type = b[0]

	switch address.Type {
	case TypeIPv4:
		if len(b) < 1+net.IPv4len+2 {
			return Address{}, xerrors.New("unmarshal address failed: not enough bytes")
		}

		address.IP = b[1 : 1+net.IPv4len]
		b = b[1+net.IPv4len:]

	case TypeIPv6:
		if len(b) < 1+net.IPv6len+2 {
			return Address{}, xerrors.New("unmarshal address failed: not enough bytes")
		}

		address.IP = b[1 : 1+net.IPv6len]
		b = b[1+net.IPv6len:]

	case TypeDomain:
		length := int(b[1])
		if len(b) < 2+length+2 {
			return Address{}, xerrors.New("unmarshal address failed: not enough bytes")
		}
		address.Host = string(b[2 : 2+length])
		b = b[2+length:]

	default:
		return Address{}, xerrors.New("unmarshal address failed: address type not support")
	}

	address.Port = binary.BigEndian.Uint16(b)

	return address, nil
}

func UnmarshalAddressFrom(r io.Reader) (Address, error) {
	addrType := make([]byte, 1)
	if _, err := r.Read(addrType); err != nil {
		return Address{}, xerrors.Errorf("unmarshal address: read addr type from io.Reader failed: %w", err)
	}

	var b []byte
	switch addrType[0] {
	case TypeIPv4:
		b = make([]byte, net.IPv4len+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return Address{}, xerrors.Errorf("unmarshal address: read ipv4 addr from io.Reader failed: %w", err)
		}
		b = append(addrType, b...)

	case TypeIPv6:
		b = make([]byte, net.IPv6len+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return Address{}, xerrors.Errorf("unmarshal address: read ipv6 addr from io.Reader failed: %w", err)
		}
		b = append(addrType, b...)

	case TypeDomain:
		addrLen := make([]byte, 1)
		if _, err := r.Read(addrLen); err != nil {
			return Address{}, xerrors.Errorf("unmarshal address: read domain name length from io.Reader failed: %w", err)
		}

		b = make([]byte, addrLen[0]+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return Address{}, xerrors.Errorf("unmarshal address: read domain name from io.Reader failed: %w", err)
		}
		b = append(addrLen, b...)
		b = append(addrType, b...)

	default:
		return Address{}, xerrors.Errorf("unmarshal address:: not support addr type %d", addrType[0])
	}

	return UnmarshalAddress(b)
}

func (address Address) String() string {
	switch address.Type {
	case TypeIPv4, TypeIPv6:
		return net.JoinHostPort(address.IP.String(), strconv.Itoa(int(address.Port)))

	case TypeDomain:
		return net.JoinHostPort(address.Host, strconv.Itoa(int(address.Port)))

	default:
		return ""
	}
}
