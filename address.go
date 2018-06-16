package libsocks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

type Address struct {
	Type uint8
	IP   net.IP
	Host string
	Port uint16
}

func (address Address) Bytes() []byte {
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, address.Port)
	bytes := []byte{address.Type}

	switch address.Type {
	case 1, 4:
		bytes = append(bytes, address.IP...)

	case 3:
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
	case 1:
		if len(b) < 1+4+2 {
			return Address{}, errors.New("not enough bytes")
		}

		address.IP = b[1:5]
		b = b[5:]

	case 4:
		if len(b) < 1+16+2 {
			return Address{}, errors.New("not enough bytes")
		}

		address.IP = b[1:17]
		b = b[17:]

	case 3:
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
	atyp := make([]byte, 1)
	if _, err := r.Read(atyp); err != nil {
		return Address{}, err
	}

	var (
		b []byte
	)

	switch atyp[0] {
	case 1:
		b = make([]byte, net.IPv4len+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return Address{}, err
		}
		b = append(atyp, b...)

	case 4:
		b = make([]byte, net.IPv6len+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return Address{}, err
		}
		b = append(atyp, b...)

	case 3:
		addrLen := make([]byte, 1)
		if _, err := r.Read(addrLen); err != nil {
			return Address{}, err
		}
		b = make([]byte, addrLen[0]+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return Address{}, err
		}
		b = append(addrLen, b...)
		b = append(atyp, b...)

	default:
		return Address{}, fmt.Errorf("not support addr type %d", atyp[0])
	}

	return Decode(b)
}

func (address Address) String() string {
	switch address.Type {
	case 1, 4:
		return net.JoinHostPort(address.IP.String(), fmt.Sprintf("%d", address.Port))

	case 3:
		return net.JoinHostPort(address.Host, fmt.Sprintf("%d", address.Port))

	default:
		return ""
	}
}
