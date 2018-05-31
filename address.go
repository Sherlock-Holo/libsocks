package libsocks

import (
    "encoding/binary"
    "errors"
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
    var bytes []byte

    switch address.Type {
    case 1, 4:
        bytes = append(bytes, address.IP...)

    default:
        bytes = append(bytes, byte(len([]byte(address.Host))))
        bytes = append(bytes, []byte(address.Host)...)
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

    switch b[0] {
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
