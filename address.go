package libsocks

import (
    "encoding/binary"
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
