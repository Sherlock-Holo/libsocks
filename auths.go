package libsocks

import "net"

type Auth struct {
    Code     uint8
    AuthFunc func(conn net.Conn) (bool, error)
}

var (
    NoAuth = Auth{0, func(conn net.Conn) (bool, error) {
        _, err := conn.Write([]byte{5, 0})
        if err != nil {
            return false, err
        }

        return true, nil
    }}
)
