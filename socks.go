package libsocks

import (
    "encoding/binary"
    "errors"
    "fmt"
    "log"
    "net"
)

const (
    Success            uint8 = iota
    ServerFailed
    ConnNotAllowed
    NetworkUnreachable
    ConnRefused
    TTLExpired
    CmdNotSupport
    AddrTypeNotSupport
)

var (
    VersionErr = errors.New("socks version not support")
)

type Socks struct {
    *net.TCPConn
    *Auth

    Target Address
}

func NewSocks(conn net.Conn, auth *Auth) (Socks, error) {
    if auth == nil {
        auth = &NoAuth
    }

    socks := Socks{
        conn.(*net.TCPConn),
        auth,
        Address{},
    }

    err := socks.init()
    if err != nil {
        log.Println(err)
        return Socks{}, err
    }
    return socks, nil
}

func (socks *Socks) init() error {
    if socks.Auth == nil {
        socks.Auth = &NoAuth
    }

    var length int

    verMsg := make([]byte, 2)

    for length < 2 {
        n, err := socks.Read(verMsg[length:])
        if err != nil {
            socks.Close()
            return err
        }
        length += n
    }

    if verMsg[0] != 5 {
        socks.Close()
        return VersionErr
    }

    methods := make([]byte, verMsg[1])
    length = 0

    for length < int(verMsg[1]) {
        n, err := socks.Read(methods[length:])
        if err != nil {
            socks.Close()
            return err
        }
        length += n
    }

    var coincide bool

    for _, auth := range methods {
        if auth == socks.Code {
            coincide = true
            break
        }
    }
    if !coincide {
        socks.Close()
        err := fmt.Errorf("auth %d not coincide", socks.Code)
        log.Println(err)
        return err
    }

    ok, err := socks.AuthFunc(socks)
    if err != nil {
        socks.Close()
        log.Println(err)
        return err
    }

    if !ok {
        socks.Close()
        err := errors.New("auth failed")
        log.Println(err)
        return err
    }

    request := make([]byte, 4)
    length = 0

    for length < 4 {
        n, err := socks.Read(request[length:])
        if err != nil {
            socks.Close()
            log.Println(err)
            return err
        }
        length += n
    }

    if request[0] != 5 {
        socks.Close()
        log.Println(err)
        return VersionErr
    }

    if request[1] != 1 {
        reply := []byte{5, CmdNotSupport, 0}
        tcpAddr := socks.LocalAddr().(*net.TCPAddr)

        if len(tcpAddr.IP) == net.IPv6len {
            reply = append(reply, 4)
        } else {
            reply = append(reply, 1)
        }
        reply = append(reply, tcpAddr.IP...)

        port := make([]byte, 2)
        binary.BigEndian.PutUint16(port, uint16(tcpAddr.Port))
        reply = append(reply, port...)

        _, err = socks.Write(reply)
        if err != nil {
            socks.Close()
            log.Println(err)
            return err
        }
        socks.Close()
        log.Println("cmd not support")
        return errors.New("cmd not support")
    }

    socks.Target.Type = request[3]

    switch request[3] {
    case 1:
        addr := make([]byte, 6)
        length = 0

        for length < 6 {
            n, err := socks.Read(addr[length:])
            if err != nil {
                socks.Close()
                log.Println(err)
                return err
            }
            length += n
        }

        socks.Target.IP = net.IP(addr[:4])
        socks.Target.Port = binary.BigEndian.Uint16(addr[4:])
        return nil

    case 4:
        addr := make([]byte, net.IPv6len+2)
        length = 0

        for length < net.IPv6len+2 {
            n, err := socks.Read(addr[length:])
            if err != nil {
                socks.Close()
                log.Println(err)
                return err
            }
            length += n
        }

        socks.Target.IP = net.IP(addr[:16])
        socks.Target.Port = binary.BigEndian.Uint16(addr[16:])
        return nil

    case 3:
        addrLength := make([]byte, 1)
        _, err := socks.Read(addrLength)
        if err != nil {
            socks.Close()
            log.Println(err)
            return err
        }

        addr := make([]byte, addrLength[0]+2)
        length = 0

        for length < int(addrLength[0])+2 {
            n, err := socks.Read(addr[length:])
            if err != nil {
                socks.Close()
                log.Println(err)
                return err
            }
            length += n
        }

        socks.Target.Host = string(addr[:addrLength[0]])
        socks.Target.Port = binary.BigEndian.Uint16(addr[addrLength[0]:])
        return nil

    default:
        reply := []byte{5, AddrTypeNotSupport, 0}
        tcpAddr := socks.LocalAddr().(*net.TCPAddr)

        if len(tcpAddr.IP) == net.IPv6len {
            reply = append(reply, 4)
        } else {
            reply = append(reply, 1)
        }
        reply = append(reply, tcpAddr.IP...)

        port := make([]byte, 2)
        binary.BigEndian.PutUint16(port, uint16(tcpAddr.Port))
        reply = append(reply, port...)

        _, err = socks.Write(reply)
        if err != nil {
            socks.Close()
            log.Println(err)
            return err
        }
        socks.Close()
        log.Println("addr type not support")
        return errors.New("addr type not support")
    }
}

func (socks *Socks) Reply(ip net.IP, port uint16, field uint8) error {
    if field > 8 {
        err := fmt.Errorf("not support reply filed %d", field)
        log.Println(err)
        return err
    }

    pb := make([]byte, 2)
    binary.BigEndian.PutUint16(pb, port)

    reply := []byte{5, field, 0}
    if len(ip) == 4 {
        reply = append(reply, 1)
    } else {
        reply = append(reply, 4)
    }
    reply = append(reply, ip...)
    reply = append(reply, pb...)

    _, err := socks.Write(reply)

    if err != nil {
        log.Println(err)
    }

    return err
}
