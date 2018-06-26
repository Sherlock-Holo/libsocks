package libsocks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	Success uint8 = iota
	ServerFailed
	ConnNotAllowed
	NetworkUnreachable
	ConnRefused
	TTLExpired
	CmdNotSupport
	AddrTypeNotSupport
)

type VersionErr struct {
	SocksVersion int
}

func (e VersionErr) Error() string {
	return fmt.Sprintf("socks version %d not support", e.SocksVersion)
}

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
		return Socks{}, err
	}
	return socks, nil
}

func (socks *Socks) init() error {
	verMsg := make([]byte, 2)

	_, err := io.ReadFull(socks, verMsg)
	if err != nil {
		socks.Close()
		return err
	}

	if verMsg[0] != 5 {
		socks.Close()
		return VersionErr{int(verMsg[0])}
	}

	methods := make([]byte, verMsg[1])

	_, err = io.ReadFull(socks, methods)
	if err != nil {
		socks.Close()
		return err
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
		return err
	}

	ok, err := socks.AuthFunc(socks)
	if err != nil {
		socks.Close()
		return err
	}

	if !ok {
		socks.Close()
		err := errors.New("auth failed")
		return err
	}

	request := make([]byte, 4)

	if _, err := io.ReadFull(socks, request); err != nil {
		return err
	}

	if request[0] != 5 {
		socks.Close()
		return VersionErr{int(request[0])}
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
			return err
		}
		socks.Close()
		return errors.New("cmd not support")
	}

	socks.Target.Type = request[3]

	switch request[3] {
	case 1:
		addr := make([]byte, 6)

		if _, err := io.ReadFull(socks, addr); err != nil {
			return err
		}

		socks.Target.IP = net.IP(addr[:4])
		socks.Target.Port = binary.BigEndian.Uint16(addr[4:])
		return nil

	case 4:
		addr := make([]byte, net.IPv6len+2)

		if _, err := io.ReadFull(socks, addr); err != nil {
			return err
		}

		socks.Target.IP = net.IP(addr[:16])
		socks.Target.Port = binary.BigEndian.Uint16(addr[16:])
		return nil

	case 3:
		addrLength := make([]byte, 1)
		_, err := socks.Read(addrLength)
		if err != nil {
			socks.Close()
			return err
		}

		addr := make([]byte, addrLength[0]+2)

		if _, err := io.ReadFull(socks, addr); err != nil {
			return err
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
			return err
		}
		socks.Close()
		return errors.New("addr type not support")
	}
}

func (socks *Socks) Reply(ip net.IP, port uint16, field uint8) error {
	if field > 8 {
		err := fmt.Errorf("not support reply filed %d", field)
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

	return err
}
