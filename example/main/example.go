package main

import (
	"io"
	"log"
	"net"

	"github.com/Sherlock-Holo/libsocks"
	"github.com/pkg/errors"
)

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:9875")
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
		}

		go Handle(conn)
	}
}

func Handle(conn net.Conn) {
	socks, err := libsocks.NewSocks(conn, nil)
	if err != nil {
		log.Fatal(err)
	}

	remote, err := net.Dial("tcp", socks.Target.String())
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		socks.Reply(net.IP{127, 0, 0, 1}, 0, libsocks.ConnRefused)
		socks.Close()
		return
	}

	tcpAddr := remote.(*net.TCPConn).LocalAddr().(*net.TCPAddr)
	err = socks.Reply(tcpAddr.IP, uint16(tcpAddr.Port), libsocks.Success)
	if err != nil {
		log.Printf("%+v", errors.WithStack(err))
		socks.Close()
		remote.Close()
		return
	}

	go func() {
		if _, err := io.Copy(remote, socks); err != nil {
			log.Printf("%+v", errors.WithStack(err))
		}
		remote.Close()
		socks.Close()
	}()

	go func() {
		if _, err := io.Copy(socks, remote); err != nil {
			log.Printf("%+v", errors.WithStack(err))
		}
		remote.Close()
		socks.Close()
	}()
}
