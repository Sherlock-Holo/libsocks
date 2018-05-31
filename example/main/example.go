package main

import (
    "fmt"
    "io"
    "log"
    "net"

    "github.com/Sherlock-Holo/libsocks"
)

func main() {
    listener, err := net.Listen("tcp", "127.0.0.1:9876")
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

    var addr string

    switch socks.AddrType {
    case 1:
        addr = socks.TargetIP.String() + ":"

    case 3:
        addr = socks.TargetHost + ":"

    case 4:
        addr = "[" + socks.TargetIP.String() + "]:"
    }

    remote, err := net.Dial("tcp", fmt.Sprintf("%s%d", addr, socks.TargetPort))
    if err != nil {
        log.Println(err)
        socks.Reply(net.IP{127, 0, 0, 1}, 0, libsocks.ConnRefused)

        socks.Close()
        return
    }

    tcpAddr := remote.(*net.TCPConn).LocalAddr().(*net.TCPAddr)
    err = socks.Reply(tcpAddr.IP, uint16(tcpAddr.Port), libsocks.Success)
    if err != nil {
        log.Println(err)
        socks.Close()
        remote.Close()
        return
    }

    go func() {
        if _, err := io.Copy(remote, socks); err != nil {
            remote.Close()
            socks.Close()
            return
        }
        if err := remote.(*net.TCPConn).CloseWrite(); err != nil {
            remote.Close()
            socks.Close()
            return
        }
    }()

    go func() {
        if _, err := io.Copy(socks, remote); err != nil {
            remote.Close()
            socks.Close()
            return
        }
        if err := socks.CloseWrite(); err != nil {
            remote.Close()
            socks.Close()
            return
        }
    }()
}
