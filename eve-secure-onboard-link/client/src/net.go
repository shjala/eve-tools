package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	vcom "github.com/lf-edge/eve/pkg/pillar/vcom/go-api"
	"golang.org/x/sys/unix"
)

func vsockDial(cid, port uint32) (net.Conn, error) {
	addr := unix.SockaddrVM{
		CID:  cid,
		Port: port,
	}

	sockfd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("error creating VSOCK socket: %v", err)
	}
	err = unix.Connect(sockfd, &addr)
	if err != nil {
		unix.Close(sockfd)
		return nil, fmt.Errorf("error connecting to VSOCK server: %v", err)
	}

	return &VSOCKConn{fd: sockfd}, nil
}

func vsockClientVsockTransport() *http.Transport {
	return &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return vsockDial(unix.VMADDR_CID_LOCAL, vcom.HostVPort) // Use vsockDial as the connection handler
		},
	}
}

func getClient() *http.Client {
	return &http.Client{
		Transport: vsockClientVsockTransport(),
		Timeout:   1000 * time.Second,
	}
}
