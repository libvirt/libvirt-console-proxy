/*
 * This file is part of the libvirt-console-proxy project
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Copyright (C) 2016 Red Hat, Inc.
 *
 */

package libvirtconsoleproxy

import (
	"crypto/tls"
	"fmt"
	"github.com/golang/glog"
	"golang.org/x/net/websocket"
	"net/http"
	"os"
)

type ConsoleServer struct {
	Server    *http.Server
	WSServer  *websocket.Server
	Connector Connector
	Mux       *http.ServeMux
	Insecure  bool
	TLSConfig *tls.Config
}

func NewConsoleServer(listenAddr string, insecure bool, tlsConfig *tls.Config, connector Connector) *ConsoleServer {

	s := &ConsoleServer{
		Mux:       http.NewServeMux(),
		Connector: connector,
		Insecure:  insecure,
		TLSConfig: tlsConfig,
	}

	s.WSServer = &websocket.Server{
		Handler: s.handleClient,
	}

	s.Server = &http.Server{
		Addr:      listenAddr,
		TLSConfig: tlsConfig,
		Handler:   s.Mux,
	}

	s.Mux.Handle("/", s.WSServer)
	s.Mux.Handle("/websockify", s.WSServer)

	return s
}

func (s *ConsoleServer) Serve() error {
	if s.Insecure {
		err := s.Server.ListenAndServe()
		if err != nil {
			return err
		}
	} else {
		err := s.Server.ListenAndServeTLS("", "")
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *ConsoleServer) handleClient(tenant *websocket.Conn) {
	glog.V(1).Infof("New tenant connection")
	compute, config, err := s.Connector.Associate(tenant)
	if err != nil {
		tenant.Close()
		fmt.Fprintln(os.Stderr, err)
		return
	}
	glog.V(1).Infof("Associated to compute service %s",
		config.Type)

	var client ConsoleClient
	switch config.Type {
	case SERVICE_VNC:
		client = NewConsoleClientVNC(tenant, compute)

	case SERVICE_SPICE:
		client = NewConsoleClientSPICE(tenant, compute)

	case SERVICE_SERIAL:
		client = NewConsoleClientSerial(tenant, compute)

	default:
		fmt.Fprintln(os.Stderr, "Unexpected service type '%s'", config.Type)
	}

	err = client.Proxy(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}
