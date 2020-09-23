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

package proxy

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"golang.org/x/net/websocket"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
)

type ConsoleServer struct {
	Server          *http.Server
	WSServer        *websocket.Server
	Resolver        Resolver
	Mux             *http.ServeMux
	Insecure        bool
	TLSClientConfig *tls.Config
	Mutex           sync.Mutex
	ActiveServices  []*ServiceConfig
}

type Diagnostics struct {
	NumActive      int             `json:"number_active"`
	ActiveServices []ServiceConfig `json:"active_sessions"`
}

func NewConsoleServer(listenAddr string, insecure bool, tlsServerConfig *tls.Config, tlsClientConfig *tls.Config, resolver Resolver) *ConsoleServer {

	s := &ConsoleServer{
		Mux:             http.NewServeMux(),
		Resolver:        resolver,
		Insecure:        insecure,
		TLSClientConfig: tlsClientConfig,
	}

	s.WSServer = &websocket.Server{
		Handler: s.handleClient,
	}

	s.Server = &http.Server{
		Addr:      listenAddr,
		TLSConfig: tlsServerConfig,
		Handler:   s.Mux,
	}

	s.Mux.Handle("/websockify", s.WSServer)
	s.Mux.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	s.Mux.HandleFunc("/statusz", func(w http.ResponseWriter, req *http.Request) {
		s.Mutex.Lock()

		services := make([]ServiceConfig, len(s.ActiveServices))

		for i, service := range s.ActiveServices {
			sc := ServiceConfig(*service)
			if sc.Password != "" {
				sc.Password = "****"
			}
			services[i] = sc
		}

		d := Diagnostics{
			NumActive:      len(services),
			ActiveServices: services,
		}

		out, _ := json.Marshal(d)
		s.Mutex.Unlock()
		fmt.Fprintf(w, "%s", out)
	})
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
	req := tenant.Request()

	req.ParseForm()

	token, ok := req.Form["token"]
	var tokenValue string
	if ok {
		if len(token) != 1 {
			tenant.Close()
			fmt.Fprintln(os.Stderr, "Expected a single token parameter")
			return
		}

		tokenValue = token[0]
	}
	if tokenValue == "" {
		fmt.Fprintln(os.Stderr, "Need a non-empty token for console access")
		return
	}

	glog.V(2).Infof("Resolving token %s", tokenValue)
	service, err := s.Resolver.Resolve(tokenValue)
	if err != nil {
		tenant.Close()
		fmt.Fprintln(os.Stderr, err)
		return
	}
	glog.V(1).Infof("Resolver compute service %s at %s (insecure: %t, tlsTunnel: %t)",
		service.Type, service.Address, service.Insecure, service.TLSTunnel)

	var compute net.Conn
	if !service.Insecure && !(service.Type == SERVICE_VNC && !service.TLSTunnel) {
		compute, err = tls.Dial("tcp", service.Address, s.TLSClientConfig)
	} else if service.Insecure && service.TLSTunnel {
		err = fmt.Errorf("Incompatible resolver service security (insecure: true, tlsTunnel: true)")
	} else {
		compute, err = net.Dial("tcp", service.Address)
	}
	if err != nil {
		tenant.Close()
		fmt.Fprintln(os.Stderr, err)
		return
	}

	var client ConsoleClient
	switch service.Type {
	case SERVICE_VNC:
		client = NewConsoleClientVNC(tenant, compute, service, s.TLSClientConfig)

	case SERVICE_SPICE:
		client = NewConsoleClientSPICE(tenant, compute)

	case SERVICE_SERIAL:
		client = NewConsoleClientSerial(tenant, compute)

	default:
		fmt.Fprintf(os.Stderr, "Unexpected service type '%s'\n", service.Type)
	}

	s.Mutex.Lock()
	s.ActiveServices = append(s.ActiveServices, service)
	s.Mutex.Unlock()

	err = client.Proxy()

	s.Mutex.Lock()
	// Remove the service from the list of active services
	for i, v := range s.ActiveServices {
		if v == service {
			lenMinusOne := len(s.ActiveServices) - 1
			s.ActiveServices[i] = s.ActiveServices[lenMinusOne]
			s.ActiveServices[lenMinusOne] = nil
			s.ActiveServices = s.ActiveServices[:lenMinusOne]
			break
		}
	}
	s.Mutex.Unlock()

	if err != nil && err == io.EOF {
		glog.V(1).Infof("Disconnect for compute service %s at %s",
			service.Type, service.Address)
	} else if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}
