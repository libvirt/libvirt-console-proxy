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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/golang/glog"
	"io/ioutil"
	proxy "libvirt.org/libvirt-console-proxy/consoleproxy"
	"os"
	"strings"
)

type stringList []string

func (i *stringList) String() string {
	return "my string representation"
}

func (i *stringList) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	listeninsecure = flag.Bool("listen-insecure", false,
		"Run public listener without TLS encryption")
	listenaddr = flag.String("listen-addr", "0.0.0.0:80",
		"TCP address and port to listen on")
	listentlscert = flag.String("listen-tls-cert", "/etc/pki/libvirt-console-proxy/server-cert.pem",
		"Path to TLS public server cert PEM file")
	listentlskey = flag.String("listen-tls-key", "/etc/pki/libvirt-console-proxy/server-key.pem",
		"Path to TLS public server key PEM file")
	listentlsca = flag.String("listen-tls-ca", "/etc/pki/libvirt-console-proxy/server-ca.pem",
		"Path to TLS public server CA cert PEM file")

	connectortype = flag.String("connector-type", "fixed",
		"Connector to use to access compute node servers")
	connectinsecure = flag.Bool("connect-insecure", false,
		"Run internal connection without TLS encryption")
	connectaddr = flag.String("connect-addr", "127.0.0.1:5900",
		"TCP address and port to connect to")
	connectservice = flag.String("connect-service", "vnc",
		"Service type to connect to (vnc, spice or serial)")
	connecttlscert = flag.String("connect-tls-cert", "/etc/pki/libvirt-console-proxy/client-cert.pem",
		"Path to TLS internal client cert PEM file")
	connecttlskey = flag.String("connect-tls-key", "/etc/pki/libvirt-console-proxy/client-key.pem",
		"Path to TLS internal client key PEM file")
	connecttlsca = flag.String("connect-tls-ca", "/etc/pki/libvirt-console-proxy/client-ca.pem",
		"Path to TLS internal client CA PEM file")

	libvirturis stringList
)

func loadTLSConfig(certFile, keyFile, caFile, addr string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	ca, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	calist := x509.NewCertPool()

	ok := calist.AppendCertsFromPEM(ca)
	if !ok {
		return nil, fmt.Errorf("Error loading CA certs from %s", caFile)
	}

	var config *tls.Config
	if addr != "" {
		addrbits := strings.Split(addr, ":")
		if len(addrbits) != 2 {
			return nil, fmt.Errorf("Expected host:port in %s\n", addr)
		}
		config = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      calist,
			ServerName:   addrbits[0],
		}
	} else {
		config = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    calist,
		}
	}

	return config, nil
}

func main() {
	flag.Var(&libvirturis, "libvirt-uri",
		"List of libvirt URIs to connect to")
	flag.Parse()

	var connector proxy.Connector
	var connecttlsconfig *tls.Config
	if !*connectinsecure {
		var err error
		glog.V(1).Info("Loading client TLS config")
		connecttlsconfig, err = loadTLSConfig(*connecttlscert, *connecttlskey, *connecttlsca, *connectaddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	switch proxy.ConnectorType(*connectortype) {
	case proxy.CONNECTOR_FIXED:
		glog.V(1).Info("Using fixed connector")
		svcconfig := &proxy.ServiceConfig{
			Type:      proxy.ServiceType(*connectservice),
			Insecure:  *connectinsecure,
			TLSConfig: connecttlsconfig,
		}

		connector = &proxy.FixedConnector{
			ComputeAddr:   *connectaddr,
			ServiceConfig: svcconfig,
		}
	case proxy.CONNECTOR_LIBVIRT:
		glog.V(1).Info("Using libvirt connector")
		connector = proxy.NewLibvirtConnector(libvirturis, connecttlsconfig)
	default:
		fmt.Fprintf(os.Stderr, "Unknown connector type %s\n", *connectortype)
		os.Exit(1)
	}

	var listentlsconfig *tls.Config
	if !*listeninsecure {
		var err error
		listentlsconfig, err = loadTLSConfig(*listentlscert, *listentlskey, *listentlsca, "")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	glog.V(1).Info("Starting console server")
	server := proxy.NewConsoleServer(*listenaddr, *listeninsecure, listentlsconfig, connector)

	err := server.Serve()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	os.Exit(0)
}
