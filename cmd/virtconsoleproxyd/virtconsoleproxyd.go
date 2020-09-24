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
	"github.com/spf13/pflag"
	"io/ioutil"
	"libvirt.org/libvirt-console-proxy/pkg/proxy"
	"libvirt.org/libvirt-console-proxy/pkg/util"
	"os"
	"strings"
)

var (
	listeninsecure = pflag.Bool("listen-insecure", false,
		"Run public listener without TLS encryption")
	listenaddr = pflag.String("listen-addr", "0.0.0.0:80",
		"TCP address and port to listen on")
	listentlscert = pflag.String("listen-tls-cert", "/etc/pki/libvirt-console-proxy/server-cert.pem",
		"Path to TLS public server cert PEM file")
	listentlskey = pflag.String("listen-tls-key", "/etc/pki/libvirt-console-proxy/server-key.pem",
		"Path to TLS public server key PEM file")
	listentlsca = pflag.String("listen-tls-ca", "/etc/pki/libvirt-console-proxy/server-ca.pem",
		"Path to TLS public server CA cert PEM file")
	listenmintls = pflag.String("listen-min-tls", "VersionTLS12",
		"Minimum TLS version to support - VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13")
	listenciphersuites = pflag.StringSlice("listen-cipher-suites", nil,
		"Comma separated list of cipher suites (https://golang.org/pkg/crypto/tls/#pkg-constants) ")

	connectinsecure = pflag.Bool("connect-insecure", false,
		"Allow running internal connection without TLS encryption")
	connecttlscert = pflag.String("connect-tls-cert", "/etc/pki/libvirt-console-proxy/client-cert.pem",
		"Path to TLS internal client cert PEM file")
	connecttlskey = pflag.String("connect-tls-key", "/etc/pki/libvirt-console-proxy/client-key.pem",
		"Path to TLS internal client key PEM file")
	connecttlsca = pflag.String("connect-tls-ca", "/etc/pki/libvirt-console-proxy/client-ca.pem",
		"Path to TLS internal client CA PEM file")

	resolvermode = pflag.String("resolver-mode", "builtin",
		"Type of resolver to use 'builtin' or 'external'")
	resolvertokens = pflag.String("resolver-tokens", "/etc/libvirt/consoleproxy/tokens.json",
		"Path to token file for builin resolver")
	resolveruri = pflag.String("resolver-uri", "https://127.0.0.1:8081/consoleresolver/",
		"URI base for the external resolver REST service")
	resolvertlscert = pflag.String("resolver-tls-cert", "/etc/pki/libvirt-console-proxy/client-cert.pem",
		"Path to TLS internal client cert PEM file")
	resolvertlskey = pflag.String("resolver-tls-key", "/etc/pki/libvirt-console-proxy/client-key.pem",
		"Path to TLS internal client key PEM file")
	resolvertlsca = pflag.String("resolver-tls-ca", "/etc/pki/libvirt-console-proxy/client-ca.pem",
		"Path to TLS internal client CA PEM file")
)

func loadTLSConfig(certFile, keyFile, caFile string, client bool, minTLS uint16, cipherSuites []uint16) (*tls.Config, error) {
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
	if client {
		config = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      calist,
		}
	} else {
		config = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    calist,
			MinVersion:   minTLS,
			CipherSuites: cipherSuites,
		}
	}

	return config, nil
}

func main() {
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	// Convince glog that we really have parsed CLI
	flag.CommandLine.Parse([]string{})

	var err error
	var connecttlsconfig *tls.Config
	if !*connectinsecure {
		glog.V(1).Info("Loading client TLS config")
		connecttlsconfig, err = loadTLSConfig(*connecttlscert, *connecttlskey, *connecttlsca, true, 0, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	var resolver proxy.Resolver
	if *resolvermode == "builtin" {
		resolver, err = proxy.NewBuiltinResolver(*resolvertokens)
	} else {
		var resolvertlsconfig *tls.Config
		if strings.HasPrefix(*resolveruri, "https") {
			var err error
			glog.V(1).Info("Loading resolver TLS config")
			resolvertlsconfig, err = loadTLSConfig(*resolvertlscert, *resolvertlskey, *resolvertlsca, true, 0, nil)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		resolver, err = proxy.NewExternalResolver(*resolveruri, resolvertlsconfig)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var listentlsconfig *tls.Config
	if !*listeninsecure {

		// Convert min TLS version string to the constant - error on invalid name
		glog.V(1).Infof("Listen minimum TLS version: %s", *listenmintls)
		minTLSVersion, ok := util.TLSNameToConst(*listenmintls)
		if !ok {
			fmt.Fprintln(os.Stderr, "Invalid minimum TLS version ", *listenmintls)
			os.Exit(1)
		}

		// Convert suite names to suite constants - error on any invalid / unsupported suite names
		glog.V(1).Infof("Listen cipher suites requested: %s", *listenciphersuites)
		var cipherSuites []uint16
		for _, name := range *listenciphersuites {
			if val, ok := util.CipherNameToConst(name); ok {
				cipherSuites = append(cipherSuites, val)
			} else {
				fmt.Fprintln(os.Stderr, "Invalid cipher suite ", name)
				os.Exit(1)
			}
		}

		var err error
		listentlsconfig, err = loadTLSConfig(*listentlscert, *listentlskey, *listentlsca, false, uint16(minTLSVersion), cipherSuites)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	glog.V(1).Info("Starting console server")
	server := proxy.NewConsoleServer(*listenaddr, *listeninsecure, listentlsconfig, connecttlsconfig, resolver)

	err = server.Serve()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	os.Exit(0)
}
