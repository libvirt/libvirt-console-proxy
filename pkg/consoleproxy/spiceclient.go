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
	"github.com/golang/glog"
	"golang.org/x/net/websocket"
	"net"
)

type ConsoleClientSPICE struct {
	Tenant    net.Conn
	Compute   net.Conn
	Insecure  bool
	TLSConfig *tls.Config
}

func NewConsoleClientSPICE(tenant *websocket.Conn, compute net.Conn, insecure bool, tlsConfig *tls.Config) *ConsoleClientSPICE {

	client := &ConsoleClientSPICE{
		Tenant:    tenant,
		Compute:   compute,
		Insecure:  insecure,
		TLSConfig: tlsConfig,
	}

	tenant.PayloadType = websocket.BinaryFrame

	return client
}

func (c *ConsoleClientSPICE) proxyData(src net.Conn, dst net.Conn) error {
	data := make([]byte, 64*1024)
	var remaining []byte
	for {
		if len(remaining) == 0 {
			got, err := src.Read(data)
			if err != nil {
				return err
			}
			if got == 0 {
				glog.V(1).Info("Got EOF")
				return nil
			}
			remaining = data[0:got]
		}

		done, err := dst.Write(remaining)
		if err != nil {
			return err
		}
		remaining = remaining[done:]
	}
}

func (c *ConsoleClientSPICE) proxyToCompute() error {
	err := c.proxyData(c.Tenant, c.Compute)
	glog.V(1).Infof("Error proxy to compute %s", err)
	c.Compute.Close()
	return err
}

func (c *ConsoleClientSPICE) proxyToTenant() error {
	err := c.proxyData(c.Compute, c.Tenant)
	glog.V(1).Infof("Error proxy to tenant %s", err)
	c.Tenant.Close()
	return err
}

func (c *ConsoleClientSPICE) Proxy() error {
	if !c.Insecure {
		conn := tls.Client(c.Compute, c.TLSConfig)

		if err := conn.Handshake(); err != nil {
			return err
		}

		c.Compute = conn
	}

	go c.proxyToTenant()

	return c.proxyToCompute()
}
