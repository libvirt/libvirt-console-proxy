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
	"golang.org/x/net/websocket"
	"net"
)

type ConsoleClientSerial struct {
	Tenant  net.Conn
	Compute net.Conn
}

func NewConsoleClientSerial(tenant *websocket.Conn, compute net.Conn) *ConsoleClientSerial {

	client := &ConsoleClientSerial{
		Tenant:  tenant,
		Compute: compute,
	}

	tenant.PayloadType = websocket.BinaryFrame

	return client
}

func (c *ConsoleClientSerial) proxyData(src net.Conn, dst net.Conn) error {
	data := make([]byte, 64*1024)
	pending := 0
	offset := 0
	for {
		if pending == 0 {
			var err error
			pending, err = src.Read(data)
			if err != nil {
				return err
			}
			if pending == 0 {
				return nil
			}
			offset = 0
		}

		done, err := dst.Write(data[offset:pending])
		if err != nil {
			return err
		}
		pending -= done
		offset += done
	}
}

func (c *ConsoleClientSerial) proxyToCompute() error {
	err := c.proxyData(c.Tenant, c.Compute)
	c.Compute.Close()
	return err
}

func (c *ConsoleClientSerial) proxyToTenant() error {
	err := c.proxyData(c.Compute, c.Tenant)
	c.Tenant.Close()
	return err
}

func (c *ConsoleClientSerial) Proxy() error {
	go c.proxyToTenant()

	return c.proxyToCompute()
}
