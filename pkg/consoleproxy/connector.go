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
	"fmt"
	"golang.org/x/net/websocket"
	"net"
)

type ConnectorType string

const (
	CONNECTOR_FIXED   = "fixed"
	CONNECTOR_LIBVIRT = "libvirt"
	CONNECTOR_ETCD    = "etcd"
)

type Connector interface {
	Associate(tenant *websocket.Conn, token string) (net.Conn, *ServiceConfig, error)
}

// FixedConnector allows tenants to connect to a single fixed
// compute node console server
type FixedConnector struct {
	ComputeAddr   string
	ServiceConfig *ServiceConfig
	Token         string
}

func (c *FixedConnector) Associate(tenant *websocket.Conn, token string) (net.Conn, *ServiceConfig, error) {
	if c.Token != "" && c.Token != token {
		return nil, nil, fmt.Errorf("Request does not have required token value")
	}
	conn, err := net.Dial("tcp", c.ComputeAddr)
	if err != nil {
		return nil, nil, err
	}

	return conn, c.ServiceConfig, nil
}
