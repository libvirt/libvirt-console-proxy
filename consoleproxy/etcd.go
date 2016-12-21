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
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"golang.org/x/net/websocket"
	"libvirt.org/libvirt-console-proxy/storage"
	"net"
	"time"
)

type EtcdConnector struct {
	TLSConfig *tls.Config
	Client    *storage.Client
}

func NewEtcdConnector(endpoints []string, requestTimeout time.Duration, v3 bool, tlsConfig *tls.Config) (*EtcdConnector, error) {
	client, err := storage.NewClient(endpoints, requestTimeout, v3)
	if err != nil {
		return nil, err
	}

	connector := &EtcdConnector{
		Client:    client,
		TLSConfig: tlsConfig,
	}

	return connector, nil
}

type EtcdConnectorToken struct {
	Type     ServiceType `json:"type"`
	Insecure bool        `json:"insecure"`
	Host     string      `json:"host"`
	Port     string      `json:"port"`
}

func (t *EtcdConnectorToken) Serialize() (string, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (t *EtcdConnectorToken) Deserialize(data string) error {
	err := json.Unmarshal([]byte(data), t)
	if err != nil {
		return err
	}
	return nil
}

func (c *EtcdConnector) resolveToken(token string) (*EtcdConnectorToken, error) {
	tokenInfo := &EtcdConnectorToken{}
	// TODO this is ok for initial proof of concept, but it is
	// recommended never to store passwords in etcd in plain
	// text. So we need to figure out some better way to deal
	// with tokens, likely encrypting them with a secret known
	// only to the proxy server, and whichever compute node
	// service is permitted to expose console info
	err := c.Client.GetObj("/libvirt/console-proxy/tokens/"+token, tokenInfo)
	if err != nil {
		return nil, err
	}
	return tokenInfo, nil
}

func (c *EtcdConnector) Associate(tenant *websocket.Conn, token string) (net.Conn, *ServiceConfig, error) {
	if token == "" {
		return nil, nil, fmt.Errorf("A non-empty token is required")
	}
	tokenInfo, err := c.resolveToken(token)
	if err != nil {
		return nil, nil, err
	}

	addr := tokenInfo.Host + ":" + tokenInfo.Port
	glog.V(1).Infof("Opening compute %s", addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, nil, err
	}

	var tlsConfig *tls.Config
	if c.TLSConfig != nil {
		glog.V(1).Info("Setting up TLS config")
		tlsConfig = &tls.Config{
			Certificates: c.TLSConfig.Certificates,
			RootCAs:      c.TLSConfig.RootCAs,
			ServerName:   tokenInfo.Host,
		}
	}

	service := &ServiceConfig{
		Type:      tokenInfo.Type,
		Insecure:  tokenInfo.Insecure,
		TLSConfig: tlsConfig,
	}

	return conn, service, nil
}
