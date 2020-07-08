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
	"encoding/binary"
	"fmt"
	"golang.org/x/net/websocket"
	"net"
)

type ConsoleClientVNC struct {
	Tenant    net.Conn
	Compute   net.Conn
	Insecure  bool
	TLSConfig *tls.Config
}

func NewConsoleClientVNC(tenant *websocket.Conn, compute net.Conn, insecure bool, tlsConfig *tls.Config) *ConsoleClientVNC {

	client := &ConsoleClientVNC{
		Tenant:    tenant,
		Compute:   compute,
		Insecure:  insecure,
		TLSConfig: tlsConfig,
	}

	tenant.PayloadType = websocket.BinaryFrame

	return client
}

func (c *ConsoleClientVNC) handshakeCompute() error {
	versionstr := make([]byte, 12)
	if err := binary.Read(c.Compute, binary.BigEndian, versionstr); err != nil {
		return err
	}

	if string(versionstr) != "RFB 003.008\n" {
		return fmt.Errorf("Expected version 3.8, got %s", versionstr)
	}

	if err := binary.Write(c.Compute, binary.BigEndian, versionstr); err != nil {
		return err
	}

	return nil
}

func (c *ConsoleClientVNC) handshakeTenant() error {
	versionstr := []byte("RFB 003.008\n")
	if err := binary.Write(c.Tenant, binary.BigEndian, versionstr); err != nil {
		return err
	}

	if err := binary.Read(c.Tenant, binary.BigEndian, versionstr); err != nil {
		return err
	}

	if string(versionstr) != "RFB 003.008\n" {
		return fmt.Errorf("Expected version 3.8, got %s", versionstr)
	}

	return nil
}

var (
	AUTH_UNKNOWN  = uint8(0)
	AUTH_NONE     = uint8(1)
	AUTH_VENCRYPT = uint8(19)

	SUBAUTH_VENCRYPT_UNKNOWN  = uint32(0)
	SUBAUTH_VENCRYPT_X509NONE = uint32(260)
)

func (c *ConsoleClientVNC) authComputeCheck() error {
	var result uint32

	if err := binary.Read(c.Compute, binary.BigEndian, &result); err != nil {
		return err
	}

	if result == 0 {
		return nil
	}

	var reasonlen uint32
	if err := binary.Read(c.Compute, binary.BigEndian, &reasonlen); err != nil {
		return err
	}
	if reasonlen > 65536 {
		return fmt.Errorf("Auth result reason too long %d", reasonlen)
	}
	reason := make([]byte, reasonlen)
	if err := binary.Read(c.Compute, binary.BigEndian, &reason); err != nil {
		return err
	}

	return fmt.Errorf("Auth failed %s", string(reason))
}

func (c *ConsoleClientVNC) authComputeVeNCrypt() error {
	var major, minor uint8
	if err := binary.Read(c.Compute, binary.BigEndian, &major); err != nil {
		return err
	}
	if err := binary.Read(c.Compute, binary.BigEndian, &minor); err != nil {
		return err
	}

	if major != 0 && minor != 2 {
		return fmt.Errorf("Only VeNCrypt version 0.2 supported, not %d.%d", major, minor)
	}

	binary.Write(c.Compute, binary.BigEndian, major)
	binary.Write(c.Compute, binary.BigEndian, minor)
	var status uint8
	if err := binary.Read(c.Compute, binary.BigEndian, &status); err != nil {
		return err
	}

	var nauth uint8
	if err := binary.Read(c.Compute, binary.BigEndian, &nauth); err != nil {
		return err
	}

	auth := make([]uint32, nauth)
	if err := binary.Read(c.Compute, binary.BigEndian, &auth); err != nil {
		return err
	}

	chooseAuth := SUBAUTH_VENCRYPT_UNKNOWN
	for i := 0; i < int(nauth); i++ {
		switch auth[i] {
		case SUBAUTH_VENCRYPT_X509NONE:
			chooseAuth = auth[i]

		default:
			return fmt.Errorf("Unsupported VeNCrypt sub-auth %d", auth[i])
		}
	}

	if chooseAuth == SUBAUTH_VENCRYPT_UNKNOWN {
		return fmt.Errorf("No supported VeNCrypt sub-auth types")
	}

	if err := binary.Write(c.Compute, binary.BigEndian, &chooseAuth); err != nil {
		return err
	}

	if err := binary.Read(c.Compute, binary.BigEndian, &status); err != nil {
		return err
	}
	if status != 1 {
		return fmt.Errorf("Server rejected request for sub-auth %d", chooseAuth)
	}

	c.TLSConfig.ServerName, _, _ = net.SplitHostPort(c.Compute.RemoteAddr().String())
	conn := tls.Client(c.Compute, c.TLSConfig)

	if err := conn.Handshake(); err != nil {
		return err
	}

	c.Compute = conn

	switch chooseAuth {
	case SUBAUTH_VENCRYPT_X509NONE:
		if err := c.authComputeCheck(); err != nil {
			return nil
		}

	default:
		return fmt.Errorf("Unexpected subauth type %d", chooseAuth)
	}

	return nil
}

func (c *ConsoleClientVNC) authCompute() error {
	var numSecType uint8

	if err := binary.Read(c.Compute, binary.BigEndian, &numSecType); err != nil {
		return err
	}

	secTypes := make([]uint8, numSecType)
	if err := binary.Read(c.Compute, binary.BigEndian, &secTypes); err != nil {
		return err
	}

	chooseAuth := AUTH_UNKNOWN
	for _, secType := range secTypes {
		switch secType {
		case AUTH_NONE:
			if !c.Insecure {
				return fmt.Errorf("Auth type NONE not permitted without Insecure flag")
			}
			chooseAuth = secType
			break

		case AUTH_VENCRYPT:
			if c.Insecure {
				return fmt.Errorf("Auth type VENCRYPT not permitted with Insecure flag")
			}
			chooseAuth = secType
			break

		default:
			return fmt.Errorf("Unsupported sec type %d", secType)
		}
	}

	if chooseAuth == AUTH_UNKNOWN {
		return fmt.Errorf("No supported auth type found")
	}

	if err := binary.Write(c.Compute, binary.BigEndian, chooseAuth); err != nil {
		return err
	}

	switch chooseAuth {
	case AUTH_NONE:
		if err := c.authComputeCheck(); err != nil {
			return nil
		}

	case AUTH_VENCRYPT:
		if err := c.authComputeVeNCrypt(); err != nil {
			return err
		}
	}

	return nil
}

func (c *ConsoleClientVNC) authTenant() error {
	numSecType := uint8(1)
	secType := []uint8{AUTH_NONE}

	if err := binary.Write(c.Tenant, binary.BigEndian, numSecType); err != nil {
		return err
	}

	if err := binary.Write(c.Tenant, binary.BigEndian, secType); err != nil {
		return err
	}

	var gotSecType uint8
	if err := binary.Read(c.Tenant, binary.BigEndian, &gotSecType); err != nil {
		return err
	}

	if gotSecType != AUTH_NONE {
		return fmt.Errorf("Expected sec type %d got %d", AUTH_NONE, gotSecType)
	}

	var status uint32
	status = 0
	if err := binary.Write(c.Tenant, binary.BigEndian, &status); err != nil {
		return err
	}

	return nil
}

func (c *ConsoleClientVNC) Close() {
	c.Tenant.Close()
	c.Compute.Close()
}

func (c *ConsoleClientVNC) proxyData(src net.Conn, dst net.Conn) error {
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

func (c *ConsoleClientVNC) proxyToCompute() error {
	err := c.proxyData(c.Tenant, c.Compute)
	c.Compute.Close()
	return err
}

func (c *ConsoleClientVNC) proxyToTenant() error {
	err := c.proxyData(c.Compute, c.Tenant)
	c.Tenant.Close()
	return err
}

func (c *ConsoleClientVNC) Proxy() error {
	if err := c.handshakeCompute(); err != nil {
		c.Close()
		return err
	}

	if err := c.handshakeTenant(); err != nil {
		c.Close()
		return err
	}

	if err := c.authCompute(); err != nil {
		c.Close()
		return err
	}

	if err := c.authTenant(); err != nil {
		c.Close()
		return err
	}

	go c.proxyToTenant()

	return c.proxyToCompute()
}
