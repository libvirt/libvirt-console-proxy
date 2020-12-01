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
	"github.com/golang/glog"
	"golang.org/x/net/websocket"
	"net"
	"time"
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
	// Name is for logging...
	name := "T:"
	if src == c.Compute {
		name = "C:"
	}

	const maxDeadlineInMs = 500
	const deadlineIncrement = 10
	const bufferSize = 64 * 1024
	data := make([]byte, bufferSize)
	pending := 0
	offset := 0
	nextDeadline := 0
	for {
		if pending == 0 {
			// In order to reduce CPU consumption, we will continue reading with
			// a progressively incrementing timeout before writing.  We start with
			// a blocking read, then increment a deadline of 10ms at a time. Once
			// we don't read anything within the deadline, we'll write it out.
			//
			// This effectively throttles a console from overwhelming the CPU with
			// thousands of small byte packets (especially over TLS) while providing
			// a good interactive user experience.
			var err error
			var deadline time.Time
			blockingRead := true
			if nextDeadline == 0 {
				deadline = time.Time{}
			} else {
				deadline = time.Now().Add(time.Duration(nextDeadline) * time.Millisecond)
				blockingRead = false
			}
			src.SetReadDeadline(deadline)
			if nextDeadline <= maxDeadlineInMs {
				nextDeadline += deadlineIncrement
			}
			for err == nil && pending < bufferSize {
				read, err := src.Read(data[pending:])
				// If we hit the timeout/deadline...
				if e, ok := err.(net.Error); ok && e.Timeout() {
					if read == 0 && pending == 0 {
						// If we haven't read anything w/in the deadline,
						// resort to a standard blocking read
						nextDeadline = 0
					}
					pending += read
					// Break out and write whatever we have (it may be nothing)
					break
				} else if err != nil {
					return err
				} else if read == 0 {
					return nil
				}
				pending += read
				if blockingRead {
					break
				}
			}
			offset = 0
		}
		if pending > 0 {
			done, err := dst.Write(data[offset:pending])
			if err != nil {
				return err
			}
			pending -= done
			offset += done
			glog.V(3).Infof("%s Wrote %d - deadline %d", name, done, nextDeadline-deadlineIncrement)
		}
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
