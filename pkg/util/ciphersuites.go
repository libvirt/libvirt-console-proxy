// +build go1.14

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

package util

import "crypto/tls"

// Used for golang 1.14 and later
func CipherNameToConst(name string) (uint16, bool) {
	for _, suite := range tls.CipherSuites() {
		if suite.Name == name {
			return suite.ID, true
		}
	}
	return 0, false
}

func TLSNameToConst(name string) (uint16, bool) {
	switch name {
	case "VersionTLS10":
		return tls.VersionTLS10, true
	case "VersionTLS11":
		return tls.VersionTLS11, true
	case "VersionTLS12":
		return tls.VersionTLS12, true
	case "VersionTLS13":
		return tls.VersionTLS13, true
	default:
		return 0, false
	}
}
