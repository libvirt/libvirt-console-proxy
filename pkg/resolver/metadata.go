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
 * Copyright (C) 2017 Red Hat, Inc.
 *
 */

package resolver

import (
	"encoding/xml"

	"github.com/golang/glog"
	"github.com/libvirt/libvirt-go"
)

/*
 * The libvirt metadata is in namespace
 *
 *   xmlns:lcp="http://libvirt.org/schemas/console-proxy/1.0"
 *
 * It can represent multiple consoles per guest domain. Each exposed
 * console must provide a globally unique secret token value. This
 * token is identified by a UUID that refers to a libvirt secret
 * object storing the actual token value.
 *
 * The type is one of "vnc", "spice", or "serial"
 *
 * The host attribute is optional and if omitted the result of the
 * virConnectGetHostname() method will be used.
 *
 * The insecure attribute is optional and defaults to "no" if omitted
 *
 * <lcp:consoles>
 *   <lcp:console type="vnc" index="0" token="bcbb4165-0a92-4a9c-a66d-9361ff4a45d6" insecure="yes" host="192.168.122.2"/>
 *   <lcp:console type="spice" index="0" token="55806c7d-8e93-456f-829b-607d8c198367" host="192.168.122.2"/>
 *   <lcp:console type="serial" index="0" token="55806c7d-8e93-456f-829b-607d8c198367" host="192.168.122.2"/>
 *   <lcp:console type="console" index="0" token="55806c7d-8e93-456f-829b-607d8c198367" host="192.168.122.2"/>
 * </lcp:consoles>
 */

const xmlns = "http://libvirt.org/schemas/console-proxy/1.0"
const xmlprefix = "lcp"

type ConsoleServerProxyMetadataConsole struct {
	Token    string `xml:"token,attr"`
	Type     string `xml:"type,attr"`
	Index    int    `xml:"port,attr"`
	Host     string `xml:"host,attr,omitempty"`
	Insecure string `xml:"insecure,attr"`
}

type ConsoleServerProxyMetadata struct {
	XMLName  xml.Name                            `xml:"consoles"`
	Consoles []ConsoleServerProxyMetadataConsole `xml:"console"`
}

func SetMetadata(dom *libvirt.Domain, meta *ConsoleServerProxyMetadata) error {
	if meta != nil {
		metaxml, err := xml.Marshal(meta)
		if err != nil {
			return err
		}

		return dom.SetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, string(metaxml), xmlprefix, xmlns, libvirt.DOMAIN_AFFECT_LIVE|libvirt.DOMAIN_AFFECT_CONFIG)
	} else {
		return dom.SetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, "", "", xmlns, libvirt.DOMAIN_AFFECT_LIVE|libvirt.DOMAIN_AFFECT_CONFIG)
	}
}

func GetMetadata(dom *libvirt.Domain) (*ConsoleServerProxyMetadata, error) {
	metaxml, err := dom.GetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, xmlns, libvirt.DOMAIN_AFFECT_LIVE)
	if err != nil {
		return nil, err
	}

	glog.V(1).Infof("Got metadata %s", metaxml)
	var meta ConsoleServerProxyMetadata
	err = xml.Unmarshal([]byte(metaxml), &meta)
	if err != nil {
		return nil, err
	}

	return &meta, nil
}
