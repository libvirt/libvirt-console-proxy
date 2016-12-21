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
	"encoding/xml"
	"fmt"
	"github.com/golang/glog"
	libvirt "github.com/libvirt/libvirt-go"
	"golang.org/x/net/websocket"
	"net"
	"time"
)

type LibvirtConnectorDomain struct {
	UUID   string
	Name   string
	Tokens []string
}

type LibvirtConnectorHost struct {
	URI        string
	Connection *libvirt.Connect
	Name       string
	Domains    map[string]*LibvirtConnectorDomain
	EventID    int
}

type LibvirtConnectorToken struct {
	Type     ServiceType
	Host     string
	Port     string
	Insecure bool
	Domain   *LibvirtConnectorDomain
}

// LibvirtConnector allows monitors running VMs on libvirt hosts
// and dynamically exposes them to tenants
type LibvirtConnector struct {
	TLSConfig *tls.Config
	Hosts     map[string]*LibvirtConnectorHost
	Tokens    map[string]*LibvirtConnectorToken
}

const XMLNS = "http://libvirt.org/schemas/console-proxy/1.0"

func eventloop() {
	for {
		libvirt.EventRunDefaultImpl()
	}
}

func init() {
	libvirt.EventRegisterDefaultImpl()
	go eventloop()
}

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
 *   <lcp:console type="vnc" token="bcbb4165-0a92-4a9c-a66d-9361ff4a45d6" insecure="yes" host="192.168.122.2"/>
 *   <lcp:console type="spice" token="55806c7d-8e93-456f-829b-607d8c198367" host="192.168.122.2"/>
 * </lcp:consoles>
 */

type LibvirtProxyMetadataConsole struct {
	Token    string `xml:"token,attr"`
	Type     string `xml:"type,attr"`
	Host     string `xml:"host,attr,omitempty"`
	Insecure string `xml:"insecure,attr"`
}

type LibvirtProxyMetadata struct {
	XMLName  xml.Name                      `xml:"consoles"`
	Consoles []LibvirtProxyMetadataConsole `xml:"console"`
}

func (c *LibvirtConnector) addDomain(host *LibvirtConnectorHost, dom *libvirt.Domain) error {
	uuid, err := dom.GetUUIDString()
	if err != nil {
		return err
	}

	name, err := dom.GetName()
	if err != nil {
		return err
	}

	glog.V(1).Infof("Adding domain %s / %s", name, uuid)

	metaxml, err := dom.GetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, XMLNS, libvirt.DOMAIN_AFFECT_LIVE)
	if err != nil {
		return err
	}

	var meta LibvirtProxyMetadata
	err = xml.Unmarshal([]byte(metaxml), &meta)
	if err != nil {
		return err
	}

	domain := &LibvirtConnectorDomain{
		Name:   name,
		UUID:   uuid,
		Tokens: make([]string, len(meta.Consoles)),
	}

	for _, console := range meta.Consoles {
		secret, err := host.Connection.LookupSecretByUUIDString(console.Token)
		if err != nil {
			return err
		}
		defer secret.Free()

		token, err := secret.GetValue(0)
		if err != nil {
			return err
		}

		domhost := host.Name
		if console.Host != "" {
			domhost = console.Host
		}
		insecure := false
		if console.Insecure == "yes" {
			insecure = true
		}
		tokenInfo := &LibvirtConnectorToken{
			Type:     ServiceType(console.Type),
			Host:     domhost,
			Port:     "5900",
			Insecure: insecure,
			Domain:   domain,
		}

		glog.V(1).Infof("Adding token %s for %s / %s on %s", string(token), name, uuid, domhost)
		c.Tokens[string(token)] = tokenInfo
	}

	host.Domains[uuid] = domain
	return nil
}

func (c *LibvirtConnector) addAllDomains(host *LibvirtConnectorHost) error {
	doms, err := host.Connection.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE)
	if err != nil {
		return err
	}

	host.Domains = make(map[string]*LibvirtConnectorDomain)
	for _, dom := range doms {
		defer dom.Free()

		err := c.addDomain(host, &dom)
		if err != nil {
			glog.V(1).Infof("Skipping domain due to error: %s", err)
		}
	}

	return nil
}

func (c *LibvirtConnector) reopenHost(host *LibvirtConnectorHost) {
	c.closeHost(host)

	for {
		err := c.openHost(host)
		if err == nil {
			break
		}

		c.closeHost(host)
		glog.V(1).Infof("Failed to open host %s, retry in 15", err)
		time.Sleep(time.Second * 15)
	}
}

func (c *LibvirtConnector) removeDomain(host *LibvirtConnectorHost, dom *LibvirtConnectorDomain) {
	glog.V(1).Infof("Removing domain %s / %s", dom.Name, dom.UUID)
	for _, token := range dom.Tokens {
		glog.V(1).Infof("Removing token %s for domain %s / %s",
			token, dom.Name, dom.UUID)
		delete(c.Tokens, token)
	}

	delete(host.Domains, dom.UUID)
}

func (c *LibvirtConnector) removeAllDomains(host *LibvirtConnectorHost) {
	for _, dom := range host.Domains {
		c.removeDomain(host, dom)
	}
}

func (c *LibvirtConnector) closeHost(host *LibvirtConnectorHost) {
	if host.Connection == nil {
		return
	}
	host.Name = ""

	c.removeAllDomains(host)

	if host.EventID != 0 {
		host.Connection.DomainEventDeregister(host.EventID)
		host.EventID = 0
	}
	host.Connection.UnregisterCloseCallback()
	host.Connection.Close()
	host.Connection = nil
}

func (c *LibvirtConnector) openHost(host *LibvirtConnectorHost) error {
	var err error
	host.Connection, err = libvirt.NewConnect(host.URI)
	if err != nil {
		return err
	}

	glog.V(1).Info("Opened connection, initializing host")
	host.Name, err = host.Connection.GetHostname()
	if err != nil {
		return err
	}

	err = c.addAllDomains(host)
	if err != nil {
		return err
	}

	err = host.Connection.RegisterCloseCallback(func(conn *libvirt.Connect, reason libvirt.ConnectCloseReason) {
		glog.V(1).Infof("Connection closed %d, starting reopen", reason)
		go c.reopenHost(host)
	})
	if err != nil {
		return err
	}

	host.EventID, err = host.Connection.DomainEventLifecycleRegister(nil, func(conn *libvirt.Connect, dom *libvirt.Domain, event *libvirt.DomainEventLifecycle) {
		uuid, err := dom.GetUUIDString()
		if err != nil {
			return
		}

		domInfo, ok := host.Domains[uuid]

		switch event.Event {
		case libvirt.DOMAIN_EVENT_STARTED:
			if ok {
				c.removeDomain(host, domInfo)
			}
			c.addDomain(host, dom)

		case libvirt.DOMAIN_EVENT_STOPPED:
			if ok {
				c.removeDomain(host, domInfo)
			}
		}
	})

	return nil
}

func NewLibvirtConnector(uris []string, tlsConfig *tls.Config) *LibvirtConnector {

	connector := &LibvirtConnector{
		TLSConfig: tlsConfig,
		Hosts:     make(map[string]*LibvirtConnectorHost),
		Tokens:    make(map[string]*LibvirtConnectorToken),
	}

	for _, uri := range uris {
		host := &LibvirtConnectorHost{
			URI: uri,
		}
		connector.Hosts[uri] = host

		err := connector.openHost(host)
		if err != nil {
			go connector.reopenHost(host)
		}
	}

	return connector
}

func (c *LibvirtConnector) Associate(tenant *websocket.Conn) (net.Conn, *ServiceConfig, error) {
	req := tenant.Request()

	req.ParseForm()

	token, ok := req.Form["token"]
	if !ok {
		return nil, nil, fmt.Errorf("Token parameter is missing")
	}

	if len(token) != 1 {
		return nil, nil, fmt.Errorf("Expected a single token parameter")
	}

	glog.V(1).Infof("Finding token %s", token[0])
	tokenInfo, ok := c.Tokens[token[0]]
	if !ok {
		return nil, nil, fmt.Errorf("No token info with value %s", token)
	}

	addr := tokenInfo.Host + ":" + tokenInfo.Port
	glog.V(1).Infof("Opening compute %s domain %s / %s", addr, tokenInfo.Domain.Name, tokenInfo.Domain.UUID)

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
