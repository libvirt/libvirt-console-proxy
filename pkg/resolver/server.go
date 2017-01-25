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

package resolver

import (
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/libvirt/libvirt-go"
	"github.com/libvirt/libvirt-go-xml"

	"libvirt.org/libvirt-console-proxy/pkg/proxy"
)

type ConsoleServerDomain struct {
	UUID   string
	Name   string
	Tokens []string
}

type ConsoleServerHost struct {
	URI        string
	Connection *libvirt.Connect
	Name       string
	Domains    map[string]*ConsoleServerDomain
	EventID    int
}

type ConsoleServerToken struct {
	Type     string
	Address  string
	Insecure bool
	Domain   *ConsoleServerDomain
}

func eventloop() {
	for {
		libvirt.EventRunDefaultImpl()
	}
}

func init() {
	libvirt.EventRegisterDefaultImpl()
	go eventloop()
}

type ConsoleServer struct {
	Mux      *http.ServeMux
	Insecure bool
	Server   *http.Server
	Hosts    map[string]*ConsoleServerHost
	Tokens   map[string]*ConsoleServerToken
}

const tokenpath = "/consoleresolver/token/"

func getListener(dom libvirtxml.Domain, gtype string, insecure bool, consoleHost, defaultHost string) (string, error) {
	if dom.Devices == nil {
		return "", errors.New("No devices present")
	}

	for _, graphics := range dom.Devices.Graphics {
		if graphics.Type != gtype {
			continue
		}

		var host string
		if consoleHost != "" {
			host = consoleHost
		} else {
			if graphics.Listen != "" && graphics.Listen != "0.0.0.0" && graphics.Listen != "::" {
				host = graphics.Listen
			} else {
				host = defaultHost
			}
		}

		var port int
		if graphics.Type == "spice" && !insecure {
			port = graphics.TLSPort
		} else {
			port = graphics.Port
		}
		glog.V(1).Infof("Got port %d\n", port)
		if graphics.Port == 0 || graphics.Port == -1 {
			return "", errors.New("Missing port for graphics")
		}

		return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
	}

	return "", fmt.Errorf("No graphics of type '%s' configured", gtype)
}

func (c *ConsoleServer) addDomain(host *ConsoleServerHost, dom *libvirt.Domain) error {
	uuid, err := dom.GetUUIDString()
	if err != nil {
		return err
	}

	name, err := dom.GetName()
	if err != nil {
		return err
	}

	glog.V(1).Infof("Adding domain %s / %s", name, uuid)

	domxml, err := dom.GetXMLDesc(0)
	if err != nil {
		return err
	}

	var domcfg libvirtxml.Domain
	err = xml.Unmarshal([]byte(domxml), &domcfg)
	if err != nil {
		return err
	}

	meta, err := GetMetadata(dom)
	if err != nil {
		return err
	}

	domain := &ConsoleServerDomain{
		Name:   name,
		UUID:   uuid,
		Tokens: make([]string, len(meta.Consoles)),
	}

	for _, console := range meta.Consoles {
		glog.V(1).Info("Processing console record")
		secret, err := host.Connection.LookupSecretByUUIDString(console.Token)
		if err != nil {
			return err
		}
		defer secret.Free()

		token, err := secret.GetValue(0)
		if err != nil {
			return err
		}

		insecure := false
		if console.Insecure == "yes" {
			insecure = true
		}

		addr, err := getListener(domcfg, console.Type, insecure, console.Host, host.Name)
		if err != nil {
			return err
		}
		tokenInfo := &ConsoleServerToken{
			Type:     console.Type,
			Address:  addr,
			Insecure: insecure,
			Domain:   domain,
		}

		_, ok := c.Tokens[string(token)]
		if ok {
			return fmt.Errorf("Another console is already registered with token %s", token)
		}

		glog.V(1).Infof("Adding token %s for %s / %s on %s", string(token), name, uuid, addr)
		c.Tokens[string(token)] = tokenInfo
	}

	host.Domains[uuid] = domain
	return nil
}

func (c *ConsoleServer) addAllDomains(host *ConsoleServerHost) error {
	doms, err := host.Connection.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE)
	if err != nil {
		return err
	}

	host.Domains = make(map[string]*ConsoleServerDomain)
	for _, dom := range doms {
		defer dom.Free()

		err := c.addDomain(host, &dom)
		if err != nil {
			glog.V(1).Infof("Skipping domain due to error: %s", err)
		}
	}

	return nil
}

func (c *ConsoleServer) reopenHost(host *ConsoleServerHost) {
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

func (c *ConsoleServer) removeDomain(host *ConsoleServerHost, dom *ConsoleServerDomain) {
	glog.V(1).Infof("Removing domain %s / %s", dom.Name, dom.UUID)
	for _, token := range dom.Tokens {
		glog.V(1).Infof("Removing token %s for domain %s / %s",
			token, dom.Name, dom.UUID)
		delete(c.Tokens, token)
	}

	delete(host.Domains, dom.UUID)
}

func (c *ConsoleServer) removeAllDomains(host *ConsoleServerHost) {
	for _, dom := range host.Domains {
		c.removeDomain(host, dom)
	}
}

func (c *ConsoleServer) closeHost(host *ConsoleServerHost) {
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

func (c *ConsoleServer) openHost(host *ConsoleServerHost) error {
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
			err = c.addDomain(host, dom)
			if err != nil {
				glog.V(1).Infof("Skipping domain due to error: %s", err)
			}

		case libvirt.DOMAIN_EVENT_STOPPED:
			if ok {
				c.removeDomain(host, domInfo)
			}
		}
	})

	return nil
}

func NewConsoleServer(listenAddr string, insecure bool, tlsConfig *tls.Config, uris []string) (*ConsoleServer, error) {

	s := &ConsoleServer{
		Mux:      http.NewServeMux(),
		Insecure: insecure,
		Hosts:    make(map[string]*ConsoleServerHost),
		Tokens:   make(map[string]*ConsoleServerToken),
	}

	for _, uri := range uris {
		host := &ConsoleServerHost{
			URI: uri,
		}
		s.Hosts[uri] = host

		err := s.openHost(host)
		if err != nil {
			go s.reopenHost(host)
		}
	}

	s.Server = &http.Server{
		Addr:      listenAddr,
		TLSConfig: tlsConfig,
		Handler:   s.Mux,
	}

	s.Mux.HandleFunc(tokenpath, func(res http.ResponseWriter, req *http.Request) {
		s.handle(res, req)
	})

	return s, nil
}

func (s *ConsoleServer) Serve() error {
	if s.Insecure {
		err := s.Server.ListenAndServe()
		if err != nil {
			return err
		}
	} else {
		err := s.Server.ListenAndServeTLS("", "")
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *ConsoleServer) handle(res http.ResponseWriter, req *http.Request) {
	token := strings.TrimPrefix(req.URL.Path, tokenpath)

	glog.V(1).Infof("Got token request '%s'", token)

	info, ok := s.Tokens[token]
	if !ok {
		glog.V(1).Info("No matching token found")
		http.Error(res, "No token found", http.StatusNotFound)
		return
	}

	config := &proxy.ServiceConfig{
		Type:     proxy.ServiceType(info.Type),
		Address:  info.Address,
		Insecure: info.Insecure,
	}

	data, err := json.Marshal(config)
	if err != nil {
		glog.V(1).Info("Could not encode console data")
		http.Error(res, "Cannot encode console data", http.StatusInternalServerError)
	}

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)
	glog.V(1).Infof("Sending console info '%s'", string(data))
	io.WriteString(res, string(data))
}
