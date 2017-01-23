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
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"io/ioutil"
	"net/http"
	"net/url"
)

type Resolver interface {
	Resolve(token string) (*ServiceConfig, error)
}

type BuiltinResolver struct {
	tokens map[string]ServiceConfig
}

type ExternalResolver struct {
	connectURI *url.URL
	client     *http.Client
}

func NewBuiltinResolver(tokenfile string) (*BuiltinResolver, error) {
	data, err := ioutil.ReadFile(tokenfile)
	if err != nil {
		return nil, err
	}

	var tokens map[string]ServiceConfig
	err = json.Unmarshal(data, &tokens)
	if err != nil {
		return nil, err
	}
	glog.V(1).Info("Loaded tokens %s", tokens)

	return &BuiltinResolver{
		tokens: tokens,
	}, nil
}

func (r *BuiltinResolver) Resolve(token string) (*ServiceConfig, error) {
	entry, ok := r.tokens[token]
	if !ok {
		return nil, fmt.Errorf("No token found with id '%s'", token)
	}

	return &entry, nil
}

func NewExternalResolver(connectURI string, tlsConfig *tls.Config) (*ExternalResolver, error) {
	parsedURL, err := url.Parse(connectURI)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: transport}

	return &ExternalResolver{
		connectURI: parsedURL,
		client:     client,
	}, nil
}

func (r *ExternalResolver) Resolve(token string) (*ServiceConfig, error) {
	tokenURI := *r.connectURI

	tokenURI.Path = tokenURI.Path + "/token/" + token

	res, err := r.client.Get(tokenURI.String())
	if err != nil {
		glog.V(1).Infof("Error from resolver %s", err)
		return nil, err
	}

	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Unable to resolve token: %s", data)
	}
	glog.V(1).Infof("Resolved '%s' to '%s'", token, data)

	var service ServiceConfig
	err = json.Unmarshal(data, &service)
	if err != nil {
		return nil, err
	}

	return &service, nil
}
