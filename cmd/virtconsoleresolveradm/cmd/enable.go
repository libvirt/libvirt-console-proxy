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

package cmd

import (
	"fmt"
	"os"

	"github.com/libvirt/libvirt-go"
	"github.com/libvirt/libvirt-go-xml"
	"github.com/satori/go.uuid"
	"github.com/spf13/cobra"

	"libvirt.org/libvirt-console-proxy/pkg/resolver"
)

var (
	enableCmd = &cobra.Command{
		Use:   "enable DOMAIN",
		Short: "Enable consoles for a domain",
		Long:  "Enable consoles for a domain",
		Run:   doEnable,
	}
	insecure *bool
	host     *string
)

func createConsole(ctype string, index int, conn *libvirt.Connect, domname, domuuid string) resolver.ConsoleServerProxyMetadataConsole {
	tokenID := uuid.NewV4()
	tokenValue := uuid.NewV4()
	console := resolver.ConsoleServerProxyMetadataConsole{
		Token:    tokenID.String(),
		Type:     ctype,
		Index:    index,
		Insecure: "no",
	}

	if *insecure {
		console.Insecure = "yes"
	}

	if *host != "" {
		console.Host = *host
	}

	secretcfg := libvirtxml.Secret{
		Ephemeral: "no",
		Private:   "no",
		Description: fmt.Sprintf("Token for %s console proxy domain %s",
			ctype, domuuid),
		UUID: tokenID.String(),
	}

	secretxml, err := secretcfg.Marshal()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot format secret XML for domain '%s': %s\n",
			domname, err)
		os.Exit(1)
	}

	secret, err := conn.SecretDefineXML(secretxml, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot define secret XML for domain '%s': %s\n",
			domname, err)
		os.Exit(1)
	}

	err = secret.SetValue([]byte(tokenValue.String()), 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot set secret value for domain '%s': %s\n",
			domname, err)
		os.Exit(1)
	}

	return console
}

func doEnable(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Missing domain name/uuid")
		os.Exit(1)
	}

	conn, err := libvirt.NewConnect(connect)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot connect to hypervisor '%s': %s\n",
			connect, err)
		os.Exit(1)
	}
	defer conn.Close()

	dom, err := GetDomain(conn, args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot get domain '%s': %s\n",
			args[0], err)
		os.Exit(1)
	}
	defer dom.Free()

	domname, err := dom.GetName()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot get domain '%s' name: %s\n",
			args[0], err)
		os.Exit(1)
	}

	domuuid, err := dom.GetUUIDString()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot get domain '%s' UUID: %s\n",
			domname, err)
		os.Exit(1)
	}

	meta, err := resolver.GetMetadata(dom)
	if err == nil {
		fmt.Printf("Access to domain '%s' already enabled\n", domname)
		return
	}

	domxml, err := dom.GetXMLDesc(0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot get domain '%s' XML config: %s\n",
			domname, err)
		os.Exit(1)
	}

	domcfg := libvirtxml.Domain{}
	err = domcfg.Unmarshal(domxml)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot parse domain '%s' XML config: %s\n",
			domname, err)
		os.Exit(1)
	}

	if domcfg.Devices == nil {
		fmt.Fprintf(os.Stderr, "No devices present for domain '%s': %s\n",
			domname, err)
		os.Exit(1)
	}

	meta = &resolver.ConsoleServerProxyMetadata{}

	for _, graphics := range domcfg.Devices.Graphics {
		switch graphics.Type {
		case "spice":
			meta.Consoles = append(meta.Consoles,
				createConsole("spice", 0, conn, domname, domuuid))
		case "vnc":
			meta.Consoles = append(meta.Consoles,
				createConsole("vnc", 0, conn, domname, domuuid))
		}

	}

	for idx, chardev := range domcfg.Devices.Serials {
		if chardev.Type == "tcp" {
			meta.Consoles = append(meta.Consoles,
				createConsole("serial", idx, conn, domname, domuuid))
		}
	}

	for idx, chardev := range domcfg.Devices.Consoles {
		if chardev.Type == "tcp" {
			meta.Consoles = append(meta.Consoles,
				createConsole("console", idx, conn, domname, domuuid))
		}
	}

	err = resolver.SetMetadata(dom, meta)
	if err != nil {
		for _, console := range meta.Consoles {
			sec, _ := conn.LookupSecretByUUIDString(console.Token)
			if sec != nil {
				sec.Undefine()
			}
		}
		fmt.Fprintf(os.Stderr, "Cannot set metadata XML for domain '%s': %s\n",
			domname, err)
		os.Exit(1)
	}

	fmt.Printf("Enabled access to domain '%s'\n", domname)
}

func init() {
	RootCmd.AddCommand(enableCmd)
	insecure = enableCmd.Flags().Bool("insecure", false, "Request insecure console connection")
	host = enableCmd.Flags().String("host", "", "Override default hostname for connections")
}
