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

	"github.com/spf13/cobra"
	"libvirt.org/libvirt-go"

	"libvirt.org/libvirt-console-proxy/pkg/resolver"
)

var disableCmd = &cobra.Command{
	Use:   "disable DOMAIN",
	Short: "Disable consoles for a domain",
	Long:  "Disable access to consoles for a domain",
	Run:   doDisable,
	Args:  cobra.ExactArgs(1),
}

func doDisable(cmd *cobra.Command, args []string) {
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

	meta, err := resolver.GetMetadata(dom)
	if err != nil {
		lverr, ok := err.(libvirt.Error)
		if ok && lverr.Code == libvirt.ERR_NO_DOMAIN_METADATA {
			fmt.Printf("Access to domain '%s' already disabled\n", domname)
			return
		}
		fmt.Fprintf(os.Stderr, "Cannot query current metadata for domain '%s': %s\n",
			domname, err)
		os.Exit(1)
	}

	for _, console := range meta.Consoles {
		sec, err := conn.LookupSecretByUUIDString(console.Token)
		if err != nil {
			lverr, ok := err.(libvirt.Error)
			if ok && lverr.Code == libvirt.ERR_NO_SECRET {
				continue
			}
			fmt.Fprintf(os.Stderr, "Cannot lookup secret '%s' for domain '%s': %s\n",
				console.Token, domname, err)
			os.Exit(1)
		}
		err = sec.Undefine()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot delete secret '%s' for domain '%s': %s\n",
				console.Token, domname, err)
			os.Exit(1)
		}
	}

	err = resolver.SetMetadata(dom, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot disable access to domain '%s': %s\n",
			domname, err)
		os.Exit(1)
	}

	fmt.Printf("Disabled access to domain '%s'\n", domname)
}

func init() {
	RootCmd.AddCommand(disableCmd)
}
