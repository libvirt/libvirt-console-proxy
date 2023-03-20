# libvirt-console-proxy [![Build Status](https://travis-ci.org/libvirt/libvirt-console-proxy.svg?branch=master)](https://travis-ci.org/libvirt/libvirt-console-proxy) [![GoDoc](https://godoc.org/github.com/libvirt/libvirt-console-proxy?status.svg)](https://godoc.org/github.com/libvirt/libvirt-console-proxy)

Websockets console proxy for VNC, SPICE and serial consoles

This package provides a general purpose websockets proxy frontend for VNC,
SPICE and serial console servers.

## Building

This project uses go vendoring for 3rd party deps and does not keep the
deps in git. The 'glide' tool must be used to populate the vendor/
directory with the 3rd party modules. If not already available via your
OS distribution packages, install glide from:

* https://github.com/Masterminds/glide

and then run 'glide install' to populate vendor/

## Contributing

Bug fixes and other improvements to the libvirt-console-proxy are
welcome at any time. The preferred submission method is via the gitlab
project:

```
  https://gitlab.com/libvirt/libvirt-console-proxy
```

The following automatic read-only mirrors are available as a
convenience to allow contributors to "fork" the repository:

```
  https://github.com/libvirt/libvirt-console-proxy
```
