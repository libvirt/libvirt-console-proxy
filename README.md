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
welcome at any time. The preferred submission method is to use
git send-email to submit patches to the libvir-list@redhat.com
mailing list. eg. to send a single patch

```
  # git send-email --to libvir-list@redhat.com --subject-prefix "PATCH console-proxy" \
       --smtp-server=$HOSTNAME -1
```

Or to send all patches on the current branch, against master

```
  $ git send-email --to libvir-list@redhat.com --subject-prefix "PATCH console-proxy" \
       --smtp-server=$HOSTNAME --no-chain-reply-to --cover-letter --annotate \
       master..
```

Note the master GIT repository is at

```
   http://libvirt.org/git/?p=libvirt-console-proxy.git;a=summary
```

The following automatic read-only mirrors are available as a
convenience to allow contributors to "fork" the repository:

```
  https://gitlab.com/libvirt/libvirt-console-proxy
  https://github.com/libvirt/libvirt-console-proxy
```

While you can send pull-requests to these mirrors, they will be
re-submitted via emai to the mailing list for review before
being merged, unless they are trivial/obvious bug fixes.

