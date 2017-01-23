
CMDS := virtconsoleproxyd

GOSRC := $(wildcard cmd/*/*.go) $(wildcard consoleproxy/*.go)

all: $(CMDS:%=build/%)

glide.lock: glide.yaml
	glide install

build/virtconsoleproxyd: cmd/virtconsoleproxyd/virtconsoleproxyd.go $(GOSRC) glide.lock
	mkdir -p build/src/libvirt.org && \
	GOPATH=`pwd`/build && \
	cd build/src/libvirt.org && (test -e libvirt-console-proxy || ln -s ../../.. libvirt-console-proxy ) && \
	cd libvirt-console-proxy && go build -o `pwd`/$@ $<

clean:
	rm -rf build/
