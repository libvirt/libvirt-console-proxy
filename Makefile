
CMDS := virtconsoleproxyd virtconsoleresolverd

GOSRC := $(wildcard cmd/*/*.go) $(wildcard pkg/*/*.go)

all: $(CMDS:%=build/%)

glide.lock: glide.yaml
	if test -d vendor; then \
                glide update --strip-vendor; \
        else \
                glide install --strip-vendor; \
        fi

build/virtconsoleproxyd: cmd/virtconsoleproxyd/virtconsoleproxyd.go $(GOSRC) glide.lock
	mkdir -p build/src/libvirt.org && \
	GOPATH=`pwd`/build && \
	cd build/src/libvirt.org && (test -e libvirt-console-proxy || ln -s ../../.. libvirt-console-proxy ) && \
	cd libvirt-console-proxy && go build -o `pwd`/$@ $<

build/virtconsoleresolverd: cmd/virtconsoleresolverd/virtconsoleresolverd.go $(GOSRC) glide.lock
	mkdir -p build/src/libvirt.org && \
	GOPATH=`pwd`/build && \
	cd build/src/libvirt.org && (test -e libvirt-console-proxy || ln -s ../../.. libvirt-console-proxy ) && \
	cd libvirt-console-proxy && go build -o `pwd`/$@ $<

clean:
	rm -rf build/
