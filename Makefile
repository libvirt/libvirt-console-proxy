
CMDS := libvirt-console-proxy

GOSRC := $(wildcard cmd/*/*.go) $(wildcard consoleproxy/*.go)

all: $(CMDS)

glide.lock: glide.yaml
	glide install

libvirt-console-proxy: cmd/libvirt-console-proxy/libvirt-console-proxy.go $(GOSRC) glide.lock
	go build -o $@ $<

clean:
	rm -f $(CMDS)
