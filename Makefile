
CMDS := virtconsoleproxyd

GOSRC := $(wildcard cmd/*/*.go) $(wildcard consoleproxy/*.go)

all: $(CMDS:%=build/%)

glide.lock: glide.yaml
	glide install

build/virtconsoleproxyd: cmd/virtconsoleproxyd/virtconsoleproxyd.go $(GOSRC) glide.lock
	go build -o $@ $<

clean:
	rm -rf build/
