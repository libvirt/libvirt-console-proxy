
CMDS := virtconsoleproxyd virtconsoleresolverd virtconsoleresolveradm

GOSRC := $(wildcard cmd/*/*.go) $(wildcard cmd/*/*/*.go) $(wildcard pkg/*/*.go)

all: $(CMDS:%=build/%)

build/virtconsoleproxyd: cmd/virtconsoleproxyd/virtconsoleproxyd.go $(GOSRC) go.sum
	go build -o $@ $<

build/virtconsoleresolverd: cmd/virtconsoleresolverd/virtconsoleresolverd.go $(GOSRC) go.sum
	go build -o $@ $<

build/virtconsoleresolveradm: cmd/virtconsoleresolveradm/main.go $(GOSRC) go.sum
	go build -o $@ $<

clean:
	rm -rf build/
