
CMDS := virtconsoleproxyd

GOSRC := $(wildcard cmd/*/*.go) $(wildcard consoleproxy/*.go)

all: $(CMDS)

glide.lock: glide.yaml
	glide install

virtconsoleproxyd: cmd/virtconsoleproxyd/virtconsoleproxyd.go $(GOSRC) glide.lock
	go build -o $@ $<

clean:
	rm -f $(CMDS)
