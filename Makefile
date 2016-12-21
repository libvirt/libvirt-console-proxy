
CMDS := virt-console-proxyd

GOSRC := $(wildcard cmd/*/*.go) $(wildcard consoleproxy/*.go)

all: $(CMDS)

glide.lock: glide.yaml
	glide install

virt-console-proxyd: cmd/virt-console-proxyd/virt-console-proxyd.go $(GOSRC) glide.lock
	go build -o $@ $<

clean:
	rm -f $(CMDS)
