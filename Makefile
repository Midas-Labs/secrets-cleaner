# Compromised API key cleanup — build and run targets.
#
#   make build                 build the secretsweep CLI
#   make check                 vet + unit tests
#   make tui PATHS=<dir...>    open the interactive TUI
#   make scan PATHS=<dir...>   Trivy + full-history scan (report only)
#   make dry-run PATHS=<dir...> preview the rewrite, nothing modified
#   make prune PATHS=<dir...>  find keys with Trivy and rewrite history
#
# PATHS accepts one or more repositories or folders (space separated).
# scan/dry-run/tui default to the current directory; prune refuses to run
# without an explicit PATHS because it permanently rewrites Git history.

GO     ?= go
BINARY := secretsweep/secretsweep
PATHS  ?= .

.PHONY: all build check test vet tui scan dry-run prune clean

all: build

build:
	cd secretsweep && $(GO) build -o secretsweep .

vet:
	cd secretsweep && $(GO) vet ./...

test:
	cd secretsweep && $(GO) test ./...

check: vet test

tui: build
	./$(BINARY) $(PATHS)

scan: build
	./$(BINARY) --headless --action scan $(PATHS)

dry-run: build
	./$(BINARY) --headless --action dry-run $(PATHS)

prune: build
ifeq ($(origin PATHS),file)
	$(error make prune permanently rewrites Git history; pass the targets explicitly, e.g. make prune PATHS=/secure/work/mirrors)
endif
	./$(BINARY) --headless --action rewrite --yes $(PATHS)

clean:
	rm -f $(BINARY)
