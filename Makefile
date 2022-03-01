OCAML_VERSION ?= 4.12.1

init:
	git submodule init
	git submodule update
	opam switch create . -y --no-install $(OCAML_VERSION)
	opam install . -y --deps-only
	opam install -y ocaml-lsp-server ocamlformat

build:
	dune $@

start:
	dune exec dream-oauth2-example
