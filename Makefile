build:
	dune $@

OCAML_VERSION ?= 4.12.1
init:
	opam switch create . -y --no-install $(OCAML_VERSION)
	opam install . -y --deps-only
	opam install -y ocaml-lsp-server ocamlformat

start:
	dune exec dream-oidc-example
