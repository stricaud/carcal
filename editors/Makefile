# Editor integrations for .posa decoders.
#
#   make install      install into every editor found (VSCodium, VS Code, Cursor)
#   make uninstall    remove them again
#   make list         show what is installed where
#   make package      build a .vsix (needs npx vsce), for sharing
#
# Install into one editor only:   make install EDITORS=~/.vscode-oss/extensions
#
# The grammar is NOT kept here: carcal loads grammars/posa.tmLanguage.json at
# runtime for its own built-in editor, so that file is the single source and this
# Makefile copies it into the extension at install time.

NAME    := carcal.posa
VERSION := $(shell sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' vscode-posa/package.json)
EXT     := $(NAME)-$(VERSION)

ROOT    := $(CURDIR)/..
GRAMMAR := $(ROOT)/grammars/posa.tmLanguage.json
SRC     := $(CURDIR)/vscode-posa

# Every editor extensions directory that exists on this machine.
CANDIDATES := $(HOME)/.vscode-oss/extensions \
              $(HOME)/.vscode/extensions \
              $(HOME)/.cursor/extensions \
              $(HOME)/.vscode-server/extensions
EDITORS ?= $(wildcard $(CANDIDATES))

.PHONY: install uninstall list package clean

install:
	@test -f "$(GRAMMAR)" || { echo "missing $(GRAMMAR)"; exit 1; }
	@test -n "$(strip $(EDITORS))" && true || { \
	  echo "No editor extensions directory found. Looked for:"; \
	  for d in $(CANDIDATES); do echo "  $$d"; done; \
	  echo "Pass one explicitly:  make install EDITORS=~/.vscode-oss/extensions"; \
	  exit 1; }
	@for d in $(EDITORS); do \
	  rm -rf "$$d/$(EXT)"; \
	  mkdir -p "$$d/$(EXT)/syntaxes"; \
	  cp "$(SRC)/package.json" "$(SRC)/language-configuration.json" "$(SRC)/README.md" "$$d/$(EXT)/"; \
	  cp "$(GRAMMAR)" "$$d/$(EXT)/syntaxes/posa.tmLanguage.json"; \
	  echo "installed $(EXT) -> $$d"; \
	done
	@echo "Restart the editor (or run 'Developer: Reload Window') to pick it up."

uninstall:
	@for d in $(EDITORS); do \
	  if [ -d "$$d/$(EXT)" ]; then rm -rf "$$d/$(EXT)"; echo "removed  $(EXT) <- $$d"; fi; \
	done

list:
	@for d in $(EDITORS); do \
	  if [ -d "$$d/$(EXT)" ]; then echo "installed     $$d/$(EXT)"; \
	  else echo "not installed $$d"; fi; \
	done

# A .vsix, for installing on a machine that has no checkout ("Install from VSIX…").
package: clean
	@mkdir -p build/$(EXT)/syntaxes
	@cp $(SRC)/package.json $(SRC)/language-configuration.json $(SRC)/README.md build/$(EXT)/
	@cp $(GRAMMAR) build/$(EXT)/syntaxes/posa.tmLanguage.json
	@cd build/$(EXT) && npx --yes @vscode/vsce package --out ../$(EXT).vsix
	@echo "built editors/build/$(EXT).vsix"

clean:
	@rm -rf build
