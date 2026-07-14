# posa syntax highlighting (VS Code / VSCodium / Cursor)

Colorizes the `.posa` decoders carcal and libpcapng use — see
`libpcapng/doc/posa.md` for the language itself.

Install from a checkout:

    cd carcal/editors
    make install        # every editor found; make list to see which

The grammar itself is not stored in this folder: carcal loads
`carcal/grammars/posa.tmLanguage.json` at runtime for its own built-in editor
(**Analyze ▸ Decoders ▸ Enter**), so that file is the single source of truth and
`make install` copies it in here. Change it there and reinstall — the TUI editor
and your GUI editor then highlight identically.

Highlights keywords (`Object`, `when`/`else`, `scope`, `repeat`/`until`/`as`,
`label`, `bits`, `seek`, `layer`, `include`, `rule`, `color`, `mask`, `hex`), the
field types, quoted labels and delimiters, numbers and operators. `#` line
comments and auto-indent after a block opener come from the language
configuration.
