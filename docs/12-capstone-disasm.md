# Capstone Disassembly Backend

Capstone is an opt-in backend for `disasm.range` and `disasm.function`.
LLDB remains the default build and runtime behavior unless the daemon is
configured with:

```sh
cmake -B build-capstone -DLDB_ENABLE_CAPSTONE=ON
```

When enabled, CMake first looks for Capstone through `pkg-config` and then
falls back to a normal header/library lookup. If Capstone cannot be found,
the Capstone-enabled configure fails. Default builds do not require Capstone.

## Scope

The first Capstone path is intentionally narrow:

- `disasm.range`
- `disasm.function`, through its existing range disassembly call

`xref.addr` and `string.xref` keep LLDB semantics. In particular,
`string.xref` still depends on LLDB's instruction comments for some ARM64
addressing patterns, so it is not switched to Capstone in this branch.

## Supported Architectures

The Capstone path is selected only for target triples beginning with:

- `x86_64`
- `amd64`
- `aarch64`
- `arm64`

Other architectures fall back to LLDB.

## Fallback

Capstone is best-effort. The backend returns LLDB output instead of raising a
new backend error when:

- the target arch/mode is unsupported
- Capstone cannot initialize
- bytes cannot be read for the requested file-address range
- Capstone cannot decode any instructions

The returned instruction shape is unchanged:

- `address`
- `byte_size`
- `bytes`
- `mnemonic`
- `operands`
- `comment`

For Capstone output, `comment` is empty and `bytes` are copied from the same
target bytes used for disassembly. Addresses remain file addresses.

## Capability Reporting

The `hello` response advertises the active disassembly backend:

```json
{
  "capabilities": {
    "disasm_backend": "lldb"
  }
}
```

Capstone-enabled builds report:

```json
{
  "capabilities": {
    "disasm_backend": "capstone",
    "disasm_fallback": true
  }
}
```

No protocol version bump is required because this is a backward-compatible
capability addition.
