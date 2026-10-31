# HayyanPatcher

Signature-based key-gate bypass for ExoPanda binaries, with a self-updating
launcher.

ExoPanda ships an entitlement gate in the hub and in every macro module. The
gate reads the local key state, fingerprints the machine, POSTs the key to
`/api/keys/validate`, verifies the signed verdict against a baked-in public key,
then returns a Rust `Result`.

HayyanPatcher patches that routine in place. Nothing about the server, the key
file, or the signature is touched — the verdict is simply forced.

## Requirements

- Windows 10/11 x64
- ExoPanda installed (default `%LOCALAPPDATA%\ExoPanda`)
- Nothing else — the launcher is a batch file, the patcher is a standalone exe

## Usage

```
HayyanPatcher.bat                  fetch latest build, then patch + watch
HayyanPatcher.bat status           report only
HayyanPatcher.bat patch            one pass, exit
HayyanPatcher.bat diag             per-binary detail: marker, site, lock, backup
HayyanPatcher.bat restore          roll back from .orig backups
HayyanPatcher.bat -v               verbose discovery log
```

Double-clicking the `.bat` is the intended path: it downloads the current build
from this repository, checks it against `HayyanPatcher.sha256`, and runs it.

The exe can also be run directly:

```
HayyanPatcher.exe                  auto (patch + watch)
HayyanPatcher.exe status|patch|diag|restore
HayyanPatcher.exe --root "D:\ExoPanda" --interval 1 --no-color
HayyanPatcher.exe --hub-only       patch the launcher, leave modules stock
HayyanPatcher.exe --modules-only   patch modules, leave the launcher stock
HayyanPatcher.exe --no-kill        do not close ExoPanda before writing
```

## Killing the app

Patching while ExoPanda runs fails on locked images, so `patch`, `restore` and
the first pass of `auto` close every `ExoPanda*` process first — hub, Fischer,
and any other installed macro binary. Auto then keeps running and patches new or
updated binaries as they appear; it only force-closes at startup, never while it
watches.

`--no-kill` disables the close step.

## Two patch shapes

The hub and the modules do not use the same shape, so the patcher picks per
binary:

**Hub — prologue stub (28 bytes).** The hub only asks the gate for a verdict
before dispatching a module, so the whole routine can be replaced:

```
xor  rax, rax
mov  [rcx+8], rax        ; Result<(), String> sret
mov  [rcx+16], rax
mov  rax, 0x8000000000000000
mov  [rcx], rax          ; Ok(())
mov  rax, rcx
ret
```

**Modules — verdict branch forced.** A module's gate lives inside the same
routine that loads its engine DLL and starts the macro. Replacing its prologue
would skip the macro start entirely — the window opens, the macro does nothing.
Instead the patcher finds the conditional jump that skips the `gate-ok` path and
replaces it with NOPs, so the routine still runs in full and only the denial
path becomes unreachable.

## How discovery works

No offsets are hard-coded, so a new version or a new module resolves on its own:

1. find the ASCII string `[0x6B01] gate-ok` in `.rdata`
2. scan `.text` for RIP-relative `lea`/`mov` instructions whose target is that
   string
3. resolve each hit to its enclosing function via the PE `.pdata` unwind table
   (`RUNTIME_FUNCTION` begin/end), which is exact
4. require a second gate marker in the same function
5. hub: stub the prologue. module: walk back from the `gate-ok` reference to the
   nearest `cmp byte [mem], 0` / `test` followed by a conditional jump that lands
   past the reference, and NOP that jump

If the markers or the branch are missing or reshaped, nothing is written — the
tool reports `gate() not located` or `verdict branch not located` instead of
guessing.

## Build

```
pip install pyinstaller
pyinstaller --onefile --console --name HayyanPatcher HayyanPatcher.py
certutil -hashfile HayyanPatcher.exe SHA256    # update HayyanPatcher.sha256
```

## Backup and rollback

The first patch writes `<name>.exe.orig` next to each binary. `restore` copies
it back and removes the backup. File sizes never change, so module manifests
that record only byte counts still validate.

## Notes

- Windows only. macOS builds of ExoPanda are Mach-O and are not handled.
- Module updates replace the patched exe; auto mode re-patches them.
- The binaries are code-signed; patching invalidates the signature. Windows does
  not enforce that for local execution.
- Without any key state on the machine a module logs `[0x6B10] gate-none` and
  will not start its macro. The patcher removes the key check, not the key state
  the engine reads afterwards.
