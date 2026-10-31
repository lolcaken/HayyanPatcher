# HayyanPatcher

Signature-based key-gate bypass for ExoPanda binaries, with a self-updating
launcher.

ExoPanda ships an entitlement gate in every binary that can start a macro or a
module. The gate reads the local key file, fingerprints the machine, POSTs the
key to `/api/keys/validate`, Ed25519-verifies the server's verdict against a
baked-in public key, then returns `Result<(), String>`.

HayyanPatcher replaces the prologue of that routine with a stub that stores
`Ok(())` into the sret slot and returns. No key file, no server call, no
signature verification, no expiry check.

## Requirements

- Windows 10/11 x64
- ExoPanda installed (default `%LOCALAPPDATA%\ExoPanda`)
- Nothing else — the launcher is a batch file, the patcher is a standalone exe

## Usage

```
HayyanPatcher.bat                  fetch latest build, then patch + watch
HayyanPatcher.bat status           report only
HayyanPatcher.bat patch            one pass, exit
HayyanPatcher.bat restore          roll back from .orig backups
HayyanPatcher.bat -v               verbose discovery log
```

Double-clicking the `.bat` is the intended path: it downloads the current build
from this repository, checks it against `HayyanPatcher.sha256`, and runs it.

The exe can also be run directly:

```
HayyanPatcher.exe                  auto (patch + watch)
HayyanPatcher.exe status|patch|restore
HayyanPatcher.exe --root "D:\ExoPanda" --interval 1 --no-color
```

## What auto mode does

- patches every gated binary under the install directory
- queues any binary that is currently running, and patches it the moment the
  process exits
- keeps watching, so newly installed modules and update downloads get patched
  without restarting anything
- exits with `Ctrl+C`

## How discovery works

No offsets are hard-coded, so a new version or a new module resolves on its own:

1. find the ASCII string `[0x6B01] gate-ok` in `.rdata`
2. scan `.text` for RIP-relative `lea`/`mov` instructions whose target is that
   string
3. resolve each hit to its enclosing function via the PE `.pdata` unwind table
   (`RUNTIME_FUNCTION` begin/end), which is exact
4. require a second gate marker in the same function
5. overwrite the prologue with the Ok stub

If the markers are missing or reshaped, nothing is written — the tool reports
`gate() not located` instead of guessing.

## Build

```
pip install pyinstaller
pyinstaller --onefile --console --name HayyanPatcher HayyanPatcher.py
certutil -hashfile HayyanPatcher.exe SHA256    # update HayyanPatcher.sha256
```

## Backup and rollback

The first patch writes `<name>.exe.orig` next to each binary. `restore` copies
it back and removes the backup. File sizes never change.

## Notes

- Windows only. macOS builds of ExoPanda are Mach-O and are not handled.
- Module updates replace the patched exe; auto mode re-patches them.
- The binaries are code-signed; patching invalidates the signature. Windows does
  not enforce that for local execution.
