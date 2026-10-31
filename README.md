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
HayyanPatcher.bat key              re-plant the key state
HayyanPatcher.bat key --real-key   put the real saved key state back
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

## Patch shape

Both the hub and the modules get the same two surgical edits, because both
routines do real work that must keep running — dispatch and key handoff in the
hub, engine load and macro start in a module:

**Verdict branch forced.** The conditional jump that skips the `gate-ok` path
becomes NOPs. The routine still runs in full; only the denial path is
unreachable.

**Signature verifier stubbed.** The routine that returns `bad_signature` gets a
five-byte prologue that returns success, so the signature on the key state is no
longer checked.

If the branch pattern cannot be found (a reshaped build), the hub falls back to
replacing the prologue of `gate()` outright:

```
xor  rax, rax
mov  [rcx+8], rax        ; Result<(), String> sret
mov  [rcx+16], rax
mov  rax, 0x8000000000000000
mov  [rcx], rax          ; Ok(())
mov  rax, rcx
ret
```

## Key state

After the verifier stub lands, the patcher plants
`%APPDATA%\ExoPanda\shared\keystate.json`:

- the machine's own `MachineGuid` as `hwid`
- `expires_at` and `grace_until` set to 2100
- any 64-byte signature (the verifier no longer reads it)

The file is then marked read-only, because both the hub and the module
revalidate against the server and will happily overwrite it with
`last_reason: "invalid"`. Read-only blocks the replace; the patched binaries
never look at the signature anyway.

The original file is kept once as `keystate.json.real`. Re-running
`HayyanPatcher.exe key` re-plants the forged state; `--keep-key` disables
planting entirely.

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
- The planted key state is a valid cache for the patched binaries only. Run
  `restore` and the stock binaries will reject it — the original is still at
  `keystate.json.real` if a real key was ever entered.
