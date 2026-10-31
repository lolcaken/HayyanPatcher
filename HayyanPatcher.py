from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import shutil
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

STUB = bytes(
    [
        0x48, 0x31, 0xC0,
        0x48, 0x89, 0x41, 0x08,
        0x48, 0x89, 0x41, 0x10,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x48, 0x89, 0x01,
        0x48, 0x89, 0xC8,
        0xC3,
    ]
)

GATE_OK = b"[0x6B01] gate-ok"
GATE_SIBLINGS = (
    b"[0x6B02] gate-deny",
    b"[0x6B10] gate-none",
    b"[0x6B11] gate-no-hwid",
    b"[0x6B0E] gate-grace",
    b"[0x6B05] gate-net",
)
SECTION_TEXT = b".text"
SECTION_PDATA = b".pdata"
BACKUP_SUFFIX = ".orig"

# ---------------------------------------------------------------- console ----


class Console:
    RESET = "\x1b[0m"
    STYLES = {
        "debug": "\x1b[38;5;244m",
        "info": "\x1b[38;5;45m",
        "ok": "\x1b[38;5;82m",
        "warn": "\x1b[38;5;220m",
        "err": "\x1b[38;5;203m",
        "head": "\x1b[38;5;177m",
        "accent": "\x1b[38;5;123m",
        "muted": "\x1b[38;5;240m",
    }
    TAGS = {
        "debug": ("DBG", "debug"),
        "info": ("  *", "info"),
        "ok": ("  +", "ok"),
        "skip": ("  =", "muted"),
        "warn": ("  !", "warn"),
        "err": ("  -", "err"),
        "dry": ("  ~", "accent"),
        "watch": ("  >", "accent"),
        "head": (" ::", "head"),
    }

    def __init__(self, color: bool, verbose: bool) -> None:
        self.color = color and self._enable_vt()
        self.verbose = verbose

    @staticmethod
    def _enable_vt() -> bool:
        if os.name != "nt":
            return True
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
        except Exception:
            return False

    def paint(self, text: str, style: str) -> str:
        if not self.color:
            return text
        return f"{self.STYLES.get(style, '')}{text}{self.RESET}"

    def emit(self, level: str, message: str, detail: str | None = None) -> None:
        if level == "debug" and not self.verbose:
            return
        tag, style = self.TAGS[level]
        line = f"{self.paint(tag, style)} {message}"
        if detail:
            line += self.paint(f"  ({detail})", "muted")
        print(line, flush=True)

    def rule(self, label: str = "") -> None:
        bar = label.center(46, "-") if label else "-" * 46
        print(self.paint(bar, "muted"), flush=True)

    def header(self, text: str) -> None:
        print(self.paint(text, "head"), flush=True)


# ------------------------------------------------------------------- PE ------


@dataclass
class Section:
    name: bytes
    va: int
    vsize: int
    raw_ptr: int
    raw_size: int

    def contains_rva(self, rva: int) -> bool:
        return self.va <= rva < self.va + max(self.vsize, self.raw_size)

    def to_offset(self, rva: int) -> int | None:
        delta = rva - self.va
        if 0 <= delta < self.raw_size:
            return self.raw_ptr + delta
        return None


@dataclass
class Image:
    path: Path
    data: bytes = field(repr=False)
    base: int = 0
    sections: list[Section] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "Image":
        data = path.read_bytes()
        img = cls(path=path, data=data)
        if data[:2] != b"MZ":
            raise ValueError("not a PE image")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe : pe + 4] != b"PE\0\0":
            raise ValueError("bad PE signature")
        nsections = struct.unpack_from("<H", data, pe + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        magic = struct.unpack_from("<H", data, pe + 24)[0]
        img.base = struct.unpack_from(
            "<Q" if magic == 0x20B else "<I", data, pe + 24 + 24
        )[0]
        table = pe + 24 + opt_size
        for i in range(nsections):
            entry = table + i * 40
            name = data[entry : entry + 8].rstrip(b"\0")
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, entry + 8)
            img.sections.append(Section(name, va, vsize, raw_ptr, raw_size))
        return img

    def section(self, name: bytes) -> Section | None:
        for sec in self.sections:
            if sec.name == name:
                return sec
        return None

    def rva_to_offset(self, rva: int) -> int | None:
        for sec in self.sections:
            if sec.contains_rva(rva):
                return sec.to_offset(rva)
        return None

    def find_string(self, needle: bytes) -> list[int]:
        out: list[int] = []
        start = 0
        while True:
            idx = self.data.find(needle, start)
            if idx < 0:
                return out
            for sec in self.sections:
                if sec.raw_ptr <= idx < sec.raw_ptr + sec.raw_size:
                    out.append(sec.va + (idx - sec.raw_ptr))
                    break
            start = idx + 1

    def functions(self) -> list[tuple[int, int]]:
        sec = self.section(SECTION_PDATA)
        if sec is None:
            return []
        raw = self.data[sec.raw_ptr : sec.raw_ptr + sec.raw_size]
        entries = []
        for off in range(0, len(raw) - 11, 12):
            begin, end, _unwind = struct.unpack_from("<III", raw, off)
            if begin and end > begin:
                entries.append((begin, end))
        entries.sort()
        return entries


def function_at(functions: list[tuple[int, int]], rva: int) -> tuple[int, int] | None:
    lo, hi = 0, len(functions) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        begin, end = functions[mid]
        if rva < begin:
            hi = mid - 1
        elif rva >= end:
            lo = mid + 1
        else:
            return functions[mid]
        if begin <= rva:
            best = functions[mid]
    return best if best and best[0] <= rva < best[1] else None


RIP_MODRM = frozenset((0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D))


def rip_refs_to(img: Image, target_rvas: set[int]) -> dict[int, set[int]]:
    text = img.section(SECTION_TEXT)
    if text is None:
        return {}
    raw = text.raw_ptr
    end = min(len(img.data) - 7, raw + text.raw_size)
    hits: dict[int, set[int]] = {t: set() for t in target_rvas}
    for p in range(raw, end):
        if img.data[p] not in (0x48, 0x49, 0x4C, 0x4D):
            continue
        if img.data[p + 1] not in (0x8D, 0x8B):
            continue
        if img.data[p + 2] not in RIP_MODRM:
            continue
        disp = struct.unpack_from("<i", img.data, p + 3)[0]
        target = text.va + (p - raw) + 7 + disp
        if target in target_rvas:
            hits[target].add(text.va + (p - raw))
    return hits


# ---------------------------------------------------------------- analysis ---


@dataclass
class GateSite:
    begin_rva: int
    end_rva: int
    markers: int


def find_gates(img: Image, out: Console | None = None) -> list[GateSite]:
    rva_of: dict[int, bytes] = {}
    for needle in (GATE_OK, *GATE_SIBLINGS):
        rvas = img.find_string(needle)
        if out and rvas:
            out.emit(
                "debug",
                f"marker {needle.decode()} at " + ", ".join(f"RVA 0x{r:X}" for r in rvas),
            )
        for rva in rvas:
            rva_of[rva] = needle
    if not rva_of:
        return []

    functions = img.functions()
    if out:
        out.emit("debug", f"unwind table: {len(functions)} RUNTIME_FUNCTION entries")
    if not functions:
        return []

    hits = rip_refs_to(img, set(rva_of))
    per_func: dict[tuple[int, int], set[bytes]] = {}
    for rva, sites in hits.items():
        for insn in sites:
            func = function_at(functions, insn)
            if func is None:
                if out:
                    out.emit(
                        "debug",
                        f"RVA 0x{insn:X} references a marker but is outside any unwind entry",
                    )
                continue
            per_func.setdefault(func, set()).add(rva_of[rva])
            if out:
                out.emit(
                    "debug",
                    f"xref RVA 0x{insn:X} -> {rva_of[rva].decode()} -> function 0x{func[0]:X}",
                )

    gates = []
    for (begin, end), markers in sorted(per_func.items()):
        accepted = GATE_OK in markers and len(markers) >= 2
        if out:
            out.emit(
                "debug",
                f"candidate function 0x{begin:X}-0x{end:X}: "
                f"{len(markers)} markers, {'accepted' if accepted else 'rejected'}",
            )
        if accepted:
            gates.append(GateSite(begin, end, len(markers)))
    return gates


def site_state(img: Image, gate: GateSite) -> tuple[str, int | None]:
    off = img.rva_to_offset(gate.begin_rva)
    if off is None:
        return "unmapped", None
    return ("patched" if img.data[off : off + len(STUB)] == STUB else "clean"), off


# ------------------------------------------------------------------ targets ---


def default_root() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", "")) / "ExoPanda"


def display(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def gated_files(root: Path, out: Console) -> list[Path]:
    found = []
    for path in sorted(root.rglob("*.exe")):
        try:
            data = path.read_bytes()
        except OSError as exc:
            out.emit("warn", f"{path.name}: unreadable", str(exc))
            continue
        if GATE_OK in data:
            found.append(path)
            out.emit("debug", f"gated: {display(path, root)} ({len(data)} bytes)")
        else:
            out.emit("debug", f"no gate marker: {display(path, root)}")
    return found


def is_locked(path: Path) -> bool:
    try:
        with open(path, "r+b"):
            return False
    except PermissionError:
        return True
    except OSError:
        return True


# ------------------------------------------------------------- process list ---


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


def running_exopanda(exclude_pid: int = 0) -> set[str]:
    names: set[str] = set()
    kernel32 = ctypes.windll.kernel32
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot in (0, -1):
        return names
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            while True:
                exe = entry.szExeFile.lower()
                if entry.th32ProcessID != exclude_pid and exe.startswith("exopanda") \
                        and "patch" not in exe:
                    names.add(entry.szExeFile)
                if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
    finally:
        kernel32.CloseHandle(snapshot)
    return names


# ---------------------------------------------------------------- patching ----


@dataclass
class PatchResult:
    patched: int = 0
    skipped: int = 0
    locked: int = 0
    failed: int = 0


def patch_file(path: Path, root: Path, out: Console, dry_run: bool = False) -> PatchResult:
    result = PatchResult()
    img = Image.load(path)
    gates = find_gates(img, out)
    label = display(path, root)
    if not gates:
        out.emit("err", f"{label}: gate() not located - skipped")
        result.failed += 1
        return result

    todo = [g for g in gates if site_state(img, g)[0] == "clean"]
    if not todo:
        out.emit("skip", f"{label}: already patched", f"{len(gates)} site(s)")
        result.skipped += 1
        return result
    if is_locked(path):
        out.emit("warn", f"{label}: locked while the process runs")
        result.locked += 1
        return result
    if dry_run:
        for gate in todo:
            out.emit("dry", f"{label}: would stub RVA 0x{gate.begin_rva:X}")
        result.patched += len(todo)
        return result

    backup = path.with_name(path.name + BACKUP_SUFFIX)
    try:
        if not backup.exists():
            shutil.copy2(path, backup)
            out.emit("ok", f"{label}: backup written", backup.name)
        data = bytearray(img.data)
        for gate in todo:
            off = img.rva_to_offset(gate.begin_rva)
            if off is None:
                out.emit("err", f"{label}: RVA 0x{gate.begin_rva:X} not file-backed")
                result.failed += 1
                continue
            data[off : off + len(STUB)] = STUB
            out.emit("debug", f"{label}: 28-byte stub -> file 0x{off:X}")
        path.write_bytes(bytes(data))
    except PermissionError:
        out.emit("warn", f"{label}: locked - close ExoPanda and its modules, then retry")
        result.locked += 1
        return result

    written = Image.load(path)
    if len(written.data) != len(img.data):
        out.emit("err", f"{label}: size changed - run restore")
        result.failed += 1
        return result
    for gate in todo:
        state, off = site_state(written, gate)
        if state != "patched":
            out.emit("err", f"{label}: verification failed at RVA 0x{gate.begin_rva:X}")
            result.failed += 1
        else:
            out.emit(
                "ok",
                f"{label}: gate() stubbed",
                f"RVA 0x{gate.begin_rva:X}  file 0x{off:X}  size unchanged",
            )
            result.patched += 1
    return result


# ---------------------------------------------------------------- actions ----


def cmd_status(root: Path, out: Console) -> int:
    out.header(f"scan {root}")
    paths = gated_files(root, out)
    if not paths:
        out.emit("err", f"no gated binaries under {root}")
        return 1

    clean = patched = 0
    for path in paths:
        img = Image.load(path)
        gates = find_gates(img, out)
        label = display(path, root)
        out.rule(label)
        if not gates:
            out.emit("warn", f"{label}: gate() not located")
            continue
        for gate in gates:
            state, off = site_state(img, gate)
            where = "" if off is None else f"file 0x{off:X}"
            detail = (
                f"RVA 0x{gate.begin_rva:X}  0x{gate.end_rva - gate.begin_rva:X} bytes"
                f"  {gate.markers} markers  {where}"
            )
            if state == "patched":
                out.emit("ok", "gate() stubbed", detail)
                patched += 1
            elif state == "clean":
                out.emit("info", "gate() untouched", detail)
                clean += 1
            else:
                out.emit("warn", "gate() unmapped", detail)
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        out.emit("debug", f"backup {'present' if backup.exists() else 'absent'}")

    out.rule()
    out.emit("info", f"{len(paths)} gated binary(ies)", f"{patched} patched, {clean} clean")
    return 0


def cmd_patch(root: Path, out: Console, dry_run: bool) -> int:
    out.header(f"patch {root}")
    paths = gated_files(root, out)
    if not paths:
        out.emit("err", f"no gated binaries under {root}")
        return 1

    total = PatchResult()
    for path in paths:
        out.rule(display(path, root))
        res = patch_file(path, root, out, dry_run)
        total.patched += res.patched
        total.skipped += res.skipped
        total.locked += res.locked
        total.failed += res.failed

    out.rule()
    if dry_run:
        out.emit("dry", "dry run - nothing written")
    elif total.failed:
        out.emit("warn", f"completed with {total.failed} failure(s)")
    else:
        out.emit("ok", "all gated binaries patched", f"{total.patched} site(s)")
    return 1 if total.failed else 0


def cmd_restore(root: Path, out: Console) -> int:
    out.header(f"restore {root}")
    restored = locked = 0
    for backup in sorted(root.rglob(f"*{BACKUP_SUFFIX}")):
        target = backup.with_name(backup.name[: -len(BACKUP_SUFFIX)])
        if not target.exists():
            continue
        try:
            shutil.copy2(backup, target)
            backup.unlink()
        except PermissionError:
            out.emit("err", f"{display(target, root)}: locked - close ExoPanda first")
            locked += 1
            continue
        out.emit("ok", f"{display(target, root)}: restored from {backup.name}")
        restored += 1
    out.rule()
    if not restored and not locked:
        out.emit("warn", "no backups found")
        return 1
    out.emit("ok" if not locked else "warn", f"{restored} restored, {locked} locked")
    return 1 if locked else 0


def cmd_auto(root: Path, out: Console, interval: float) -> int:
    out.header("HayyanPatcher - auto mode")
    out.emit("info", "watching", f"{root}")

    known: dict[Path, tuple[int, int]] = {}
    gated: set[Path] = set()
    sites: dict[Path, list[tuple[int, int]]] = {}
    pending: set[Path] = set()
    last_procs: set[str] = set()
    rescan_at = 0.0
    self_pid = os.getpid()

    def stat_key(path: Path) -> tuple[int, int] | None:
        try:
            st = path.stat()
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def probe(path: Path) -> str:
        """cheap state read using cached gate offsets; 'unknown' forces a rescan"""
        key = stat_key(path)
        if key is None:
            return "missing"
        if known.get(path) != key or path not in sites:
            return "unknown"
        try:
            with open(path, "rb") as handle:
                for _begin, off in sites[path]:
                    handle.seek(off)
                    if handle.read(len(STUB)) != STUB:
                        return "clean"
        except OSError:
            return "unknown"
        return "patched"

    try:
        while True:
            now = time.monotonic()
            procs = running_exopanda(self_pid)
            if procs != last_procs:
                for started in sorted(procs - last_procs):
                    out.emit("watch", f"app started: {started}")
                for closed in sorted(last_procs - procs):
                    out.emit("watch", f"app closed: {closed}")
                last_procs = procs
                rescan_at = 0.0

            if now >= rescan_at:
                rescan_at = now + max(interval * 10, 15.0)
                for path in sorted(root.rglob("*.exe")):
                    if path in known:
                        continue
                    try:
                        if GATE_OK not in path.read_bytes():
                            known[path] = stat_key(path) or (0, 0)
                            out.emit("debug", f"no gate marker: {display(path, root)}")
                            continue
                    except OSError:
                        continue
                    gated.add(path)
                    known.pop(path, None)
                    out.emit("debug", f"gated: {display(path, root)}")

            for path in sorted(list(gated)):
                key = stat_key(path)
                if key is None:
                    gated.discard(path)
                    known.pop(path, None)
                    pending.discard(path)
                    continue

                state = probe(path)
                if state == "unknown":
                    img = Image.load(path)
                    gates = find_gates(img, out)
                    offsets = [
                        (gate.begin_rva, off)
                        for gate in gates
                        if (off := img.rva_to_offset(gate.begin_rva)) is not None
                    ]
                    if not offsets:
                        out.emit("warn", f"{display(path, root)}: gate() not located, untracked")
                        gated.discard(path)
                        known.pop(path, None)
                        pending.discard(path)
                        continue
                    sites[path] = offsets
                    known[path] = key
                    state = "patched" if all(
                        img.data[off : off + len(STUB)] == STUB for _b, off in offsets
                    ) else "clean"

                if state == "patched":
                    pending.discard(path)
                    continue

                if is_locked(path):
                    if path not in pending:
                        out.emit("watch", f"{display(path, root)}: unpatched and running, "
                                           f"queued until it closes")
                        pending.add(path)
                    continue

                pending.discard(path)
                res = patch_file(path, root, out)
                if res.locked:
                    pending.add(path)
                    continue
                key = stat_key(path)
                if key:
                    known[path] = key

            if out.verbose:
                out.emit("debug", f"tracking {len(gated)} gated file(s), "
                                  f"{len(pending)} queued")
            time.sleep(interval)
    except KeyboardInterrupt:
        out.rule()
        out.emit("info", "stopped")
        return 0


# ------------------------------------------------------------------- main ----


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="HayyanPatcher",
        description="Signature-based key-gate bypass for ExoPanda binaries. "
                    "Run with no arguments to patch now and keep patching.",
    )
    parser.add_argument(
        "action",
        nargs="?",
        default="auto",
        choices=("auto", "status", "patch", "restore"),
        help="auto (default): patch now, then watch for new or updated binaries",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=default_root(),
        help="ExoPanda install directory (default: %%LOCALAPPDATA%%\\ExoPanda)",
    )
    parser.add_argument("--dry-run", action="store_true", help="report without writing")
    parser.add_argument("--interval", type=float, default=2.0, help="watch poll seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = parser.parse_args(argv[1:])

    out = Console(color=not args.no_color, verbose=args.verbose)
    root: Path = args.root
    if not root.is_dir():
        out.emit("err", f"install directory not found: {root}")
        return 1

    if args.action == "status":
        return cmd_status(root, out)
    if args.action == "patch":
        return cmd_patch(root, out, args.dry_run)
    if args.action == "restore":
        return cmd_restore(root, out)
    return cmd_auto(root, out, max(0.5, args.interval))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
