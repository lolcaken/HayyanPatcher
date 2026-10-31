from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.wintypes as wt
import json
import os
import shutil
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    import winreg
except ImportError:  # non-Windows import for tooling
    winreg = None

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
VERIFY_ERR = b"bad_signature"
VERIFY_STUB = bytes((0x31, 0xC0, 0x31, 0xD2, 0xC3))  # xor eax,eax; xor edx,edx; ret
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


@dataclass
class PatchSite:
    kind: str
    rva: int
    offset: int | None
    payload: bytes


def site_state(img: Image, site: PatchSite) -> tuple[str, int | None]:
    off = img.rva_to_offset(site.rva)
    if off is None:
        return "unmapped", None
    hit = img.data[off : off + len(site.payload)] == site.payload
    return ("patched" if hit else "clean"), off


JCC_NEAR = range(0x80, 0x90)
JCC_SHORT = range(0x70, 0x80)
MODRM_REG_MASK = 0x38


def _zero_compare_ending_at(data: bytes, p: int) -> bool:
    """True when the bytes that end at p are a cmp/test against zero."""
    if p >= 2 and data[p - 1] == 0xC0 and data[p - 2] in (0x84, 0x85):
        return True
    if p < 3 or data[p - 1] != 0x00:
        return False
    for span, mods in ((3, (0, 3)), (4, (1,)), (7, (2,))):
        op = p - span
        if op < 0 or data[op] != 0x80:
            continue
        modrm = data[op + 1]
        if modrm & MODRM_REG_MASK != MODRM_REG_MASK:
            continue
        mod = modrm >> 6
        if mod not in mods:
            continue
        if mod == 0 and modrm & 7 == 4:
            continue
        return True
    return False


def find_ok_branch(img: Image, gate: GateSite) -> tuple[int, int] | None:
    """Locate the conditional jump that skips the gate-ok path.

    Modules validate the key and then start the macro inside the same routine
    as the marker. Stubbing its prologue skips the macro start, so modules get
    the verdict branch neutralised instead: the routine still runs in full and
    only the denial path becomes unreachable.
    """
    text = img.section(SECTION_TEXT)
    if text is None:
        return None
    ok_rvas = set(img.find_string(GATE_OK))
    if not ok_rvas:
        return None
    refs = sorted({insn for sites in rip_refs_to(img, ok_rvas).values() for insn in sites})
    low = text.raw_ptr
    for ref in refs:
        if not (gate.begin_rva <= ref < gate.end_rva):
            continue
        base = low + (ref - text.va)
        for p in range(base - 2, max(base - 64, low) - 1, -1):
            op = img.data[p]
            if op == 0x0F and img.data[p + 1] in JCC_NEAR:
                rel = struct.unpack_from("<i", img.data, p + 2)[0]
                target = text.va + (p - low) + 6 + rel
                length = 6
            elif op in JCC_SHORT:
                rel = struct.unpack_from("<b", img.data, p + 1)[0]
                target = text.va + (p - low) + 2 + rel
                length = 2
            else:
                continue
            if target <= ref:
                continue
            if not _zero_compare_ending_at(img.data, p):
                continue
            return text.va + (p - low), length
    return None


def find_verify_function(img: Image, gate: GateSite, out: Console) -> int | None:
    """Locate the entitlement verifier: the routine that reports bad_signature."""
    rvas = set(img.find_string(VERIFY_ERR))
    if not rvas:
        return None
    functions = img.functions()
    if not functions:
        return None
    for insn in sorted({i for s in rip_refs_to(img, rvas).values() for i in s}):
        func = function_at(functions, insn)
        if func is None:
            continue
        if func[0] == gate.begin_rva:
            if out.verbose:
                out.emit("debug", "signature check is inlined in the gate, no verify stub")
            continue
        return func[0]
    return None


def plan_sites(img: Image, gate: GateSite, hub: bool, out: Console) -> list[PatchSite]:
    if hub:
        return [PatchSite("stub", gate.begin_rva, img.rva_to_offset(gate.begin_rva), STUB)]
    sites: list[PatchSite] = []
    branch = find_ok_branch(img, gate)
    if branch is not None:
        rva, length = branch
        if out.verbose:
            out.emit("debug", f"verdict branch RVA 0x{rva:X} ({length} bytes)")
        sites.append(PatchSite("branch", rva, img.rva_to_offset(rva), b"\x90" * length))
    verify = find_verify_function(img, gate, out)
    if verify is not None:
        if out.verbose:
            out.emit("debug", f"signature verifier RVA 0x{verify:X}")
        sites.append(PatchSite("verify", verify, img.rva_to_offset(verify), VERIFY_STUB))
    return sites


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


def exopanda_processes(exclude_pid: int = 0) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    kernel32 = ctypes.windll.kernel32
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot in (0, -1):
        return found
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            while True:
                exe = entry.szExeFile.lower()
                if entry.th32ProcessID != exclude_pid and exe.startswith("exopanda") \
                        and "patch" not in exe:
                    found.append((entry.th32ProcessID, entry.szExeFile))
                if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
    finally:
        kernel32.CloseHandle(snapshot)
    return found


def running_exopanda(exclude_pid: int = 0) -> set[str]:
    return {name for _pid, name in exopanda_processes(exclude_pid)}


def terminate_exopanda(out: Console, exclude_pid: int | None = None) -> int:
    """Close the hub and every module process so their images unlock."""
    kernel32 = ctypes.windll.kernel32
    exclude = os.getpid() if exclude_pid is None else exclude_pid
    killed = 0
    for _ in range(4):
        targets = exopanda_processes(exclude)
        if not targets:
            break
        for pid, name in targets:
            handle = kernel32.OpenProcess(0x0001, False, pid)
            if not handle:
                continue
            try:
                if kernel32.TerminateProcess(handle, 0):
                    killed += 1
                    out.emit("watch", f"closed {name}", f"pid {pid}")
            finally:
                kernel32.CloseHandle(handle)
        time.sleep(0.6)
    return killed


# ---------------------------------------------------------------- patching ----


@dataclass
class PatchResult:
    patched: int = 0
    skipped: int = 0
    locked: int = 0
    failed: int = 0
    verify: int = 0


def machine_hwid() -> str | None:
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
    except OSError:
        return None
    return str(value).strip().lower() or None


def keystate_path() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    return Path(base) / "ExoPanda" / "shared" / "keystate.json"


def keystate_ok() -> bool:
    try:
        state = json.loads(keystate_path().read_text(encoding="utf-8"))
        ent = state.get("entitlement") or {}
        return (
            state.get("last_reason") == "ok"
            and ent.get("hwid")
            and int(ent.get("expires_at") or 0) > int(time.time() * 1000)
        )
    except (OSError, ValueError, TypeError):
        return False


def write_keystate(out: Console, dry_run: bool = False) -> bool:
    """Plant a machine-bound entitlement that never expires.

    The verifier stub is what makes this stick: the signature is checked by the
    routine that reports bad_signature, and that routine is patched out before
    this file lands.
    """
    hwid = machine_hwid()
    if not hwid:
        out.emit("warn", "MachineGuid unreadable - key state left alone")
        return False

    path = keystate_path()
    now = int(time.time() * 1000)
    far = 4102444800000  # 2100-01-01
    token = "EXO-0000-0000-0000-0000"
    state = {
        "schema_version": 2,
        "key": token,
        "server_expires_at": far,
        "server_time": now,
        "checked_local_ms": now,
        "last_reason": "ok",
        "entitlement": {
            "v": 1,
            "key": token,
            "hwid": hwid,
            "expires_at": far,
            "issued_at": now,
            "grace_until": far,
            "sig": base64.b64encode(bytes(64)).decode(),
        },
    }
    if dry_run:
        out.emit("dry", f"would write {path}", f"hwid {hwid}")
        return True
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        keep = path.with_name(path.name + ".real")
        if path.exists() and not keep.exists():
            shutil.copy2(path, keep)
        if path.exists():
            os.chmod(path, 0o666)
        path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        os.chmod(path, 0o444)
    except OSError as exc:
        out.emit("err", f"key state not written: {exc}")
        return False
    out.emit("ok", "key state planted", f"hwid {hwid}")
    return True


def planning_image(path: Path) -> Image:
    """Structure comes from the pristine backup when one is present.

    The verdict branch disappears once it is patched, so the live file can no
    longer describe where the patch belongs. The backup still can, and it is
    only trusted while the sizes agree - a module update changes both the
    layout and the size, which invalidates it.
    """
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    if backup.exists():
        try:
            if backup.stat().st_size == path.stat().st_size:
                return Image.load(backup)
        except OSError:
            pass
    return Image.load(path)


def patch_file(path: Path, root: Path, out: Console, dry_run: bool = False) -> PatchResult:
    result = PatchResult()
    img = planning_image(path)
    live = Image.load(path)
    label = display(path, root)
    gates = find_gates(img, out)
    if not gates:
        out.emit("err", f"{label}: gate() not located - skipped")
        result.failed += 1
        return result

    hub = path.parent == root
    sites: list[PatchSite] = []
    for gate in gates:
        planned = plan_sites(img, gate, hub, out)
        if not planned:
            out.emit("warn", f"{label}: gate branch not located - left stock")
            result.failed += 1
            continue
        sites.extend(planned)

    todo = [s for s in sites if site_state(live, s)[0] == "clean"]
    if not todo:
        out.emit("skip", f"{label}: already patched", f"{len(sites)} site(s)")
        result.skipped += 1
        return result
    if is_locked(path):
        out.emit("warn", f"{label}: locked by a running process")
        result.locked += 1
        return result
    if dry_run:
        for site in todo:
            out.emit("dry", f"{label}: would patch {site.kind} RVA 0x{site.rva:X}")
            result.patched += 1
        return result

    backup = path.with_name(path.name + BACKUP_SUFFIX)
    try:
        if not backup.exists():
            shutil.copy2(path, backup)
            out.emit("ok", f"{label}: backup written", backup.name)
        data = bytearray(live.data)
        for site in todo:
            if site.offset is None:
                out.emit("err", f"{label}: RVA 0x{site.rva:X} not file-backed")
                result.failed += 1
                continue
            data[site.offset : site.offset + len(site.payload)] = site.payload
            out.emit("debug", f"{label}: {site.kind} -> file 0x{site.offset:X}")
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
    for site in todo:
        state, off = site_state(written, site)
        if state != "patched":
            out.emit("err", f"{label}: verification failed at RVA 0x{site.rva:X}")
            result.failed += 1
        else:
            what = {
                "stub": "gate() stubbed",
                "branch": "verdict branch forced",
                "verify": "signature check stubbed",
            }.get(site.kind, site.kind)
            out.emit("ok", f"{label}: {what}", f"RVA 0x{site.rva:X}  file 0x{off:X}")
            result.patched += 1
            if site.kind == "verify":
                result.verify += 1
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
        img = planning_image(path)
        live = Image.load(path)
        gates = find_gates(img, out)
        label = display(path, root)
        hub = path.parent == root
        out.rule(label)
        if not gates:
            out.emit("warn", f"{label}: gate() not located")
            continue
        for gate in gates:
            planned = plan_sites(img, gate, hub, out)
            if not planned:
                out.emit("warn", "verdict branch not located", f"RVA 0x{gate.begin_rva:X}")
                continue
            for site in planned:
                state, off = site_state(live, site)
                where = "" if off is None else f"file 0x{off:X}"
                detail = (
                    f"RVA 0x{site.rva:X}  0x{gate.end_rva - gate.begin_rva:X} bytes"
                    f"  {gate.markers} markers  {where}"
                )
                what = {
                    "stub": "gate() stubbed",
                    "branch": "verdict branch forced",
                    "verify": "signature check stubbed",
                }.get(site.kind, site.kind)
                if state == "patched":
                    out.emit("ok", what, detail)
                    patched += 1
                elif state == "clean":
                    out.emit("info", f"untouched ({site.kind})", detail)
                    clean += 1
                else:
                    out.emit("warn", "gate() unmapped", detail)
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        out.emit("debug", f"backup {'present' if backup.exists() else 'absent'}")
        if is_locked(path):
            out.emit("warn", f"{label}: in use by a running process")

    out.rule()
    out.emit("info", f"{len(paths)} gated binary(ies)", f"{patched} patched, {clean} clean")
    return 0


def cmd_key(out: Console, dry_run: bool = False) -> int:
    out.header(f"key {keystate_path()}")
    ok = write_keystate(out, dry_run)
    out.rule()
    out.emit("ok" if ok else "warn", "key state ready" if ok else "key state unchanged")
    return 0 if ok else 1


def cmd_patch(root: Path, out: Console, dry_run: bool, wait: float = 0.0,
              scope: str = "all", kill: bool = True, keyless: bool = True) -> int:
    out.header(f"patch {root}")
    if kill and not dry_run:
        closed = terminate_exopanda(out)
        if closed:
            out.emit("info", "app closed", f"{closed} process(es)")
    paths = gated_files(root, out)
    if scope == "hub":
        paths = [p for p in paths if p.parent == root]
    elif scope == "modules":
        paths = [p for p in paths if p.parent != root]
    if not paths:
        out.emit("err", f"no gated binaries in scope '{scope}' under {root}")
        return 1

    deadline = time.monotonic() + max(wait, 0.0)
    total = PatchResult()
    verifies = 0
    while True:
        total = PatchResult()
        for path in paths:
            out.rule(display(path, root))
            res = patch_file(path, root, out, dry_run)
            total.patched += res.patched
            total.skipped += res.skipped
            total.locked += res.locked
            total.failed += res.failed
            total.verify += res.verify

        verifies += total.verify
        if not total.locked or dry_run or time.monotonic() >= deadline:
            break
        left = int(deadline - time.monotonic())
        out.emit("info", "waiting for the app to exit", f"{total.locked} locked, {left}s left")
        time.sleep(2)

    if verifies and not dry_run and keyless:
        write_keystate(out)

    out.rule()
    if dry_run:
        out.emit("dry", "dry run - nothing written")
    elif total.failed:
        out.emit("warn", f"completed with {total.failed} failure(s)")
    else:
        out.emit("ok", "exopanda vibecoded slop patched ez", f"{total.patched} site(s)")
    if total.locked:
        out.emit("warn", f"{total.locked} file(s) still locked - close ExoPanda, then run patch again")
        out.emit("info", "or run", "HayyanPatcher.exe patch --wait 300")
    return 1 if total.failed else 0


def cmd_restore(root: Path, out: Console, kill: bool = True) -> int:
    out.header(f"restore {root}")
    if kill:
        closed = terminate_exopanda(out)
        if closed:
            out.emit("info", "app closed", f"{closed} process(es)")
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


def cmd_diag(root: Path, out: Console) -> int:
    out.header(f"diag {root}")
    procs = running_exopanda(os.getpid())
    out.emit("info", "processes", ", ".join(sorted(procs)) if procs else "none")

    gated_seen = 0
    for path in sorted(root.rglob("*.exe")):
        label = display(path, root)
        try:
            data = path.read_bytes()
        except OSError as exc:
            out.rule(label)
            out.emit("err", "unreadable", str(exc))
            continue

        out.rule(label)
        out.emit("info", "size", f"{len(data)} bytes")
        if GATE_OK not in data:
            out.emit("skip", "no gate marker")
            continue
        gated_seen += 1

        img = planning_image(path)
        live = Image.load(path)
        gates = find_gates(img, out if out.verbose else None)
        hub = path.parent == root
        if not gates:
            out.emit("warn", "gate() not located - markers present but no matching function")
        for gate in gates:
            planned = plan_sites(img, gate, hub, out)
            if not planned:
                out.emit("warn", "verdict branch not located", f"RVA 0x{gate.begin_rva:X}")
                continue
            for site in planned:
                state, off = site_state(live, site)
                where = "unmapped" if off is None else f"file 0x{off:X}"
                out.emit("info", f"{site.kind} {state}",
                         f"RVA 0x{site.rva:X}  0x{gate.end_rva - gate.begin_rva:X} bytes"
                         f"  {gate.markers} markers  {where}")
        out.emit("info", "locked", "yes" if is_locked(path) else "no")
        out.emit("info", "backup",
                 "present" if path.with_name(path.name + BACKUP_SUFFIX).exists() else "absent")

    out.rule()
    if not (root / "ExoPanda.exe").exists():
        out.emit("warn", "hub not found at this root - pass --root <install dir> if it lives elsewhere")
    out.emit("info", f"{gated_seen} gated binary(ies) found")
    return 0


def cmd_auto(root: Path, out: Console, interval: float, kill: bool = False,
             keyless: bool = True) -> int:
    if kill:
        closed = terminate_exopanda(out)
        if closed:
            out.emit("info", "app closed", f"{closed} process(es)")
    if keyless and not keystate_ok():
        write_keystate(out)
    out.emit("info", "watching", f"{root}")

    known: dict[Path, tuple[int, int]] = {}
    gated: set[Path] = set()
    sites: dict[Path, list[tuple[int, bytes]]] = {}
    pending: set[Path] = set()
    last_procs: set[str] = set()
    rescan_at = 0.0
    self_pid = os.getpid()
    batch_patched = 0

    def stat_key(path: Path) -> tuple[int, int] | None:
        try:
            st = path.stat()
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def probe(path: Path) -> str:
        """cheap state read using cached patch offsets; 'unknown' forces a rescan"""
        key = stat_key(path)
        if key is None:
            return "missing"
        if known.get(path) != key or path not in sites:
            return "unknown"
        try:
            with open(path, "rb") as handle:
                for off, payload in sites[path]:
                    handle.seek(off)
                    if handle.read(len(payload)) != payload:
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
                    img = planning_image(path)
                    live = Image.load(path)
                    gates = find_gates(img, out)
                    hub = path.parent == root
                    offsets = [
                        (off, payload)
                        for gate in gates
                        for site in plan_sites(img, gate, hub, out)
                        if (off := img.rva_to_offset(site.rva)) is not None
                        for payload in (site.payload,)
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
                        live.data[off : off + len(payload)] == payload for off, payload in offsets
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
                if res.verify and keyless:
                    write_keystate(out)
                if res.locked:
                    pending.add(path)
                    continue
                batch_patched += res.patched
                key = stat_key(path)
                if key:
                    known[path] = key

            if batch_patched and not pending:
                out.emit("ok", "exopanda vibecoded slop patched ez")
                batch_patched = 0

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
        choices=("auto", "status", "patch", "diag", "key", "restore"),
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
    parser.add_argument("--wait", type=float, default=0.0,
                        help="patch: keep retrying locked files for N seconds")
    parser.add_argument("--hub-only", action="store_true",
                        help="patch: only the launcher, leave module binaries stock")
    parser.add_argument("--modules-only", action="store_true",
                        help="patch: only module binaries, leave the launcher stock")
    parser.add_argument("--no-kill", action="store_true",
                        help="do not close ExoPanda or its modules before writing")
    parser.add_argument("--keep-key", action="store_true",
                        help="leave the existing key state alone instead of planting one")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = parser.parse_args(argv[1:])

    out = Console(color=not args.no_color, verbose=args.verbose)
    root: Path = args.root
    if not root.is_dir():
        out.emit("err", f"install directory not found: {root}")
        return 1

    scope = "all"
    if args.hub_only:
        scope = "hub"
    elif args.modules_only:
        scope = "modules"
    kill = not args.no_kill
    keyless = not args.keep_key

    if args.action == "status":
        return cmd_status(root, out)
    if args.action == "key":
        return cmd_key(out, args.dry_run)
    if args.action == "patch":
        return cmd_patch(root, out, args.dry_run, args.wait, scope, kill, keyless)
    if args.action == "diag":
        return cmd_diag(root, out)
    if args.action == "restore":
        return cmd_restore(root, out, kill)
    return cmd_auto(root, out, max(0.5, args.interval), kill, keyless)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
