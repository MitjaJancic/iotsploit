"""
firmware_elf.py

Pure-Python ELF binary security hardening analyzer (checksec equivalent).
Inspects extracted IoT firmware binaries for compiler mitigations:
1. NX / DEP (No-Execute Stack, via PT_GNU_STACK)
2. Stack Canaries (__stack_chk_fail)
3. PIE / ASLR (Position Independent Executable, via e_type ET_DYN vs ET_EXEC)
4. RELRO (Relocation Read-Only, via PT_GNU_RELRO)
"""

from __future__ import annotations

import os
import struct
import uuid
from pathlib import Path
from typing import Any

from iotsploit.core.scoring import Finding


def _fid(check_name: str, device_id: str) -> str:
    return f"{device_id}_{check_name}_{uuid.uuid4().hex[:8]}"


# Program header constants
PT_GNU_STACK = 0x6474e551
PT_GNU_RELRO = 0x6474e552
PF_X = 0x1  # Executable flag


def inspect_elf(file_path: Path) -> dict[str, Any] | None:
    """
    Parses ELF binary header and program headers to determine security mitigations.
    Returns None if file is not an ELF binary.
    """
    try:
        data = file_path.read_bytes()
        if len(data) < 52 or not data.startswith(b"\x7fELF"):
            return None

        ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = data[5]   # 1 = Little Endian, 2 = Big Endian
        endian = "<" if ei_data == 1 else ">"

        if ei_class == 1:
            # 32-bit ELF (52 bytes total header, 36 bytes unpacked from offset 16 to 52)
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, _, _, _ = \
                struct.unpack(f"{endian}HHIIIIIHHHHHH", data[16:52])
            ph_format = f"{endian}IIIIIIII"
        elif ei_class == 2:
            # 64-bit ELF (64 bytes total header, 48 bytes unpacked from offset 16 to 64)
            if len(data) < 64:
                return None
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, _, _, _ = \
                struct.unpack(f"{endian}HHIQQQIHHHHHH", data[16:64])
            ph_format = f"{endian}IIQQQQQQ"
        else:
            return None

        # 1. PIE Check (e_type == 3 is ET_DYN, 2 is ET_EXEC)
        pie = (e_type == 3)

        # 2. Canary Check: look for __stack_chk_fail in symbol table or raw data
        canary = b"__stack_chk_fail" in data

        # 3. NX / RELRO Checks via Program Headers
        nx = False
        relro = False
        has_gnu_stack = False

        if e_phoff > 0 and e_phnum > 0 and e_phentsize > 0:
            for i in range(min(e_phnum, 128)):
                offset = e_phoff + i * e_phentsize
                ph_slice = data[offset:offset + e_phentsize]
                if len(ph_slice) < 32:
                    break

                if ei_class == 1:
                    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                        struct.unpack(ph_format, ph_slice[:32])
                else:
                    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                        struct.unpack(ph_format, ph_slice[:56])

                if p_type == PT_GNU_STACK:
                    has_gnu_stack = True
                    # If PF_X flag is NOT set, stack is Non-Executable (NX enabled)
                    nx = (p_flags & PF_X) == 0
                elif p_type == PT_GNU_RELRO:
                    relro = True

        return {
            "binary": file_path.name,
            "path": str(file_path),
            "class": "32-bit" if ei_class == 1 else "64-bit",
            "endian": "LE" if ei_data == 1 else "BE",
            "nx": nx,
            "canary": canary,
            "pie": pie,
            "relro": relro,
            "has_gnu_stack": has_gnu_stack,
        }
    except Exception:
        return None


def audit_firmware_binaries(firmware_dir: str | Path,
                            device_id: str | None = None,
                            max_binaries: int = 40,
                            evidence_store=None) -> list[Finding]:
    """
    Recursively scans an extracted firmware directory for ELF binaries and
    assesses compiler hardening protections.
    """
    root = Path(firmware_dir)
    device_id = device_id or root.name
    findings: list[Finding] = []

    if not root.exists() or not root.is_dir():
        return [Finding(
            finding_id=_fid("elf_not_found", device_id),
            device_id=device_id,
            check_name="firmware_checksec",
            description=f"Firmware directory not found: {firmware_dir}",
            cvss=None,
            damage={},
        )]

    target_dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "lib", "usr/lib"]
    candidate_paths: list[Path] = []
    for td in target_dirs:
        d = root / td
        if d.is_dir():
            for p in d.rglob("*"):
                if p.is_file() and not p.is_symlink():
                    candidate_paths.append(p)

    # If standard dirs empty, fall back to root rglob
    if not candidate_paths:
        for p in root.rglob("*"):
            if p.is_file() and not p.is_symlink():
                candidate_paths.append(p)

    inspected_results: list[dict[str, Any]] = []
    for p in candidate_paths[:max_binaries * 2]:
        info = inspect_elf(p)
        if info:
            inspected_results.append(info)
            if len(inspected_results) >= max_binaries:
                break

    if not inspected_results:
        return [Finding(
            finding_id=_fid("elf_none_analyzed", device_id),
            device_id=device_id,
            check_name="firmware_checksec",
            description=f"No ELF executable binaries discovered in {firmware_dir}.",
            cvss=None,
            damage={},
        )]

    # Aggregate mitigation statistics
    total = len(inspected_results)
    no_nx = [r for r in inspected_results if not r["nx"]]
    no_canary = [r for r in inspected_results if not r["canary"]]
    no_pie = [r for r in inspected_results if not r["pie"]]
    no_relro = [r for r in inspected_results if not r["relro"]]

    evidence_path = None
    if evidence_store:
        evidence_path = evidence_store.save_json(
            _fid("checksec", device_id),
            "binary_mitigations",
            {"total_analyzed": total, "binaries": inspected_results},
        )

    # 1. Executable Stack (Missing NX / DEP) - Critical Memory Corruption Risk
    if no_nx:
        sample_names = ", ".join(r["binary"] for r in no_nx[:4])
        findings.append(Finding(
            finding_id=_fid("missing_nx", device_id),
            device_id=device_id,
            check_name="firmware_missing_nx",
            description=(
                f"Missing NX/DEP Protection: {len(no_nx)} of {total} binaries have EXECUTABLE stacks "
                f"(e.g., {sample_names}). Simplifies buffer-overflow exploitation and shellcode injection."
            ),
            cvss=7.8,
            damage={"availability": 2, "chaining_depth": 2},
            evidence_path=evidence_path,
        ))

    # 2. Missing Stack Canaries
    if no_canary:
        sample_names = ", ".join(r["binary"] for r in no_canary[:4])
        findings.append(Finding(
            finding_id=_fid("missing_canary", device_id),
            device_id=device_id,
            check_name="firmware_missing_canary",
            description=(
                f"Missing Stack Canaries: {len(no_canary)} of {total} binaries lack stack-smashing protection "
                f"(-fstack-protector) (e.g., {sample_names})."
            ),
            cvss=6.5,
            damage={"availability": 1, "chaining_depth": 1},
            evidence_path=evidence_path,
        ))

    # 3. Missing PIE (Position Independent Executable)
    if no_pie:
        sample_names = ", ".join(r["binary"] for r in no_pie[:4])
        findings.append(Finding(
            finding_id=_fid("missing_pie", device_id),
            device_id=device_id,
            check_name="firmware_missing_pie",
            description=(
                f"Missing PIE/ASLR: {len(no_pie)} of {total} binaries compiled as static ET_EXEC "
                f"with fixed base addresses (e.g., {sample_names}). ROP chain construction is trivial."
            ),
            cvss=5.9,
            damage={"chaining_depth": 1},
            evidence_path=evidence_path,
        ))

    # Overall Summary Finding
    findings.append(Finding(
        finding_id=_fid("checksec_summary", device_id),
        device_id=device_id,
        check_name="firmware_checksec_summary",
        description=(
            f"Analyzed {total} firmware ELF binaries. Mitigations: "
            f"NX={total - len(no_nx)}/{total}, "
            f"Canary={total - len(no_canary)}/{total}, "
            f"PIE={total - len(no_pie)}/{total}, "
            f"RELRO={total - len(no_relro)}/{total}."
        ),
        cvss=None,
        damage={},
        evidence_path=evidence_path,
    ))

    return findings
