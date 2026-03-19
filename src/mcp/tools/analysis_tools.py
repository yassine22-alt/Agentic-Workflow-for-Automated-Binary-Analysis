from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

import pefile

from src.common.entropy import calculate_entropy
from src.common.process import run_command
from src.common.sample import detect_kind

try:
    import r2pipe  # type: ignore
except Exception:  # pragma: no cover - optional dependency in some environments
    r2pipe = None


def _detect_kind_from_file(sample_path: Path, timeout_sec: int) -> str:
    file_res = run_command(["file", "-b", str(sample_path)], timeout_sec=timeout_sec)
    return detect_kind(file_res.stdout if file_res.ok else "")


def _collect_strings(sample_path: Path, timeout_sec: int, min_len: int = 6) -> tuple[list[str], Dict[str, Any]]:
    res = run_command(["strings", "-n", str(min_len), str(sample_path)], timeout_sec=timeout_sec)
    meta = {
        "command_ok": res.ok,
        "timed_out": res.timed_out,
        "returncode": res.returncode,
        "stderr": res.stderr,
    }
    if not res.stdout:
        return [], meta
    lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
    return lines, meta


def _open_r2(sample_path: Path):
    if r2pipe is None:
        return None, "r2pipe not available"
    try:
        handle = r2pipe.open(str(sample_path), flags=["-2"])
        handle.cmd("e scr.color=false")
        return handle, None
    except Exception as exc:
        return None, str(exc)


def _r2_cmdj(handle: Any, command: str) -> Any:
    try:
        raw = handle.cmd(command)
        if not raw:
            return None
        return json.loads(raw)
    except Exception:
        return None


def _r2_collect_string_xrefs(sample_path: Path, suspicious_keywords: List[str]) -> Dict[str, Any]:
    handle, err = _open_r2(sample_path)
    if not handle:
        return {"available": False, "error": err, "string_xrefs": []}

    try:
        handle.cmd("aa")
        strings_json = _r2_cmdj(handle, "izj") or []
        matches = []
        keywords = [kw.lower() for kw in suspicious_keywords]
        for item in strings_json:
            text = str(item.get("string", ""))
            lowered = text.lower()
            matched = next((kw for kw in keywords if kw in lowered), None)
            if not matched:
                continue

            vaddr = item.get("vaddr") or item.get("paddr")
            xrefs = _r2_cmdj(handle, f"axtj @ {vaddr}") if vaddr is not None else []
            xrefs = xrefs or []
            matches.append(
                {
                    "keyword": matched,
                    "string": text[:300],
                    "vaddr": vaddr,
                    "xrefs": [
                        {
                            "from": xr.get("from"),
                            "type": xr.get("type"),
                            "opcode": xr.get("opcode"),
                        }
                        for xr in xrefs[:8]
                    ],
                    "xrefs_count": len(xrefs),
                }
            )
            if len(matches) >= 40:
                break

        return {"available": True, "error": None, "string_xrefs": matches}
    finally:
        try:
            handle.quit()
        except Exception:
            pass


def _r2_collect_syscall_wrappers(sample_path: Path) -> Dict[str, Any]:
    handle, err = _open_r2(sample_path)
    if not handle:
        return {
            "available": False,
            "error": err,
            "candidate_wrappers": [],
            "call_targets": [],
        }

    try:
        handle.cmd("aa")
        functions = _r2_cmdj(handle, "aflj") or []
        wrapper_terms = ["syscall", "exec", "socket", "connect", "mprotect", "fork", "clone"]

        wrappers = []
        call_targets = []
        for fn in functions:
            name = str(fn.get("name", ""))
            lname = name.lower()
            if any(term in lname for term in wrapper_terms):
                wrappers.append(
                    {
                        "name": name,
                        "offset": fn.get("offset"),
                        "size": fn.get("size"),
                        "nbbs": fn.get("nbbs"),
                    }
                )
            call_refs = fn.get("callrefs") or []
            for cref in call_refs[:3]:
                if isinstance(cref, dict):
                    call_targets.append(
                        {
                            "from": fn.get("name"),
                            "to": cref.get("addr") or cref.get("at") or cref.get("name"),
                            "type": cref.get("type"),
                        }
                    )

        return {
            "available": True,
            "error": None,
            "candidate_wrappers": wrappers[:40],
            "call_targets": call_targets[:80],
        }
    finally:
        try:
            handle.quit()
        except Exception:
            pass


def _r2_collect_crypto_refs(sample_path: Path, indicator_tokens: List[str]) -> Dict[str, Any]:
    handle, err = _open_r2(sample_path)
    if not handle:
        return {"available": False, "error": err, "matches": []}

    try:
        handle.cmd("aa")
        strings_json = _r2_cmdj(handle, "izj") or []
        matches = []
        token_set = {tok.lower() for tok in indicator_tokens}

        for item in strings_json:
            text = str(item.get("string", ""))
            lowered = text.lower()
            if not any(tok in lowered for tok in token_set):
                continue

            vaddr = item.get("vaddr") or item.get("paddr")
            xrefs = _r2_cmdj(handle, f"axtj @ {vaddr}") if vaddr is not None else []
            xrefs = xrefs or []
            matches.append(
                {
                    "string": text[:300],
                    "vaddr": vaddr,
                    "xrefs_count": len(xrefs),
                    "xrefs_preview": [xr.get("from") for xr in xrefs[:6]],
                }
            )
            if len(matches) >= 50:
                break

        return {"available": True, "error": None, "matches": matches}
    finally:
        try:
            handle.quit()
        except Exception:
            pass


def _r2_collect_cfg_anomalies(sample_path: Path) -> Dict[str, Any]:
    handle, err = _open_r2(sample_path)
    if not handle:
        return {
            "available": False,
            "error": err,
            "basic_block_overview": {},
            "suspicious_functions": [],
            "call_targets": [],
        }

    try:
        handle.cmd("aa")
        functions = _r2_cmdj(handle, "aflj") or []

        total_functions = len(functions)
        total_basic_blocks = 0
        suspicious_functions = []
        call_targets = []

        for fn in functions:
            nbbs = int(fn.get("nbbs") or 0)
            total_basic_blocks += nbbs
            cyclomatic = int(fn.get("cc") or 0)
            if nbbs >= 80 or cyclomatic >= 25:
                suspicious_functions.append(
                    {
                        "name": fn.get("name"),
                        "offset": fn.get("offset"),
                        "nbbs": nbbs,
                        "cc": cyclomatic,
                        "size": fn.get("size"),
                    }
                )

            for cref in (fn.get("callrefs") or [])[:2]:
                if isinstance(cref, dict):
                    call_targets.append(
                        {
                            "from": fn.get("name"),
                            "to": cref.get("addr") or cref.get("at") or cref.get("name"),
                            "type": cref.get("type"),
                        }
                    )

        return {
            "available": True,
            "error": None,
            "basic_block_overview": {
                "functions": total_functions,
                "total_basic_blocks": total_basic_blocks,
                "avg_basic_blocks_per_function": round(
                    total_basic_blocks / total_functions, 2
                )
                if total_functions
                else 0.0,
            },
            "suspicious_functions": suspicious_functions[:40],
            "call_targets": call_targets[:100],
        }
    finally:
        try:
            handle.quit()
        except Exception:
            pass


def extract_strings_with_context(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    lines, meta = _collect_strings(sample_path, timeout_sec=timeout_sec)

    suspicious_keywords = [
        "powershell", "cmd.exe", "http://", "https://", "createprocess", "virtualalloc",
        "writeprocessmemory", "regsvr32", "rundll32", "mimikatz", "wget", "curl",
    ]
    r2_strings = _r2_collect_string_xrefs(sample_path, suspicious_keywords)

    hits: List[Dict[str, Any]] = []
    lowered = [s.lower() for s in lines]
    for i, val in enumerate(lowered):
        for kw in suspicious_keywords:
            if kw in val:
                start = max(0, i - 1)
                end = min(len(lines), i + 2)
                hits.append(
                    {
                        "keyword": kw,
                        "value": lines[i],
                        "context": lines[start:end],
                    }
                )
                break

    signals: List[Dict[str, Any]] = []
    if hits:
        signals.append(
            {
                "type": "strings.suspicious_keywords",
                "severity": "medium",
                "confidence": 0.6,
                "details": f"Found {len(hits)} suspicious strings with context",
            }
        )

    summary = [
        f"Extracted {len(lines)} printable strings (min length: 6)",
        f"Suspicious contextual hits: {len(hits)}",
    ]
    if r2_strings.get("available"):
        summary.append(
            f"r2 string-xref hits: {len(r2_strings.get('string_xrefs', []))}"
        )
    elif r2_strings.get("error"):
        summary.append("r2 enrichment unavailable for strings context")
    if meta["timed_out"]:
        summary.append("strings command timed out; output may be partial")

    evidence = [
        {
            "source_tool": "extract_strings_with_context",
            "artifact_type": "string",
            "value": h["value"],
            "location": {"offset": None, "va": None},
            "reason": f"Matched keyword: {h['keyword']}",
        }
        for h in hits[:50]
    ]

    return {
        "ok": meta["command_ok"] or bool(lines),
        "summary": summary,
        "signals": signals,
        "artifacts": {
            "strings_count": len(lines),
            "strings_preview": lines[:200],
            "keyword_hits": hits[:200],
            "r2": r2_strings,
        },
        "evidence": evidence,
        "raw_refs": [],
        "error": meta["stderr"] if (not meta["command_ok"] and not lines) else None,
    }


def extract_iocs(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    lines, meta = _collect_strings(sample_path, timeout_sec=timeout_sec)
    blob = "\n".join(lines)

    url_re = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
    domain_re = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    email_re = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)
    win_path_re = re.compile(r"\b[A-Za-z]:\\[^\r\n\t\x00]+")
    reg_re = re.compile(r"\bHKEY_[A-Z_\\]+")

    urls = sorted(set(url_re.findall(blob)))[:200]
    domains = sorted(set(domain_re.findall(blob)))[:200]
    ips = sorted(set(ip_re.findall(blob)))[:200]
    emails = sorted(set(email_re.findall(blob)))[:200]
    paths = sorted(set(win_path_re.findall(blob)))[:200]
    registry_keys = sorted(set(reg_re.findall(blob)))[:200]

    signals: List[Dict[str, Any]] = []
    if urls:
        signals.append({"type": "ioc.url", "severity": "medium", "confidence": 0.75, "details": f"URLs detected: {len(urls)}"})
    if domains:
        signals.append({"type": "ioc.domain", "severity": "low", "confidence": 0.65, "details": f"Domains detected: {len(domains)}"})
    if ips:
        signals.append({"type": "ioc.ip", "severity": "medium", "confidence": 0.7, "details": f"IP addresses detected: {len(ips)}"})

    summary = [
        f"IOC extraction completed from {len(lines)} strings",
        f"URLs={len(urls)}, domains={len(domains)}, IPs={len(ips)}, emails={len(emails)}",
    ]
    if meta["timed_out"]:
        summary.append("strings command timed out; IOC set may be partial")

    evidence = []
    for url in urls[:50]:
        evidence.append({
            "source_tool": "extract_iocs",
            "artifact_type": "ioc",
            "value": url,
            "location": {"offset": None, "va": None},
            "reason": "Matched URL regex",
        })

    return {
        "ok": meta["command_ok"] or bool(lines),
        "summary": summary,
        "signals": signals,
        "artifacts": {
            "urls": urls,
            "domains": domains,
            "ips": ips,
            "emails": emails,
            "paths": paths,
            "registry_keys": registry_keys,
        },
        "evidence": evidence,
        "raw_refs": [],
        "error": meta["stderr"] if (not meta["command_ok"] and not lines) else None,
    }


def detect_packing_or_obfuscation(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    signals: List[Dict[str, Any]] = []
    anomalies: List[str] = []

    upx_res = run_command(["upx", "-t", str(sample_path)], timeout_sec=timeout_sec)
    upx_text = f"{upx_res.stdout}\n{upx_res.stderr}".lower()
    upx_detected = "packed" in upx_text and "notpacked" not in upx_text

    if upx_detected:
        signals.append({
            "type": "packing.upx_detected",
            "severity": "high",
            "confidence": 0.95,
            "details": "UPX test indicates sample may be packed",
        })
        anomalies.append("UPX packing indicators present")

    with sample_path.open("rb") as f:
        data = f.read()
    overall_entropy = round(calculate_entropy(data), 2)
    if overall_entropy >= 7.2:
        signals.append({
            "type": "packing.high_entropy",
            "severity": "medium",
            "confidence": 0.7,
            "details": f"Overall sample entropy is high ({overall_entropy})",
        })
        anomalies.append("Overall entropy suggests compression/encryption")

    summary = [
        f"UPX check status: {'detected' if upx_detected else 'not detected'}",
        f"Overall file entropy: {overall_entropy}",
    ]

    return {
        "ok": True,
        "summary": summary,
        "signals": signals,
        "artifacts": {
            "upx_detected": upx_detected,
            "upx_output": (upx_res.stdout or upx_res.stderr)[:1000],
            "overall_entropy": overall_entropy,
            "anomalies": anomalies,
        },
        "evidence": [
            {
                "source_tool": "detect_packing_or_obfuscation",
                "artifact_type": "heuristic",
                "value": f"entropy={overall_entropy}",
                "location": {"offset": 0, "va": None},
                "reason": "Global entropy heuristic",
            }
        ],
        "raw_refs": [],
        "error": None,
    }


def extract_imports_and_suspicious_apis(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    kind = _detect_kind_from_file(sample_path, timeout_sec)

    network_apis = {"wsastartup", "socket", "connect", "internetopen", "winhttpopen", "urlmon"}
    injection_apis = {"virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread", "ntmapviewofsection"}
    persistence_apis = {"regsetvalue", "schtasks", "createService", "shellstartup", "runonce"}

    imported_names: List[str] = []

    if kind == "PE":
        try:
            pe = pefile.PE(str(sample_path))
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imported_names.append(imp.name.decode(errors="ignore"))
            pe.close()
        except Exception as exc:
            return {
                "ok": False,
                "summary": [f"Failed to parse PE imports: {exc}"],
                "signals": [],
                "artifacts": {"kind": kind},
                "evidence": [],
                "raw_refs": [],
                "error": str(exc),
            }
    else:
        # Fallback for ELF/unknown: symbol extraction with readelf.
        relf = run_command(["readelf", "-Ws", str(sample_path)], timeout_sec=timeout_sec)
        imported_names = re.findall(r"\b([A-Za-z_][A-Za-z0-9_@.]*)\b", relf.stdout)

    imported_lower = [s.lower() for s in imported_names]

    net_hits = sorted({s for s in imported_lower if any(x in s for x in network_apis)})
    inj_hits = sorted({s for s in imported_lower if any(x in s for x in injection_apis)})
    per_hits = sorted({s for s in imported_lower if any(x.lower() in s for x in persistence_apis)})

    signals: List[Dict[str, Any]] = []
    if inj_hits:
        signals.append({"type": "imports.proc_injection_apis", "severity": "high", "confidence": 0.85, "details": f"Injection-related APIs: {', '.join(inj_hits[:10])}"})
    if net_hits:
        signals.append({"type": "imports.network_apis", "severity": "medium", "confidence": 0.75, "details": f"Network APIs: {', '.join(net_hits[:10])}"})
    if per_hits:
        signals.append({"type": "imports.persistence_apis", "severity": "medium", "confidence": 0.7, "details": f"Persistence APIs: {', '.join(per_hits[:10])}"})

    summary = [
        f"Detected binary kind: {kind}",
        f"Imported symbol/API count: {len(imported_names)}",
        f"Suspicious API hits: network={len(net_hits)}, injection={len(inj_hits)}, persistence={len(per_hits)}",
    ]

    evidence = []
    for api in (inj_hits + net_hits + per_hits)[:50]:
        evidence.append(
            {
                "source_tool": "extract_imports_and_suspicious_apis",
                "artifact_type": "import_api",
                "value": api,
                "location": {"offset": None, "va": None},
                "reason": "Matched suspicious API group",
            }
        )

    return {
        "ok": True,
        "summary": summary,
        "signals": signals,
        "artifacts": {
            "kind": kind,
            "imports": sorted(set(imported_names))[:2000],
            "suspicious": {
                "network": net_hits,
                "injection": inj_hits,
                "persistence": per_hits,
            },
        },
        "evidence": evidence,
        "raw_refs": [],
        "error": None,
    }


def find_suspicious_syscalls(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    dis = run_command(["objdump", "-d", str(sample_path)], timeout_sec=timeout_sec)
    text = (dis.stdout or "").lower()
    r2_sys = _r2_collect_syscall_wrappers(sample_path)

    syscall_count = len(re.findall(r"\bsyscall\b", text))
    int80_count = len(re.findall(r"int\s+\$?0x80", text))

    family_patterns = {
        "process_exec": r"\b(execve|createprocess|winexec|shellexecute)\b",
        "network": r"\b(socket|connect|send|recv|wsasocket)\b",
        "memory_protect": r"\b(mprotect|virtualprotect|virtualallocex)\b",
    }

    family_hits = {
        family: len(re.findall(pattern, text))
        for family, pattern in family_patterns.items()
    }

    signals: List[Dict[str, Any]] = []
    if syscall_count + int80_count > 5:
        top_family = max(family_hits, key=family_hits.get)
        signals.append(
            {
                "type": "syscall.suspicious_family",
                "severity": "medium",
                "confidence": 0.65,
                "details": f"Frequent syscall usage detected; dominant family: {top_family}",
            }
        )

    summary = [
        f"Disassembly available: {'yes' if bool(dis.stdout) else 'no'}",
        f"syscall instructions: {syscall_count}, int 0x80: {int80_count}",
        "Family hit counts: " + ", ".join(f"{k}={v}" for k, v in family_hits.items()),
    ]
    if r2_sys.get("available"):
        summary.append(
            "r2 wrappers/call-targets: "
            f"{len(r2_sys.get('candidate_wrappers', []))}/{len(r2_sys.get('call_targets', []))}"
        )
    elif r2_sys.get("error"):
        summary.append("r2 enrichment unavailable for syscall analysis")
    if dis.timed_out:
        summary.append("objdump timed out; analysis may be partial")

    return {
        "ok": dis.ok or bool(dis.stdout),
        "summary": summary,
        "signals": signals,
        "artifacts": {
            "syscall_count": syscall_count,
            "int80_count": int80_count,
            "family_hits": family_hits,
            "r2": r2_sys,
        },
        "evidence": [
            {
                "source_tool": "find_suspicious_syscalls",
                "artifact_type": "disassembly_stat",
                "value": f"syscall={syscall_count},int80={int80_count}",
                "location": {"offset": None, "va": None},
                "reason": "Instruction frequency heuristic",
            }
        ],
        "raw_refs": [],
        "error": dis.stderr if (not dis.ok and not dis.stdout) else None,
    }


def extract_crypto_constants(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    lines, meta = _collect_strings(sample_path, timeout_sec=timeout_sec)
    blob = "\n".join(lines).lower()

    indicators = {
        "aes": ["aes", "rijndael", "cbc", "gcm"],
        "rc4": ["rc4", "arc4"],
        "rsa": ["rsa", "pkcs1", "oaep"],
        "sha": ["sha1", "sha256", "sha512", "md5"],
    }
    indicator_tokens = [tok for group in indicators.values() for tok in group]
    r2_crypto = _r2_collect_crypto_refs(sample_path, indicator_tokens)

    hits: Dict[str, List[str]] = {}
    for family, tokens in indicators.items():
        family_hits = [tok for tok in tokens if tok in blob]
        if family_hits:
            hits[family] = family_hits

    signals: List[Dict[str, Any]] = []
    if "aes" in hits:
        signals.append({"type": "crypto.suspected_aes", "severity": "medium", "confidence": 0.6, "details": "AES-related constants/strings detected"})
    if "rc4" in hits:
        signals.append({"type": "crypto.suspected_rc4", "severity": "medium", "confidence": 0.6, "details": "RC4-related constants/strings detected"})

    summary = [
        f"Crypto indicator families detected: {', '.join(sorted(hits.keys())) if hits else 'none'}",
        f"Indicator token matches: {sum(len(v) for v in hits.values())}",
    ]
    if r2_crypto.get("available"):
        summary.append(f"r2 crypto references: {len(r2_crypto.get('matches', []))}")
    elif r2_crypto.get("error"):
        summary.append("r2 enrichment unavailable for crypto extraction")
    if meta["timed_out"]:
        summary.append("strings command timed out; crypto indicators may be partial")

    evidence = []
    for fam, toks in hits.items():
        for tok in toks:
            evidence.append(
                {
                    "source_tool": "extract_crypto_constants",
                    "artifact_type": "crypto_indicator",
                    "value": tok,
                    "location": {"offset": None, "va": None},
                    "reason": f"Matched crypto family: {fam}",
                }
            )

    return {
        "ok": meta["command_ok"] or bool(lines),
        "summary": summary,
        "signals": signals,
        "artifacts": {
            "families": hits,
            "sampled_strings": lines[:200],
            "r2": r2_crypto,
        },
        "evidence": evidence,
        "raw_refs": [],
        "error": meta["stderr"] if (not meta["command_ok"] and not lines) else None,
    }


def analyze_control_flow_anomalies(sample_path: Path, timeout_sec: int) -> Dict[str, Any]:
    dis = run_command(["objdump", "-d", str(sample_path)], timeout_sec=timeout_sec)
    text = (dis.stdout or "").lower()
    r2_cfg = _r2_collect_cfg_anomalies(sample_path)

    total_branches = len(re.findall(r"\bj[a-z]{1,3}\b", text)) + len(re.findall(r"\bcall\b", text))
    indirect_jumps = len(re.findall(r"\bjmp\s+\*", text)) + len(re.findall(r"\bcall\s+\*", text))
    int3_count = len(re.findall(r"\bint3\b", text))

    ratio = (indirect_jumps / total_branches) if total_branches else 0.0

    signals: List[Dict[str, Any]] = []
    if indirect_jumps >= 10 and ratio >= 0.2:
        signals.append(
            {
                "type": "cfg.indirect_jump_heavy",
                "severity": "medium",
                "confidence": 0.7,
                "details": f"Indirect branch ratio is high ({ratio:.2f})",
            }
        )
    if int3_count >= 20:
        signals.append(
            {
                "type": "cfg.suspicious_stubs",
                "severity": "low",
                "confidence": 0.55,
                "details": f"Frequent int3 stubs observed ({int3_count})",
            }
        )

    summary = [
        f"Control-flow stats: total_branches={total_branches}, indirect={indirect_jumps}, ratio={ratio:.2f}",
        f"Trap/stub markers (int3): {int3_count}",
    ]
    if r2_cfg.get("available"):
        bb = r2_cfg.get("basic_block_overview", {})
        summary.append(
            "r2 basic-block overview: "
            f"functions={bb.get('functions', 0)}, blocks={bb.get('total_basic_blocks', 0)}"
        )
    elif r2_cfg.get("error"):
        summary.append("r2 enrichment unavailable for cfg anomaly analysis")
    if dis.timed_out:
        summary.append("objdump timed out; CFG metrics may be partial")

    return {
        "ok": dis.ok or bool(dis.stdout),
        "summary": summary,
        "signals": signals,
        "artifacts": {
            "total_branches": total_branches,
            "indirect_branches": indirect_jumps,
            "indirect_ratio": round(ratio, 4),
            "int3_count": int3_count,
            "r2": r2_cfg,
        },
        "evidence": [
            {
                "source_tool": "analyze_control_flow_anomalies",
                "artifact_type": "cfg_metric",
                "value": f"ratio={ratio:.2f}",
                "location": {"offset": None, "va": None},
                "reason": "Indirect branch density heuristic",
            }
        ],
        "raw_refs": [],
        "error": dis.stderr if (not dis.ok and not dis.stdout) else None,
    }
