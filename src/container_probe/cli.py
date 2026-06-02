from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from .detectors import inspect_file


PASSWORD_RECOVERY_SUPPORT = {
    "7z archive": "Supported by Hashcat and John the Ripper",
    "Encrypted Microsoft Office document": "Supported by Hashcat and John the Ripper",
    "Encrypted PDF document": "Supported by Hashcat and John the Ripper",
    "KeePass KDB database": "Supported by Hashcat and John the Ripper",
    "KeePass KDBX database": "Supported by Hashcat and John the Ripper",
    "OpenSSH private key": "Supported by Hashcat and John the Ripper",
    "PKCS#12 / PFX container": "Supported by Hashcat and John the Ripper",
    "RAR archive": "Supported by Hashcat and John the Ripper for many RAR variants",
    "ZIP archive with WinZip AES": "Supported by John the Ripper; Hashcat support varies by ZIP variant",
    "Encrypted ZIP archive": "Supported by John the Ripper; Hashcat support varies by ZIP variant",
}

FORMAT_SPECIFIC_GUIDANCE = {
    "BitLocker volume": "Deeper BitLocker metadata parsing or filesystem-level analysis may reveal more than the boot-sector signature alone.",
    "Bouncy Castle BKS keystore": "This is a candidate match; stronger confirmation may require application context or a dedicated BKS parser.",
    "Bouncy Castle UBER keystore": "This is a candidate match; stronger confirmation may require application context or a dedicated UBER parser.",
    "SafeHouse virtual disk": "Further SafeHouse-specific reverse engineering may be needed to identify additional header fields or confirm the cipher.",
    "SQLCipher-like encrypted SQLite candidate": "This is a heuristic match; application context or a dedicated SQLCipher workflow is the best way to confirm it.",
}


class Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def bold(self, text: str) -> str:
        return self.wrap("1", text)

    def cyan(self, text: str) -> str:
        return self.wrap("36", text)

    def green(self, text: str) -> str:
        return self.wrap("32", text)

    def yellow(self, text: str) -> str:
        return self.wrap("33", text)

    def red(self, text: str) -> str:
        return self.wrap("31", text)

    def dim(self, text: str) -> str:
        return self.wrap("2", text)

    def wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="container-probe",
        description="Inspect an encrypted container and report the likely protocol or format.",
    )
    parser.add_argument("path", type=Path, help="Path to the file to inspect")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of a text report",
    )
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="Control ANSI color output for the text report",
    )
    return parser


def render_text(report: dict, style: Style | None = None) -> str:
    styler = style or Style(False)
    encryption_details = summarize_encryption_details(report["detections"])
    algorithm_summary = summarize_algorithms(report["detections"])
    analysis_guidance = build_analysis_guidance(report)
    verdict = summarize_verdict(report["detections"])

    lines = [
        heading(styler, "Container Probe"),
        f"{label(styler, 'File')}: {report['path']}",
        f"{label(styler, 'Size')}: {report['size_bytes']} bytes",
        f"{label(styler, 'Analyzed')}: {report['analyzed_bytes']} bytes",
        f"{label(styler, 'Entropy')}: {report['sample_entropy']:.2f} bits/byte",
        f"{label(styler, 'Chi-square')}: {report['chi_square']:.2f}",
        f"{label(styler, 'Printable ratio')}: {report['printable_ratio']:.3f}",
    ]

    if verdict:
        lines.append(f"{label(styler, 'Verdict')}: {verdict}")

    if encryption_details:
        lines.extend(["", section(styler, "Encryption Details")])
        for detail_label, value in encryption_details:
            lines.append(f"  {detail_label}: {value}")

    if algorithm_summary:
        lines.extend(["", section(styler, "Algorithm Summary")])
        for item in algorithm_summary:
            lines.append(f"- {item}")

    detections = report["detections"]
    lines.extend(["", section(styler, "Format Matches")])
    if detections:
        lines.extend(render_findings(detections, styler))
    else:
        lines.append("- No known format matched.")

    heuristics = report.get("heuristics", [])
    if heuristics:
        lines.extend(["", section(styler, "Heuristics")])
        lines.extend(render_findings(heuristics, styler))

    sidecar_hints = report.get("sidecar_hints", [])
    if sidecar_hints:
        lines.extend(["", section(styler, "Sidecar Hints")])
        lines.extend(render_findings(sidecar_hints, styler))

    if analysis_guidance:
        lines.extend(["", section(styler, "Analysis Guidance")])
        for item in analysis_guidance:
            lines.append(f"- {item}")

    notes = report["notes"]
    if notes:
        lines.extend(["", section(styler, "Notes")])
        for note in notes:
            lines.append(f"- {note}")

    return "\n".join(lines)


def render_findings(findings: list[dict], styler: Style) -> list[str]:
    lines: list[str] = []
    for finding in findings:
        badge = confidence_badge(styler, finding["confidence"])
        lines.append(f"- {styler.bold(finding['label'])} {badge}")
        lines.append(f"  {finding['rationale']}")
        for key, value in finding["details"].items():
            lines.append(f"  {key}: {value}")
    return lines


def summarize_algorithms(detections: list[dict]) -> list[str]:
    summary: list[str] = []
    seen: set[str] = set()

    for detection in detections:
        label_name = detection["label"]
        details = detection["details"]

        if "encryption_algorithm" in details:
            item = f"{label_name}: {details['encryption_algorithm']}"
            if "kdf" in details:
                item += f" (KDF: {details['kdf']})"
            if item not in seen:
                summary.append(item)
                seen.add(item)

        if "payload_encryption" in details:
            item = f"{label_name}: {details['payload_encryption']}"
            if item not in seen:
                summary.append(item)
                seen.add(item)

    return summary


def summarize_encryption_details(detections: list[dict]) -> list[tuple[str, str]]:
    best_details: list[tuple[str, str]] = []
    best_score = -1

    for detection in detections:
        details = normalize_encryption_details(detection["label"], detection["details"])
        if not details:
            continue
        score = len(details)
        if detection["confidence"] == "high":
            score += 2
        elif detection["confidence"] == "medium":
            score += 1
        if score > best_score:
            best_details = details
            best_score = score

    return best_details


def normalize_encryption_details(label_name: str, details: dict[str, str]) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []

    algorithm = details.get("payload_encryption") or details.get("encryption_algorithm")
    if algorithm:
        rows.append(("Algorithm", algorithm))

    kdf = details.get("kdf")
    kdf_hash = details.get("kdf_hash")
    if kdf and kdf_hash:
        rows.append(("KDF", f"{kdf} (hash: {kdf_hash})"))
    elif kdf:
        rows.append(("KDF", kdf))
    elif kdf_hash:
        rows.append(("KDF", kdf_hash))

    if "kdf_iterations" in details:
        rows.append(("KDF Iterations", details["kdf_iterations"]))

    if "kdf_salt_length" in details:
        salt_summary = f"{details['kdf_salt_length']} bytes"
        if "kdf_salt_offset" in details and "kdf_salt_end" in details:
            salt_summary += f" ({details['kdf_salt_offset']}-{details['kdf_salt_end']})"
        rows.append(("KDF Salt", salt_summary))

    compression = details.get("compression_methods") or details.get("compression_method")
    if compression:
        rows.append(("Compression", compression))

    if "cipher_chunk" in details:
        cipher_summary = details["cipher_chunk"]
        if "cipher_chunk_offset" in details:
            cipher_summary += f" at {details['cipher_chunk_offset']}"
        rows.append(("Cipher Chunk", cipher_summary))

    if "encrypted_password_verifier" in details:
        verifier_summary = details["encrypted_password_verifier"]
        if "encrypted_password_verifier_offset" in details:
            verifier_summary += f" at {details['encrypted_password_verifier_offset']}"
        rows.append(("Encrypted Password Verifier", verifier_summary))

    header_encrypted = details.get("header_encrypted")
    if header_encrypted == "yes":
        rows.append(("Header Encrypted", "Yes"))
    elif header_encrypted == "no":
        rows.append(("Header Encrypted", "No"))

    password_recovery = PASSWORD_RECOVERY_SUPPORT.get(label_name)
    if password_recovery:
        rows.append(("Password Recovery", password_recovery))

    return rows


def summarize_verdict(detections: list[dict]) -> str | None:
    if not detections:
        return "No known container or algorithm detected."

    has_known_algorithm = False
    has_hidden_algorithm = False

    for detection in detections:
        details = detection["details"]
        if "payload_encryption" in details:
            has_known_algorithm = True
        algorithm = details.get("encryption_algorithm")
        if algorithm:
            if algorithm.startswith("not exposed") or algorithm.startswith("not recovered"):
                has_hidden_algorithm = True
            elif not algorithm.startswith("unknown "):
                has_known_algorithm = True

    if has_known_algorithm:
        return "Known algorithm identified from visible metadata."
    if has_hidden_algorithm:
        return "Format identified, but the algorithm is not exposed by the parsed header."
    return "Container detected, but no specific algorithm could be confirmed."


def build_analysis_guidance(report: dict) -> list[str]:
    detections = report.get("detections", [])
    heuristics = report.get("heuristics", [])
    sidecar_hints = report.get("sidecar_hints", [])

    primary = select_primary_detection(detections)
    if primary is None:
        return build_unknown_guidance(sidecar_hints, heuristics)

    label_name = primary["label"]
    details = primary["details"]
    algorithm = details.get("payload_encryption") or details.get("encryption_algorithm")
    is_hidden = bool(
        algorithm
        and (
            algorithm.startswith("not exposed")
            or algorithm.startswith("not recovered")
            or algorithm.startswith("not provable")
        )
    )
    is_candidate = "candidate" in label_name.lower() or "candidate" in primary["rationale"].lower()

    if not is_hidden and not is_candidate and not sidecar_hints:
        return []

    guidance: list[str] = []

    if label_name == "Unknown high-entropy blob":
        return build_unknown_guidance(sidecar_hints, heuristics)

    guidance.append(f"Container format identified as {label_name}.")

    if is_hidden:
        guidance.append("Encryption algorithm is not exposed in the parsed header metadata.")
    elif is_candidate:
        guidance.append("This match is heuristic rather than fully proven from a strong format signature.")

    specific_guidance = FORMAT_SPECIFIC_GUIDANCE.get(label_name)
    if specific_guidance:
        guidance.append(specific_guidance)
    elif is_hidden:
        guidance.append("A fuller parser or vendor-specific documentation may reveal additional encryption details.")

    if sidecar_hints:
        guidance.append("Adjacent sidecar metadata may contain additional cipher, mode, salt, IV, or KDF details.")

    password_recovery = PASSWORD_RECOVERY_SUPPORT.get(label_name)
    if password_recovery:
        guidance.append(f"Password recovery is {password_recovery.lower()} for this container family.")
    elif label_name != "Unknown high-entropy blob":
        guidance.append("Any password-recovery approach should target the identified container format rather than generic raw ciphertext.")

    return unique_lines(guidance)


def build_unknown_guidance(sidecar_hints: list[dict], heuristics: list[dict]) -> list[str]:
    guidance = [
        "No supported container format was identified with high confidence.",
        "The file should be treated as opaque data until stronger format evidence is found.",
    ]

    heuristic_labels = {item["label"] for item in heuristics}
    if "16-byte alignment heuristic" in heuristic_labels:
        guidance.append("The byte length aligns with a 16-byte block size, which is consistent with many block-cipher formats such as AES.")
    elif "8-byte alignment heuristic" in heuristic_labels:
        guidance.append("The byte length aligns with an 8-byte block size, which is consistent with some older block-cipher layouts.")

    if sidecar_hints:
        guidance.append("Adjacent sidecar metadata may be the best source for cipher, mode, or KDF details.")
    else:
        guidance.append("Check for adjacent .json, .xml, .yml, .yaml, or .inf files that may describe the encryption settings.")

    guidance.append("Compare the file against vendor-specific or headerless container families such as application-specific blobs, VeraCrypt-style volumes, or raw encrypted disk segments.")
    return unique_lines(guidance)


def select_primary_detection(detections: list[dict]) -> dict | None:
    if not detections:
        return None
    ranked = sorted(
        detections,
        key=lambda item: (
            confidence_rank(item["confidence"]),
            0 if item["label"] == "Unknown high-entropy blob" else 1,
        ),
        reverse=True,
    )
    return ranked[0]


def confidence_rank(confidence: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(confidence, 0)


def unique_lines(lines: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            ordered.append(line)
    return ordered


def confidence_badge(styler: Style, confidence: str) -> str:
    text = f"[{confidence.upper()}]"
    if confidence == "high":
        return styler.green(text)
    if confidence == "medium":
        return styler.yellow(text)
    return styler.red(text)


def heading(styler: Style, text: str) -> str:
    return styler.bold(styler.cyan(text))


def section(styler: Style, text: str) -> str:
    return styler.bold(text)


def label(styler: Style, text: str) -> str:
    return styler.dim(text)


def should_use_color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    return sys.stdout.isatty() and os.environ.get("TERM", "dumb") != "dumb"


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    report = inspect_file(args.path).to_dict()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report, Style(should_use_color(args.color))))

    return 0
