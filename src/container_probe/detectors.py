from __future__ import annotations

import base64
import binascii
from dataclasses import asdict, dataclass, field
import json
import math
from pathlib import Path
import re
import struct


READ_LIMIT = 1024 * 1024
BITLOCKER_SIGNATURE = b"-FVE-FS-"
DMG_TRAILER_SIZE = 512
SEVEN_Z_SIGNATURE = b"7z\xbc\xaf\x27\x1c"
RAR4_SIGNATURE = b"Rar!\x1a\x07\x00"
RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"
OLE_CFB_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
JKS_MAGIC = 0xFEEDFEED
JCEKS_MAGIC = 0xCECECECE
BKS_VERSION_TAGS = {1, 2}
KDB_SIGNATURE_1 = 0x9AA2D903
KDB_SIGNATURE_2 = 0xB54BFB65
KDBX_SIGNATURE_1 = 0x9AA2D903
KDBX_SIGNATURE_2 = 0xB54BFB67
LUKS1_MAGIC = b"LUKS\xba\xbe"
LUKS2_MAGIC = b"SKUL\xba\xbe"
KNOWN_SIDECAR_SUFFIXES = {".json", ".xml", ".yml", ".yaml", ".inf"}
PGP_SYMMETRIC_ALGORITHMS = {
    0: "plaintext or unencrypted",
    1: "IDEA",
    2: "Triple DES",
    3: "CAST5",
    4: "Blowfish",
    7: "AES-128",
    8: "AES-192",
    9: "AES-256",
    10: "Twofish",
    11: "Camellia-128",
    12: "Camellia-192",
    13: "Camellia-256",
}
PGP_HASH_ALGORITHMS = {
    1: "MD5",
    2: "SHA-1",
    3: "RIPEMD-160",
    8: "SHA-256",
    9: "SHA-384",
    10: "SHA-512",
    11: "SHA-224",
}
PGP_COMPRESSION_ALGORITHMS = {
    0: "uncompressed",
    1: "ZIP",
    2: "ZLIB",
    3: "BZip2",
}
CMS_CONTENT_TYPES = {
    "1.2.840.113549.1.7.1": "data",
    "1.2.840.113549.1.7.3": "envelopedData",
    "1.2.840.113549.1.7.6": "encryptedData",
    "1.2.840.113549.1.9.16.1.23": "authEnvelopedData",
}
CMS_ENCRYPTION_OIDS = {
    "1.2.840.113549.3.2": "RC2-CBC",
    "1.2.840.113549.3.7": "Triple DES-CBC",
    "1.3.14.3.2.7": "DES-CBC",
    "2.16.840.1.101.3.4.1.2": "AES-128-CBC",
    "2.16.840.1.101.3.4.1.6": "AES-128-GCM",
    "2.16.840.1.101.3.4.1.22": "AES-192-CBC",
    "2.16.840.1.101.3.4.1.26": "AES-192-GCM",
    "2.16.840.1.101.3.4.1.42": "AES-256-CBC",
    "2.16.840.1.101.3.4.1.46": "AES-256-GCM",
}
PKCS5_KDFS = {
    "1.2.840.113549.1.5.12": "PBKDF2",
    "1.3.6.1.4.1.11591.4.11": "scrypt",
}
PKCS8_ENCRYPTION_SCHEMES = {
    **CMS_ENCRYPTION_OIDS,
    "1.2.840.113549.3.4": "RC4",
}
PKCS12_PBE_OIDS = {
    "1.2.840.113549.1.12.1.1": "PKCS12 pbeWithSHAAnd128BitRC4",
    "1.2.840.113549.1.12.1.2": "PKCS12 pbeWithSHAAnd40BitRC4",
    "1.2.840.113549.1.12.1.3": "PKCS12 pbeWithSHAAnd3-KeyTripleDES-CBC",
    "1.2.840.113549.1.12.1.4": "PKCS12 pbeWithSHAAnd2-KeyTripleDES-CBC",
    "1.2.840.113549.1.12.1.5": "PKCS12 pbeWithSHAAnd128BitRC2-CBC",
    "1.2.840.113549.1.12.1.6": "PKCS12 pbeWithSHAAnd40BitRC2-CBC",
}
KDBX_CIPHER_UUIDS = {
    bytes.fromhex("31C1F2E6BF714350BE5805216AFC5AFF"): "AES-256-CBC",
    bytes.fromhex("D6038A2B8B6F4CB5A524339A31DBB59A"): "ChaCha20",
}
KDBX_KDF_UUIDS = {
    bytes.fromhex("C9D9F39A628A4460BF740D08C18A4FEA"): "AES-KDF",
    bytes.fromhex("EF636DDF8C29444B91F7A9A403E30A0C"): "Argon2d",
    bytes.fromhex("9E298B1956DB4773B23DFC3EC6F0A1E6"): "Argon2id",
}
KDB_FLAG_ALGORITHMS = {
    0x00000002: "AES",
    0x00000008: "Twofish",
}
PDF_FILTER_ALGORITHMS = {
    "V2": "RC4 or compatible legacy stream cipher",
    "AESV2": "AES-128-CBC",
    "AESV3": "AES-256",
}
TRADITIONAL_PEM_LABELS = {
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
}
SEVEN_Z_METHOD_NAMES = {
    b"\x00": "Copy",
    b"\x03\x01\x01": "LZMA",
    b"\x21": "LZMA2",
    b"\x03\x03\x01\x03": "BCJ",
    b"\x03\x03\x01\x1B": "BCJ2",
    b"\x03\x04\x01": "PPMd",
    b"\x04\x01\x08": "Deflate",
    b"\x04\x02\x02": "BZip2",
    b"\x04\x03\x01": "RAR29",
    b"\x06\xF1\x07\x01": "7zAES",
}
ZIP_COMPRESSION_METHODS = {
    0: "stored",
    8: "deflate",
    9: "deflate64",
    12: "bzip2",
    14: "lzma",
    93: "zstd",
    98: "ppmd",
    99: "aes-marker",
}


@dataclass(slots=True)
class Detection:
    label: str
    confidence: str
    rationale: str
    details: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class InspectionReport:
    path: str
    size_bytes: int
    analyzed_bytes: int
    sample_entropy: float
    chi_square: float
    printable_ratio: float
    detections: list[Detection]
    heuristics: list[Detection] = field(default_factory=list)
    sidecar_hints: list[Detection] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "analyzed_bytes": self.analyzed_bytes,
            "sample_entropy": self.sample_entropy,
            "chi_square": self.chi_square,
            "printable_ratio": self.printable_ratio,
            "detections": [asdict(item) for item in self.detections],
            "heuristics": [asdict(item) for item in self.heuristics],
            "sidecar_hints": [asdict(item) for item in self.sidecar_hints],
            "notes": list(self.notes),
        }


class BinaryReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def remaining(self) -> int:
        return len(self.data) - self.offset

    def read_byte(self) -> int:
        if self.offset >= len(self.data):
            raise ValueError("unexpected end of data")
        value = self.data[self.offset]
        self.offset += 1
        return value

    def read_bytes(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.data):
            raise ValueError("unexpected end of data")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def read_uint64_7z(self) -> int:
        first = self.read_byte()
        mask = 0x80
        value = 0
        for index in range(8):
            if first & mask == 0:
                return value | ((first & (mask - 1)) << (8 * index))
            value |= self.read_byte() << (8 * index)
            mask >>= 1
        return value

    def skip(self, size: int) -> None:
        self.read_bytes(size)


def inspect_file(path: Path) -> InspectionReport:
    raw = path.read_bytes()
    sample = raw[:READ_LIMIT]
    sidecar_hints = scan_sidecar_files(path)
    report = inspect_bytes(sample, path=str(path), size_bytes=len(raw), full_data=raw)
    report.sidecar_hints = sidecar_hints
    return report


def inspect_bytes(
    data: bytes,
    path: str = "<memory>",
    size_bytes: int | None = None,
    full_data: bytes | None = None,
) -> InspectionReport:
    full = data if full_data is None else full_data
    size = len(full) if size_bytes is None else size_bytes
    entropy = shannon_entropy(data)
    chi_square = chi_square_uniform(data)
    ratio = printable_ratio(data[: min(len(data), 4096)])
    detections: list[Detection] = []
    notes: list[str] = []

    detectors = [
        detect_safehouse_virtual_disk,
        detect_bitlocker,
        detect_ansible_vault,
        detect_keepass_kdb,
        detect_keepass_kdbx,
        detect_java_keystore,
        detect_bouncycastle_keystore,
        detect_sqlcipher_like_database,
        detect_apple_dmg,
        detect_openssh_private_key,
        detect_pkcs8_encrypted_private_key,
        detect_traditional_pem_private_key,
        detect_pkcs12,
        detect_pdf_encryption,
        detect_encrypted_office_document,
        detect_openssl_salted,
        detect_age,
        detect_pgp_ascii,
        detect_pgp_binary,
        detect_cms,
        detect_luks1,
        detect_luks2,
        detect_zip_encryption,
        detect_rar,
        detect_7z,
    ]

    for detector in detectors:
        result = detector(data)
        if result is not None:
            detections.append(result)

    if not detections:
        heuristic_match = detect_unknown_high_entropy(data, entropy, chi_square, ratio)
        if heuristic_match is not None:
            detections.append(heuristic_match)

    heuristics = analyze_statistics(data, entropy, chi_square, ratio)
    if should_apply_raw_block_heuristics(detections):
        heuristics.extend(analyze_raw_block_cipher_heuristics(full))

    if not detections:
        notes.append("No known signature matched in the analyzed bytes.")

    if not detections and entropy >= 7.5:
        notes.append(
            "Opaque high-entropy files can include raw ciphertext, VeraCrypt/TrueCrypt-style containers, or compressed data."
        )

    notes.append(
        "Format detection is strongest when a file stores a stable header or preamble."
    )
    notes.append(
        "Some formats intentionally hide algorithm details or avoid fixed magic bytes, so algorithm detection is not always possible."
    )

    return InspectionReport(
        path=path,
        size_bytes=size,
        analyzed_bytes=len(data),
        sample_entropy=entropy,
        chi_square=chi_square,
        printable_ratio=ratio,
        detections=sort_findings(detections),
        heuristics=sort_findings(heuristics),
        notes=notes,
    )


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    entropy = 0.0
    length = len(data)
    for count in counts:
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def chi_square_uniform(data: bytes) -> float:
    if not data:
        return 0.0

    expected = len(data) / 256.0
    if expected == 0:
        return 0.0

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    return sum(((count - expected) ** 2) / expected for count in counts)


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for byte in data if byte in b"\t\n\r" or 32 <= byte <= 126)
    return printable / len(data)


def sort_findings(findings: list[Detection]) -> list[Detection]:
    rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(findings, key=lambda item: (rank.get(item.confidence, 99), item.label))


def should_apply_raw_block_heuristics(detections: list[Detection]) -> bool:
    if not detections:
        return True

    structured_labels = {
        "BitLocker volume",
        "Ansible Vault file",
        "Bouncy Castle BKS keystore",
        "Bouncy Castle UBER keystore",
        "Java JCEKS keystore",
        "Java JKS keystore",
        "KeePass KDB database",
        "KeePass KDBX database",
        "Apple DMG disk image",
        "CMS/PKCS#7 encrypted content",
        "Encrypted ZIP archive",
        "LUKS1 container",
        "LUKS2 container",
        "RAR archive",
        "SafeHouse virtual disk",
        "ZIP archive with WinZip AES",
        "7z archive",
        "OpenSSL salted blob",
        "age file format",
        "age armored file",
        "ASCII-armored OpenPGP message",
    }
    return not any(item.label in structured_labels for item in detections)


def analyze_statistics(
    data: bytes,
    entropy: float,
    chi_square: float,
    ratio: float,
) -> list[Detection]:
    if not data:
        return []

    details = {
        "entropy_bits_per_byte": f"{entropy:.3f}",
        "chi_square_uniformity": f"{chi_square:.2f}",
        "printable_ratio": f"{ratio:.3f}",
    }

    if entropy >= 7.5 and 120.0 <= chi_square <= 420.0:
        rationale = (
            "The sample is high entropy and reasonably close to a uniform byte distribution, which is consistent with ciphertext or compressed data."
        )
        confidence = "medium"
    elif ratio >= 0.85 and entropy <= 5.5:
        rationale = (
            "The sample is highly printable with relatively low entropy, which looks more like text or structured metadata than strong encryption."
        )
        confidence = "medium"
    else:
        rationale = (
            "The statistical profile is mixed: useful as a sanity check, but not enough to prove a specific algorithm."
        )
        confidence = "low"

    return [
        Detection(
            label="Statistical profile",
            confidence=confidence,
            rationale=rationale,
            details=details,
        )
    ]


def analyze_raw_block_cipher_heuristics(data: bytes) -> list[Detection]:
    if not data:
        return []

    findings: list[Detection] = []
    size = len(data)

    if size % 16 == 0:
        findings.append(
            Detection(
                label="16-byte alignment heuristic",
                confidence="low",
                rationale=(
                    "The total length is a multiple of 16 bytes, which is compatible with many modern block-cipher outputs such as AES or Camellia."
                ),
                details={"size_mod_16": "0"},
            )
        )
    elif size % 8 == 0:
        findings.append(
            Detection(
                label="8-byte alignment heuristic",
                confidence="low",
                rationale=(
                    "The total length is a multiple of 8 bytes, which is compatible with older block-cipher layouts such as DES, Triple DES, or Blowfish."
                ),
                details={"size_mod_8": "0"},
            )
        )

    for block_size in (16, 8):
        padding = detect_pkcs7_padding(data, block_size)
        if padding is not None:
            findings.append(
                Detection(
                    label=f"PKCS#7 padding candidate ({block_size}-byte blocks)",
                    confidence="low",
                    rationale=(
                        "The trailing bytes match a valid PKCS#7 padding pattern. This is compatible with a block-cipher payload, but it can also occur by chance."
                    ),
                    details={"padding_length": str(padding)},
                )
            )

    return findings


def detect_pkcs7_padding(data: bytes, block_size: int) -> int | None:
    if not data or len(data) < block_size:
        return None

    padding = data[-1]
    if padding == 0 or padding > block_size:
        return None
    if data[-padding:] != bytes([padding]) * padding:
        return None
    return padding


def scan_sidecar_files(path: Path) -> list[Detection]:
    findings: list[Detection] = []
    if not path.parent.exists():
        return findings

    candidates = [
        sibling
        for sibling in path.parent.iterdir()
        if sibling.is_file()
        and sibling != path
        and sibling.suffix.lower() in KNOWN_SIDECAR_SUFFIXES
        and (
            sibling.stem == path.stem
            or sibling.name.startswith(f"{path.name}.")
        )
    ]

    for candidate in sorted(candidates):
        details = extract_sidecar_hints(candidate)
        if details:
            findings.append(
                Detection(
                    label="Sidecar metadata hint",
                    confidence="medium",
                    rationale=(
                        "An adjacent metadata file contains encryption-related fields that may describe the payload."
                    ),
                    details={"path": str(candidate), **details},
                )
            )

    return findings


def extract_sidecar_hints(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {}

    matches: dict[str, str] = {}
    if path.suffix.lower() == ".json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        if payload is not None:
            json_matches = find_json_encryption_keys(payload)
            if json_matches:
                return json_matches

    line_patterns = [
        re.compile(
            r"(?i)\b(cipher|algorithm|encryption|mode|iv|salt|kdf|pbkdf)\b\s*[:=]\s*(.+)"
        ),
        re.compile(
            r"(?is)<(cipher|algorithm|encryption|mode|iv|salt|kdf|pbkdf)>\s*([^<]+)\s*</\1>"
        ),
    ]
    for pattern in line_patterns:
        for match in pattern.finditer(text[:262144]):
            key = match.group(1).lower()
            value = sanitize_text(match.group(2))
            if value:
                matches[key] = value
            if len(matches) >= 8:
                return matches

    return matches


def find_json_encryption_keys(payload: object, prefix: str = "") -> dict[str, str]:
    results: dict[str, str] = {}
    if isinstance(payload, dict):
        for key, value in payload.items():
            dotted = f"{prefix}.{key}" if prefix else str(key)
            lower = str(key).lower()
            if any(token in lower for token in ("cipher", "algorithm", "encrypt", "mode", "iv", "salt", "kdf", "pbkdf")):
                results[dotted] = sanitize_text(json.dumps(value) if not isinstance(value, str) else value)
            nested = find_json_encryption_keys(value, dotted)
            results.update(nested)
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            nested = find_json_encryption_keys(item, f"{prefix}[{index}]")
            results.update(nested)
    return dict(list(results.items())[:8])


def sanitize_text(value: str) -> str:
    compact = " ".join(value.strip().split())
    return compact[:120]


def sanitize_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "", value)[:120]


def read_c_string(data: bytes, start: int, max_len: int) -> str:
    chunk = data[start : start + max_len]
    end = chunk.find(b"\x00")
    if end != -1:
        chunk = chunk[:end]
    return chunk.decode("ascii", errors="ignore").strip()


def detect_safehouse_virtual_disk(data: bytes) -> Detection | None:
    warning = b"WARNING: This file is a SafeHouse virtual disk volume."
    if not data.startswith(warning):
        return None

    header_version = None
    marker = b"header version: "
    marker_index = data.find(marker)
    if marker_index != -1:
        version_window = data[marker_index + len(marker) : marker_index + len(marker) + 32]
        match = re.search(rb"\d+\.\d+", version_window)
        if match is not None:
            header_version = match.group(0).decode("ascii")

    product_name = read_c_string(data, 0x60, 32) if len(data) > 0x60 else ""
    app_version = read_c_string(data, 0x70, 16) if len(data) > 0x70 else ""
    if not app_version:
        app_version = read_c_string(data, 0x74, 12) if len(data) > 0x74 else ""
    volume_name = read_c_string(data, 0x84, 64) if len(data) > 0x84 else ""
    vendor_name = read_c_string(data, 0xCE, 32) if len(data) > 0xCE else ""
    header_identifier = None
    identifier_match = re.search(rb"[A-F0-9]{32,64}", data[:1024])
    if identifier_match is not None:
        header_identifier = identifier_match.group(0).decode("ascii")

    details: dict[str, str] = {}
    version_parts: list[str] = []
    if header_version:
        details["header_version"] = header_version
        version_parts.append(f"SafeHouse header {header_version}")
    if product_name:
        details["product_name"] = product_name
    if app_version:
        details["app_version"] = app_version
    if product_name and app_version:
        version_parts.insert(0, f"{product_name} {app_version}")
    if version_parts:
        details["version_text"] = " / ".join(version_parts)
    if volume_name:
        details["volume_name"] = volume_name
    if vendor_name:
        details["vendor_name"] = vendor_name
    if header_identifier:
        details["header_identifier"] = header_identifier
    add_safehouse_crypto_header_details(data, details)
    details["encryption_algorithm"] = "not exposed by parsed SafeHouse header"

    return Detection(
        label="SafeHouse virtual disk",
        confidence="high",
        rationale="Header contains the SafeHouse virtual disk warning text and product markers.",
        details=details,
    )


def add_safehouse_crypto_header_details(data: bytes, details: dict[str, str]) -> None:
    if len(data) >= 0x12A:
        details["kdf_iterations"] = str(struct.unpack_from("<H", data, 0x128)[0])
        details["kdf_iterations_offset"] = "0x128"

    salt_offset = 0x130
    salt_length = 128
    salt_end = salt_offset + salt_length - 1
    if len(data) > salt_end:
        salt = data[salt_offset : salt_offset + salt_length]
        details["kdf_salt"] = salt.hex()
        details["kdf_salt_length"] = str(salt_length)
        details["kdf_salt_offset"] = f"0x{salt_offset:x}"
        details["kdf_salt_end"] = f"0x{salt_end:x}"

    cipher_chunk_offset = 0x1B0
    cipher_chunk_length = 16
    if len(data) >= cipher_chunk_offset + cipher_chunk_length:
        chunk = data[cipher_chunk_offset : cipher_chunk_offset + cipher_chunk_length]
        details["cipher_chunk_offset"] = f"0x{cipher_chunk_offset:x}"
        details["cipher_chunk"] = chunk.hex()

    verifier_offset = 0x1C0
    verifier_length = 16
    if len(data) >= verifier_offset + verifier_length:
        verifier = data[verifier_offset : verifier_offset + verifier_length]
        details["encrypted_password_verifier_offset"] = f"0x{verifier_offset:x}"
        details["encrypted_password_verifier"] = verifier.hex()


def detect_bitlocker(data: bytes) -> Detection | None:
    signature_offset = data.find(BITLOCKER_SIGNATURE, 0, min(len(data), 512))
    if signature_offset == -1:
        return None

    details = {"signature_offset": str(signature_offset)}
    if len(data) >= 13:
        bytes_per_sector = struct.unpack_from("<H", data, 11)[0]
        if bytes_per_sector:
            details["bytes_per_sector"] = str(bytes_per_sector)
    details["encryption_algorithm"] = "not exposed by the BitLocker boot-sector signature"

    return Detection(
        label="BitLocker volume",
        confidence="high",
        rationale="The file contains the BitLocker volume signature '-FVE-FS-' in the boot-sector header area.",
        details=details,
    )


def detect_ansible_vault(data: bytes) -> Detection | None:
    if not data.startswith(b"$ANSIBLE_VAULT;"):
        return None

    first_line = data.splitlines()[0].decode("utf-8", errors="ignore").strip()
    parts = first_line.split(";")
    if len(parts) < 3 or parts[0] != "$ANSIBLE_VAULT":
        return None

    details = {
        "format_version": parts[1],
        "encryption_algorithm": parts[2],
    }
    if len(parts) >= 4:
        details["vault_id_label"] = parts[3]

    return Detection(
        label="Ansible Vault file",
        confidence="high",
        rationale="The file begins with the standard Ansible Vault header, which explicitly includes the format version and cipher name.",
        details=details,
    )


def detect_keepass_kdb(data: bytes) -> Detection | None:
    if len(data) < 124:
        return None

    sig1, sig2 = struct.unpack_from("<II", data, 0)
    if sig1 != KDB_SIGNATURE_1 or sig2 != KDB_SIGNATURE_2:
        return None

    flags = struct.unpack_from("<I", data, 8)[0]
    version = struct.unpack_from("<I", data, 12)[0]
    groups = struct.unpack_from("<I", data, 16)[0]
    entries = struct.unpack_from("<I", data, 20)[0]
    key_transf_rounds = struct.unpack_from("<I", data, 120)[0]

    algorithms = [
        name for bit, name in KDB_FLAG_ALGORITHMS.items() if flags & bit
    ]
    details: dict[str, str] = {
        "flags": f"0x{flags:08X}",
        "version": f"0x{version:08X}",
        "group_count": str(groups),
        "entry_count": str(entries),
        "key_transformation_rounds": str(key_transf_rounds),
    }
    if algorithms:
        details["encryption_algorithm"] = ", ".join(algorithms)
    else:
        details["encryption_algorithm"] = "not recovered from visible KDB flags"

    return Detection(
        label="KeePass KDB database",
        confidence="high",
        rationale="The first two 32-bit signatures match the KeePass 1.x KDB format, and the header flags can indicate the configured cipher family.",
        details=details,
    )


def detect_keepass_kdbx(data: bytes) -> Detection | None:
    if len(data) < 12:
        return None

    sig1, sig2 = struct.unpack_from("<II", data, 0)
    if sig1 != KDBX_SIGNATURE_1 or sig2 != KDBX_SIGNATURE_2:
        return None

    version = struct.unpack_from("<I", data, 8)[0]
    major = version >> 16
    minor = version & 0xFFFF
    details: dict[str, str] = {
        "format_version": f"{major}.{minor}",
    }

    header_fields = parse_kdbx_header_fields(data, major)
    cipher_uuid = header_fields.get(2)
    if cipher_uuid is not None:
        details["cipher_uuid"] = cipher_uuid.hex().upper()
        algorithm = KDBX_CIPHER_UUIDS.get(cipher_uuid)
        if algorithm:
            details["encryption_algorithm"] = algorithm
        else:
            details["encryption_algorithm"] = f"unknown-cipher-uuid({cipher_uuid.hex().upper()})"

    kdf_params = header_fields.get(11)
    if kdf_params is not None:
        parsed_kdf = parse_kdbx_variant_dictionary(kdf_params)
        kdf_uuid = parsed_kdf.get("$UUID")
        if isinstance(kdf_uuid, bytes):
            details["kdf_uuid"] = kdf_uuid.hex().upper()
            kdf_name = KDBX_KDF_UUIDS.get(kdf_uuid)
            if kdf_name:
                details["kdf"] = kdf_name
        if "R" in parsed_kdf:
            details["kdf_rounds"] = str(parsed_kdf["R"])
        if "I" in parsed_kdf:
            details["kdf_iterations"] = str(parsed_kdf["I"])
        if "M" in parsed_kdf:
            details["kdf_memory_bytes"] = str(parsed_kdf["M"])
        if "P" in parsed_kdf:
            details["kdf_parallelism"] = str(parsed_kdf["P"])

    rationale = "Header signatures identify a KeePass KDBX database and the visible header fields expose cipher and KDF metadata."
    confidence = "high"
    return Detection(
        label="KeePass KDBX database",
        confidence=confidence,
        rationale=rationale,
        details=details,
    )


def parse_kdbx_header_fields(data: bytes, major: int) -> dict[int, bytes]:
    fields: dict[int, bytes] = {}
    offset = 12
    size_format = "<I" if major >= 4 else "<H"
    size_len = 4 if major >= 4 else 2

    while offset + 1 + size_len <= len(data):
        field_id = data[offset]
        offset += 1
        field_size = struct.unpack_from(size_format, data, offset)[0]
        offset += size_len
        end = offset + field_size
        if end > len(data):
            break
        value = data[offset:end]
        fields[field_id] = value
        offset = end
        if field_id == 0:
            break
    return fields


def parse_kdbx_variant_dictionary(data: bytes) -> dict[str, object]:
    result: dict[str, object] = {}
    if len(data) < 3:
        return result

    reader = BinaryReader(data)
    _version = struct.unpack_from("<H", data, 0)[0]
    reader.offset = 2
    while reader.remaining() > 0:
        value_type = reader.read_byte()
        if value_type == 0:
            break
        name_len = struct.unpack_from("<I", data, reader.offset)[0]
        reader.offset += 4
        name = reader.read_bytes(name_len).decode("utf-8", errors="ignore")
        value_len = struct.unpack_from("<I", data, reader.offset)[0]
        reader.offset += 4
        value_bytes = reader.read_bytes(value_len)
        result[name] = decode_kdbx_variant_value(value_type, value_bytes)
    return result


def decode_kdbx_variant_value(value_type: int, value: bytes) -> object:
    if value_type == 0x04 and len(value) == 4:
        return struct.unpack("<I", value)[0]
    if value_type == 0x05 and len(value) == 8:
        return struct.unpack("<Q", value)[0]
    if value_type == 0x08 and len(value) == 1:
        return bool(value[0])
    if value_type == 0x0C and len(value) == 4:
        return struct.unpack("<i", value)[0]
    if value_type == 0x0D and len(value) == 8:
        return struct.unpack("<q", value)[0]
    if value_type == 0x18:
        return value.decode("utf-8", errors="ignore")
    if value_type == 0x42:
        return value
    return value


def detect_java_keystore(data: bytes) -> Detection | None:
    if len(data) < 12:
        return None

    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in {JKS_MAGIC, JCEKS_MAGIC}:
        return None

    version = struct.unpack_from(">I", data, 4)[0]
    entry_count = struct.unpack_from(">I", data, 8)[0]
    if magic == JKS_MAGIC:
        label = "Java JKS keystore"
        details = {
            "version": str(version),
            "entry_count": str(entry_count),
            "encryption_algorithm": "not exposed by the JKS file header",
        }
        rationale = "Magic bytes identify the proprietary Java KeyStore format."
    else:
        label = "Java JCEKS keystore"
        details = {
            "version": str(version),
            "entry_count": str(entry_count),
            "encryption_algorithm": "legacy JCEKS keystore; entry protection commonly uses TripleDES-based PBE",
        }
        rationale = "Magic bytes identify the Java Cryptography Extension keystore format."

    return Detection(
        label=label,
        confidence="high",
        rationale=rationale,
        details=details,
    )


def detect_bouncycastle_keystore(data: bytes) -> Detection | None:
    if len(data) < 8:
        return None

    version = struct.unpack_from(">I", data, 0)[0]
    if version not in BKS_VERSION_TAGS:
        return None

    entry_count = struct.unpack_from(">I", data, 4)[0]
    if entry_count > 1000000:
        return None

    if looks_like_bks_keystore(data, version):
        return Detection(
            label="Bouncy Castle BKS keystore",
            confidence="medium",
            rationale="The leading fields look like a plausible BKS keystore header with a small integer version and entry count.",
            details={
                "version": str(version),
                "entry_count": str(entry_count),
                "encryption_algorithm": "BKS store format; exact entry protection depends on keystore contents",
            },
        )

    if looks_like_uber_keystore(data):
        return Detection(
            label="Bouncy Castle UBER keystore",
            confidence="medium",
            rationale="The file shape is consistent with a Bouncy Castle UBER keystore, which encrypts the store using password-based protection.",
            details={
                "encryption_algorithm": "password-based store encryption (commonly described as SHA-1 plus Twofish in UBER)",
            },
        )

    return None


def looks_like_bks_keystore(data: bytes, version: int) -> bool:
    if version not in BKS_VERSION_TAGS or len(data) < 12:
        return False

    entry_count = struct.unpack_from(">I", data, 4)[0]
    if entry_count > 1000000:
        return False

    salt_length = struct.unpack_from(">I", data, 8)[0]
    if salt_length <= 0 or salt_length > 4096:
        return False
    if 12 + salt_length + 4 > len(data):
        return False

    iteration_count_offset = 12 + salt_length
    iteration_count = struct.unpack_from(">I", data, iteration_count_offset)[0]
    return 0 < iteration_count < 100000000


def looks_like_uber_keystore(data: bytes) -> bool:
    if len(data) < 16:
        return False
    if data.startswith(b"-----BEGIN "):
        return False
    version = struct.unpack_from(">I", data, 0)[0]
    salt_length = struct.unpack_from(">I", data, 4)[0]
    if version not in BKS_VERSION_TAGS:
        return False
    return 0 < salt_length <= 4096 and 8 + salt_length + 4 <= len(data)


def detect_sqlcipher_like_database(data: bytes) -> Detection | None:
    if data.startswith(b"SQLite format 3\x00"):
        return None
    if len(data) < 4096:
        return None

    first_page = data[:4096]
    entropy = shannon_entropy(first_page)
    chi_square = chi_square_uniform(first_page)
    printable = printable_ratio(first_page)
    if entropy < 7.5 or printable > 0.20:
        return None

    zero_block = first_page[:16]
    if zero_block == b"\x00" * 16:
        return None

    return Detection(
        label="SQLCipher-like encrypted SQLite candidate",
        confidence="low",
        rationale="The file does not begin with the normal SQLite magic header and its first page looks like high-entropy opaque data, which is consistent with SQLCipher-style encrypted databases.",
        details={
            "entropy_first_page": f"{entropy:.3f}",
            "chi_square_first_page": f"{chi_square:.2f}",
            "encryption_algorithm": "not provable from bytes alone; SQLCipher commonly uses AES-256",
        },
    )


def detect_apple_dmg(data: bytes) -> Detection | None:
    if len(data) < DMG_TRAILER_SIZE:
        return None

    trailer_offset = len(data) - DMG_TRAILER_SIZE
    if data[trailer_offset : trailer_offset + 4] != b"koly":
        return None

    details: dict[str, str] = {
        "trailer_signature": "koly",
        "trailer_offset": str(trailer_offset),
        "encryption_algorithm": "not exposed by the UDIF trailer alone",
    }
    if len(data) >= trailer_offset + 8:
        version = struct.unpack_from(">I", data, trailer_offset + 4)[0]
        details["udif_version"] = str(version)

    body_window = data[: min(len(data), 262144)].decode("latin1", errors="ignore").lower()
    if "encr" in body_window:
        details["encryption_hint"] = "file contains encryption-related markers in the visible metadata region"

    return Detection(
        label="Apple DMG disk image",
        confidence="high",
        rationale="The trailing 512-byte UDIF footer contains the 'koly' signature used by Apple DMG images.",
        details=details,
    )


def detect_openssh_private_key(data: bytes) -> Detection | None:
    if not data.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
        return None

    decoded = decode_ascii_armor(data)
    if decoded is None or not decoded.startswith(b"openssh-key-v1\x00"):
        return Detection(
            label="OpenSSH private key",
            confidence="medium",
            rationale="PEM header matches an OpenSSH private key, but the binary key body could not be decoded fully.",
            details={},
        )

    try:
        cipher_name, kdf_name, _kdf_options, public_keys_count = parse_openssh_key_header(decoded)
    except ValueError:
        return Detection(
            label="OpenSSH private key",
            confidence="medium",
            rationale="PEM header matches an OpenSSH private key, but the key header fields could not be parsed fully.",
            details={},
        )

    details = {
        "cipher_name": cipher_name,
        "kdf": kdf_name,
        "public_keys": str(public_keys_count),
    }
    if cipher_name != "none":
        details["encryption_algorithm"] = cipher_name
        confidence = "high"
        rationale = "OpenSSH private-key metadata exposes the cipher and KDF names."
    else:
        confidence = "high"
        rationale = "OpenSSH private-key metadata indicates the key is not encrypted."

    return Detection(
        label="OpenSSH private key",
        confidence=confidence,
        rationale=rationale,
        details=details,
    )


def parse_openssh_key_header(data: bytes) -> tuple[str, str, bytes, int]:
    if not data.startswith(b"openssh-key-v1\x00"):
        raise ValueError("missing OpenSSH key prefix")

    offset = len(b"openssh-key-v1\x00")
    cipher_name, offset = read_ssh_string(data, offset)
    kdf_name, offset = read_ssh_string(data, offset)
    kdf_options, offset = read_ssh_bytes(data, offset)
    public_keys_count = struct.unpack_from(">I", data, offset)[0]
    return cipher_name.decode("utf-8", errors="ignore"), kdf_name.decode("utf-8", errors="ignore"), kdf_options, public_keys_count


def read_ssh_bytes(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        raise ValueError("unexpected end of SSH string length")
    length = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    end = offset + length
    if end > len(data):
        raise ValueError("unexpected end of SSH string body")
    return data[offset:end], end


def read_ssh_string(data: bytes, offset: int) -> tuple[bytes, int]:
    return read_ssh_bytes(data, offset)


def detect_pkcs8_encrypted_private_key(data: bytes) -> Detection | None:
    if not data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):
        return None

    decoded = decode_ascii_armor(data)
    if decoded is None:
        return None

    oids = extract_asn1_oids(decoded)
    algorithms = [PKCS8_ENCRYPTION_SCHEMES[oid] for oid in oids if oid in PKCS8_ENCRYPTION_SCHEMES]
    kdfs = [PKCS5_KDFS[oid] for oid in oids if oid in PKCS5_KDFS]
    details: dict[str, str] = {}
    if algorithms:
        details["encryption_algorithm"] = ", ".join(unique_preserve_order(algorithms))
    if kdfs:
        details["kdf"] = ", ".join(unique_preserve_order(kdfs))

    return Detection(
        label="PKCS#8 encrypted private key",
        confidence="high" if algorithms else "medium",
        rationale="PEM label and ASN.1 metadata identify an encrypted PKCS#8 private key.",
        details=details,
    )


def detect_traditional_pem_private_key(data: bytes) -> Detection | None:
    if not any(data.startswith(prefix) for prefix in TRADITIONAL_PEM_LABELS):
        return None

    text = data.decode("ascii", errors="ignore")
    if "Proc-Type: 4,ENCRYPTED" not in text:
        return Detection(
            label="PEM private key",
            confidence="high",
            rationale="PEM label identifies a private key, but the traditional PEM headers do not indicate that it is encrypted.",
            details={},
        )

    match = re.search(r"^DEK-Info:\s*([^,]+),\s*([0-9A-Fa-f]+)", text, re.MULTILINE)
    details: dict[str, str] = {"pem_encrypted": "true"}
    if match:
        details["encryption_algorithm"] = sanitize_slug(match.group(1))
        details["iv"] = sanitize_slug(match.group(2))

    return Detection(
        label="Traditional PEM encrypted private key",
        confidence="high" if "encryption_algorithm" in details else "medium",
        rationale="Traditional PEM encryption headers expose the DEK-Info cipher name and IV.",
        details=details,
    )


def detect_pkcs12(data: bytes) -> Detection | None:
    source = "DER"
    der = data

    if data.startswith(b"-----BEGIN PKCS12-----"):
        decoded = decode_ascii_armor(data)
        if decoded is None:
            return None
        der = decoded
        source = "PEM"
    elif not data.startswith(b"\x30"):
        return None

    oids = extract_asn1_oids(der)
    pbe_algorithms = [PKCS12_PBE_OIDS[oid] for oid in oids if oid in PKCS12_PBE_OIDS]
    if not pbe_algorithms and not looks_like_pkcs12(der, oids):
        return None

    details = {"encoding": source}
    if pbe_algorithms:
        details["encryption_algorithm"] = ", ".join(unique_preserve_order(pbe_algorithms))

    return Detection(
        label="PKCS#12 / PFX container",
        confidence="high" if pbe_algorithms else "medium",
        rationale="ASN.1 structure looks like a PKCS#12/PFX container and may expose PKCS#12 PBE algorithm OIDs.",
        details=details,
    )


def looks_like_pkcs12(data: bytes, oids: list[str]) -> bool:
    if "1.2.840.113549.1.7.1" not in oids:
        return False
    parsed = parse_asn1_value(data, 0)
    if parsed is None or parsed[0] != 0x30:
        return False
    _, _, value_start, value_end, _ = parsed
    child = parse_asn1_value(data, value_start)
    if child is None or child[0] != 0x02:
        return False
    version = int.from_bytes(data[child[2] : child[3]], "big")
    return version == 3


def detect_pdf_encryption(data: bytes) -> Detection | None:
    if not data.startswith(b"%PDF-"):
        return None

    text = data[: min(len(data), 262144)].decode("latin1", errors="ignore")
    if "/Encrypt" not in text:
        return None

    details: dict[str, str] = {}
    version_match = re.search(r"/V\s+(\d+)", text)
    revision_match = re.search(r"/R\s+(\d+)", text)
    cfm_match = re.search(r"/CFM\s*/([A-Za-z0-9]+)", text)
    length_match = re.search(r"/Length\s+(\d+)", text)
    if version_match:
        details["security_handler_version"] = version_match.group(1)
    if revision_match:
        details["security_handler_revision"] = revision_match.group(1)
    if length_match:
        details["key_length_bits"] = length_match.group(1)

    if cfm_match:
        cfm = cfm_match.group(1)
        details["crypt_filter_method"] = cfm
        algorithm = PDF_FILTER_ALGORITHMS.get(cfm)
        if algorithm:
            details["encryption_algorithm"] = algorithm
    elif version_match:
        version = int(version_match.group(1))
        if version in (1, 2):
            details["encryption_algorithm"] = "RC4"
        elif version == 4:
            details["encryption_algorithm"] = "PDF standard security handler with configurable crypt filters"
        elif version >= 5:
            details["encryption_algorithm"] = "AES-256 or newer PDF standard-security variant"

    return Detection(
        label="Encrypted PDF document",
        confidence="high" if "encryption_algorithm" in details else "medium",
        rationale="The PDF trailer references an Encrypt dictionary, and the security handler fields may expose the cipher family.",
        details=details,
    )


def detect_encrypted_office_document(data: bytes) -> Detection | None:
    if not data.startswith(OLE_CFB_SIGNATURE):
        return None

    if b"E\x00n\x00c\x00r\x00y\x00p\x00t\x00i\x00o\x00n\x00I\x00n\x00f\x00o\x00" not in data:
        return None
    if b"E\x00n\x00c\x00r\x00y\x00p\x00t\x00e\x00d\x00P\x00a\x00c\x00k\x00a\x00g\x00e\x00" not in data:
        return None

    details: dict[str, str] = {}
    profile = detect_office_encryption_profile(data)
    if profile is not None:
        details.update(profile)

    return Detection(
        label="Encrypted Microsoft Office document",
        confidence="high",
        rationale="The OLE compound file contains both EncryptionInfo and EncryptedPackage streams, which is the standard encrypted Office container pattern.",
        details=details,
    )


def detect_office_encryption_profile(data: bytes) -> dict[str, str] | None:
    text = data.decode("latin1", errors="ignore")
    utf16_text = data.decode("utf-16le", errors="ignore")
    details: dict[str, str] = {}

    if "AES" in text:
        aes_match = re.search(r"AES(?:-?)(128|192|256)", text)
        if aes_match:
            details["encryption_algorithm"] = f"AES-{aes_match.group(1)}"
        else:
            details["encryption_algorithm"] = "AES"
    elif "AES" in utf16_text:
        aes_match = re.search(r"AES(?:-?)(128|192|256)", utf16_text)
        if aes_match:
            details["encryption_algorithm"] = f"AES-{aes_match.group(1)}"
        else:
            details["encryption_algorithm"] = "AES"

    if "agile" in text.lower() or "agile" in utf16_text.lower():
        details["office_encryption_profile"] = "Agile"
    elif "standard" in text.lower() or "standard" in utf16_text.lower():
        details["office_encryption_profile"] = "Standard"

    hash_match = re.search(r"SHA(?:1|256|384|512)", text, re.IGNORECASE) or re.search(
        r"SHA(?:1|256|384|512)", utf16_text, re.IGNORECASE
    )
    if hash_match:
        details["kdf_hash"] = hash_match.group(0).upper()

    return details or None


def detect_openssl_salted(data: bytes) -> Detection | None:
    if not data.startswith(b"Salted__"):
        return None

    salt_hex = data[8:16].hex() if len(data) >= 16 else "unavailable"
    return Detection(
        label="OpenSSL salted blob",
        confidence="high",
        rationale="Header starts with the OpenSSL salted-file marker.",
        details={
            "salt": salt_hex,
            "encryption_algorithm": "not encoded in the OpenSSL salted blob header",
        },
    )


def detect_age(data: bytes) -> Detection | None:
    if data.startswith(b"age-encryption.org/v1\n"):
        stanza_types = parse_age_stanza_types(data)
        details = {"payload_encryption": "ChaCha20-Poly1305"}
        if stanza_types:
            details["recipient_stanzas"] = ", ".join(stanza_types)
        return Detection(
            label="age file format",
            confidence="high",
            rationale="Header matches the age file preamble.",
            details=details,
        )

    if data.startswith(b"-----BEGIN AGE ENCRYPTED FILE-----"):
        return Detection(
            label="age armored file",
            confidence="high",
            rationale="Header matches the armored age preamble.",
            details={"payload_encryption": "ChaCha20-Poly1305"},
        )

    return None


def detect_pgp_ascii(data: bytes) -> Detection | None:
    if not data.startswith(b"-----BEGIN PGP MESSAGE-----"):
        return None

    details: dict[str, str] = {}
    decoded = decode_ascii_armor(data)
    metadata = extract_pgp_encryption_metadata(decoded) if decoded is not None else {}
    details.update(metadata)

    return Detection(
        label="ASCII-armored OpenPGP message",
        confidence="high",
        rationale="Header matches the standard OpenPGP armored message preamble.",
        details=details,
    )


def detect_pgp_binary(data: bytes) -> Detection | None:
    packet = parse_openpgp_packet_header(data, 0)
    if packet is None:
        return None

    tag, body_offset, body_length, _next_offset, packet_format = packet
    details = {
        "packet_tag": str(tag),
        "packet_format": packet_format,
    }
    metadata = extract_pgp_encryption_metadata(data)
    if metadata:
        details.update(metadata)
        confidence = "medium"
        rationale = "Leading bytes parse as OpenPGP packets and include symmetric-encryption metadata."
    else:
        confidence = "low"
        rationale = (
            "Leading bytes parse as an OpenPGP packet header, but binary OpenPGP streams do not always expose the symmetric algorithm in plaintext."
        )

    if body_length is not None:
        details["first_packet_length"] = str(body_length)
        details["first_packet_body_offset"] = str(body_offset)

    return Detection(
        label="Probable binary OpenPGP packet stream",
        confidence=confidence,
        rationale=rationale,
        details=details,
    )


def decode_ascii_armor(data: bytes) -> bytes | None:
    lines = data.decode("ascii", errors="ignore").splitlines()
    payload_lines: list[str] = []
    in_body = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("-----BEGIN "):
            in_body = True
            continue
        if stripped.startswith("-----END "):
            break
        if not in_body or not stripped:
            continue
        if ":" in stripped and not payload_lines:
            continue
        if stripped.startswith("="):
            continue
        if re.fullmatch(r"[A-Za-z0-9+/=]+", stripped):
            payload_lines.append(stripped)

    if not payload_lines:
        return None

    try:
        return base64.b64decode("".join(payload_lines), validate=False)
    except binascii.Error:
        return None


def extract_pgp_symmetric_algorithms(data: bytes) -> list[str]:
    algorithms: list[str] = []
    metadata = extract_pgp_encryption_metadata(data)
    algorithm_string = metadata.get("encryption_algorithm")
    if algorithm_string:
        return [part.strip() for part in algorithm_string.split(",")]
    return algorithms


def extract_pgp_encryption_metadata(data: bytes | None) -> dict[str, str]:
    if not data:
        return {}

    algorithms: list[str] = []
    compression_algorithms: list[str] = []
    details: dict[str, str] = {}
    offset = 0

    for _ in range(12):
        packet = parse_openpgp_packet_header(data, offset)
        if packet is None:
            break
        tag, body_offset, body_length, next_offset, _packet_format = packet
        if body_length is None or body_offset + body_length > len(data):
            break
        body = data[body_offset : body_offset + body_length]

        if tag == 3 and len(body) >= 2:
            algorithm_name = PGP_SYMMETRIC_ALGORITHMS.get(body[1])
            if algorithm_name and algorithm_name not in algorithms:
                algorithms.append(algorithm_name)
            s2k_details = parse_openpgp_s2k(body[2:])
            details.update(s2k_details)
        elif tag == 8 and body:
            compression_name = PGP_COMPRESSION_ALGORITHMS.get(body[0])
            if compression_name and compression_name not in compression_algorithms:
                compression_algorithms.append(compression_name)

        offset = next_offset

    if algorithms:
        details["encryption_algorithm"] = ", ".join(algorithms)
    if compression_algorithms:
        details["compression_algorithm"] = ", ".join(compression_algorithms)
    return details


def parse_openpgp_s2k(data: bytes) -> dict[str, str]:
    if len(data) < 2:
        return {}

    s2k_type = data[0]
    hash_algorithm = PGP_HASH_ALGORITHMS.get(data[1], f"unknown-hash({data[1]})")
    details = {
        "s2k_type": {
            0: "simple",
            1: "salted",
            3: "iterated-and-salted",
        }.get(s2k_type, f"unknown({s2k_type})"),
        "s2k_hash": hash_algorithm,
    }

    if s2k_type == 3 and len(data) >= 11:
        coded_count = data[10]
        count = ((16 + (coded_count & 15)) << ((coded_count >> 4) + 6))
        details["s2k_iteration_count"] = str(count)
    return details


def parse_openpgp_packet_header(
    data: bytes, offset: int
) -> tuple[int, int, int | None, int, str] | None:
    if offset >= len(data):
        return None

    first = data[offset]
    if first & 0x80 == 0:
        return None

    if first & 0x40:
        tag = first & 0x3F
        if offset + 1 >= len(data):
            return None
        first_length = data[offset + 1]
        if first_length < 192:
            length = first_length
            header_size = 2
        elif first_length < 224:
            if offset + 2 >= len(data):
                return None
            length = ((first_length - 192) << 8) + data[offset + 2] + 192
            header_size = 3
        elif first_length == 255:
            if offset + 5 >= len(data):
                return None
            length = struct.unpack_from(">I", data, offset + 2)[0]
            header_size = 6
        else:
            return None
        body_offset = offset + header_size
        return tag, body_offset, length, body_offset + length, "new"

    tag = (first >> 2) & 0x0F
    length_type = first & 0x03
    if length_type == 0:
        if offset + 1 >= len(data):
            return None
        length = data[offset + 1]
        header_size = 2
    elif length_type == 1:
        if offset + 2 >= len(data):
            return None
        length = struct.unpack_from(">H", data, offset + 1)[0]
        header_size = 3
    elif length_type == 2:
        if offset + 4 >= len(data):
            return None
        length = struct.unpack_from(">I", data, offset + 1)[0]
        header_size = 5
    else:
        return None
    body_offset = offset + header_size
    return tag, body_offset, length, body_offset + length, "old"


def detect_cms(data: bytes) -> Detection | None:
    source = "DER"
    der = data

    if data.startswith(b"-----BEGIN PKCS7-----") or data.startswith(b"-----BEGIN CMS-----"):
        decoded = decode_ascii_armor(data)
        if decoded is None:
            return None
        der = decoded
        source = "PEM"
    elif not data.startswith(b"\x30"):
        return None

    oids = extract_asn1_oids(der)
    content_type = next((CMS_CONTENT_TYPES[oid] for oid in oids if oid in CMS_CONTENT_TYPES), None)
    algorithms = [CMS_ENCRYPTION_OIDS[oid] for oid in oids if oid in CMS_ENCRYPTION_OIDS]
    if content_type is None:
        return None

    details = {"content_type": content_type, "encoding": source}
    if algorithms:
        details["encryption_algorithm"] = ", ".join(unique_preserve_order(algorithms))
        confidence = "high"
        rationale = "ASN.1/CMS metadata exposes content-encryption algorithm OIDs."
    else:
        confidence = "medium"
        rationale = "CMS content type was detected, but no known content-encryption OID was mapped from the analyzed ASN.1 structure."

    return Detection(
        label="CMS/PKCS#7 encrypted content",
        confidence=confidence,
        rationale=rationale,
        details=details,
    )


def parse_asn1_value(
    data: bytes, offset: int
) -> tuple[int, int, int, int, int] | None:
    if offset + 2 > len(data):
        return None

    tag = data[offset]
    length, length_offset = parse_asn1_length(data, offset + 1)
    value_start = length_offset
    value_end = value_start + length
    if value_end > len(data):
        return None
    return tag, length, value_start, value_end, value_end


def extract_asn1_oids(data: bytes) -> list[str]:
    oids: list[str] = []

    def walk(offset: int, end: int, depth: int) -> int:
        while offset < end and depth < 32:
            if offset + 2 > len(data):
                return end
            tag = data[offset]
            offset += 1
            length, offset = parse_asn1_length(data, offset)
            value_end = offset + length
            if value_end > len(data):
                return end

            if tag == 0x06:
                oids.append(decode_oid(data[offset:value_end]))
            elif tag & 0x20:
                walk(offset, value_end, depth + 1)

            offset = value_end
        return offset

    try:
        walk(0, len(data), 0)
    except ValueError:
        return []
    return oids


def parse_asn1_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("unexpected end of ASN.1 length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or offset + count > len(data):
        raise ValueError("invalid ASN.1 length")
    length = int.from_bytes(data[offset : offset + count], "big")
    return length, offset + count


def decode_oid(value: bytes) -> str:
    if not value:
        return ""

    first = value[0]
    nodes = [str(first // 40), str(first % 40)]
    current = 0

    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            nodes.append(str(current))
            current = 0

    return ".".join(nodes)


def detect_luks1(data: bytes) -> Detection | None:
    if len(data) < 592 or not data.startswith(LUKS1_MAGIC):
        return None

    version = struct.unpack(">H", data[6:8])[0]
    if version != 1:
        return None

    cipher_name = read_c_string(data, 8, 32)
    cipher_mode = read_c_string(data, 40, 32)
    hash_spec = read_c_string(data, 72, 32)
    payload_offset = struct.unpack(">I", data[104:108])[0]
    key_bytes = struct.unpack(">I", data[108:112])[0]
    uuid = read_c_string(data, 168, 40)

    return Detection(
        label="LUKS1 container",
        confidence="high",
        rationale="Header matches the LUKS1 magic and exposes cipher, mode, and hash fields in plaintext.",
        details={
            "version": str(version),
            "cipher_name": cipher_name,
            "cipher_mode": cipher_mode,
            "hash_spec": hash_spec,
            "key_bytes": str(key_bytes),
            "payload_offset_sectors": str(payload_offset),
            "uuid": uuid,
            "encryption_algorithm": f"{cipher_name}-{cipher_mode}",
        },
    )


def detect_luks2(data: bytes) -> Detection | None:
    if len(data) < 4096 or not data.startswith(LUKS2_MAGIC):
        return None

    version = struct.unpack(">H", data[6:8])[0]
    metadata = parse_luks2_json_metadata(data)
    details: dict[str, str] = {"version": str(version)}

    if metadata is not None:
        encryption = extract_first_json_value(metadata, "encryption")
        kdf_type = extract_first_json_value(metadata, "type", parent_key="kdf")
        kdf_hash = extract_first_json_value(metadata, "hash")
        sector_size = extract_first_json_value(metadata, "sector_size")
        if encryption:
            details["encryption_algorithm"] = encryption
        if kdf_type:
            details["kdf"] = kdf_type
        if kdf_hash:
            details["kdf_hash"] = kdf_hash
        if sector_size:
            details["sector_size"] = sector_size
        rationale = "Header matches LUKS2 magic and the embedded JSON metadata exposes encryption settings."
        confidence = "high"
    else:
        details["encryption_algorithm"] = "not recovered from analyzed LUKS2 JSON metadata"
        rationale = "Header matches LUKS2 magic, but the JSON metadata could not be parsed from the analyzed bytes."
        confidence = "medium"

    return Detection(
        label="LUKS2 container",
        confidence=confidence,
        rationale=rationale,
        details=details,
    )


def parse_luks2_json_metadata(data: bytes) -> dict | None:
    search_window = data[: min(len(data), 262144)]
    start = search_window.find(b"{")
    end = search_window.rfind(b"}")
    if start == -1 or end == -1 or end <= start:
        return None

    candidate = search_window[start : end + 1].rstrip(b"\x00").decode("utf-8", errors="ignore")
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError:
        return None

    return payload if isinstance(payload, dict) else None


def extract_first_json_value(payload: object, target_key: str, parent_key: str | None = None) -> str | None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if parent_key is None and key == target_key:
                return sanitize_text(str(value))
            if parent_key is not None and key == parent_key and isinstance(value, dict):
                nested = value.get(target_key)
                if nested is not None:
                    return sanitize_text(str(nested))
            nested = extract_first_json_value(value, target_key, parent_key=parent_key)
            if nested is not None:
                return nested
    elif isinstance(payload, list):
        for item in payload:
            nested = extract_first_json_value(item, target_key, parent_key=parent_key)
            if nested is not None:
                return nested
    return None


def detect_zip_encryption(data: bytes) -> Detection | None:
    if len(data) < 30 or not data.startswith(b"PK\x03\x04"):
        return None

    fields = struct.unpack_from("<HHHHHIIIHH", data, 4)
    (
        _version_needed,
        flags,
        compression_method,
        _mtime,
        _mdate,
        _crc32,
        _csize,
        _usize,
        name_len,
        extra_len,
    ) = fields
    name_start = 30
    extra_start = name_start + name_len
    extra_end = extra_start + extra_len
    extra = data[extra_start:extra_end]

    is_encrypted = bool(flags & 0x0001)
    uses_strong_encryption = bool(flags & 0x0040)
    aes_info = parse_zip_aes_extra(extra)
    has_aes_extra = aes_info is not None

    if not is_encrypted and not has_aes_extra:
        return None

    details = {
        "compression_method": ZIP_COMPRESSION_METHODS.get(compression_method, str(compression_method)),
        "encrypted_flag": str(is_encrypted).lower(),
    }
    if uses_strong_encryption:
        details["strong_encryption_flag"] = "true"

    if has_aes_extra:
        details["aes_extra_field"] = "present"
        details["encryption_algorithm"] = aes_info["algorithm"]
        details["compression_method"] = aes_info["actual_compression_method"]
        details["aes_vendor_version"] = aes_info["vendor_version"]
        label = "ZIP archive with WinZip AES"
        rationale = "ZIP local header is marked encrypted and contains the AES extra field."
        confidence = "high"
    elif uses_strong_encryption:
        details["encryption_algorithm"] = "unknown ZIP strong-encryption variant"
        label = "Encrypted ZIP archive"
        rationale = (
            "ZIP local header indicates encryption, but the exact strong-encryption algorithm is not exposed by the parsed fields."
        )
        confidence = "medium"
    else:
        details["encryption_algorithm"] = "ZipCrypto"
        label = "Encrypted ZIP archive"
        rationale = "ZIP local header sets the classic encryption bit without the AES extra field."
        confidence = "high"

    return Detection(
        label=label,
        confidence=confidence,
        rationale=rationale,
        details=details,
    )


def parse_zip_aes_extra(extra: bytes) -> dict[str, str] | None:
    cursor = 0
    while cursor + 4 <= len(extra):
        header_id, data_size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        data = extra[cursor : cursor + data_size]
        if header_id == 0x9901 and len(data) >= 7:
            vendor_version = struct.unpack_from("<H", data, 0)[0]
            strength = data[4]
            actual_method = struct.unpack_from("<H", data, 5)[0]
            algorithm = {
                1: "AES-128",
                2: "AES-192",
                3: "AES-256",
            }.get(strength, f"AES-unknown-strength({strength})")
            return {
                "algorithm": algorithm,
                "vendor_version": f"AE-{vendor_version}",
                "actual_compression_method": ZIP_COMPRESSION_METHODS.get(actual_method, str(actual_method)),
            }
        cursor += data_size
    return None


def detect_rar(data: bytes) -> Detection | None:
    if data.startswith(RAR5_SIGNATURE):
        details = {"version": "5"}
        encryption = parse_rar5_encryption_header(data)
        if encryption is not None:
            details.update(encryption)
            rationale = "Header matches the RAR5 archive signature and the archive encryption header exposes the encryption settings."
        else:
            details["encryption_algorithm"] = "not exposed by the visible RAR5 headers"
            rationale = "Header matches the RAR5 archive signature."
        return Detection(
            label="RAR archive",
            confidence="high",
            rationale=rationale,
            details=details,
        )
    if data.startswith(RAR4_SIGNATURE):
        return Detection(
            label="RAR archive",
            confidence="high",
            rationale="Header matches the legacy RAR archive signature.",
            details={"version": "4 or earlier", "encryption_algorithm": "not exposed by the leading RAR signature"},
    )
    return None


def parse_rar5_encryption_header(data: bytes) -> dict[str, str] | None:
    offset = len(RAR5_SIGNATURE)
    if offset + 4 >= len(data):
        return None

    offset += 4  # header CRC32
    header_size, size_len = parse_rar_vint(data, offset)
    if header_size is None or size_len is None:
        return None
    offset += size_len
    end = offset + header_size
    if end > len(data):
        return None

    header_type, type_len = parse_rar_vint(data, offset)
    if header_type is None or type_len is None:
        return None
    offset += type_len

    _header_flags, flags_len = parse_rar_vint(data, offset)
    if flags_len is None:
        return None
    offset += flags_len

    if header_type != 4:
        return None

    enc_version, enc_version_len = parse_rar_vint(data, offset)
    if enc_version is None or enc_version_len is None:
        return None
    offset += enc_version_len

    enc_flags, enc_flags_len = parse_rar_vint(data, offset)
    if enc_flags is None or enc_flags_len is None:
        return None
    offset += enc_flags_len

    if offset >= end:
        return None
    kdf_count_log2 = data[offset]
    offset += 1
    if offset + 16 > end:
        return None
    salt = data[offset : offset + 16]
    offset += 16

    details = {
        "encryption_algorithm": "AES-256",
        "kdf": "PBKDF2",
        "rar5_encryption_version": str(enc_version),
        "kdf_iterations_log2": str(kdf_count_log2),
        "salt": salt.hex(),
    }
    if enc_flags & 0x0001 and offset + 12 <= end:
        details["password_check"] = "present"
    return details


def parse_rar_vint(data: bytes, offset: int) -> tuple[int | None, int | None]:
    value = 0
    shift = 0
    consumed = 0

    while offset + consumed < len(data) and consumed < 10:
        byte = data[offset + consumed]
        consumed += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, consumed
        shift += 7

    return None, None


def detect_7z(data: bytes) -> Detection | None:
    if not data.startswith(SEVEN_Z_SIGNATURE):
        return None

    details: dict[str, str] = {}
    method_info = parse_7z_method_summary(data)
    if method_info is not None:
        details["methods"] = ", ".join(method_info["methods"])
        if method_info["encryption_algorithm"] is not None:
            details["encryption_algorithm"] = method_info["encryption_algorithm"]
        if method_info["kdf"] is not None:
            details["kdf"] = method_info["kdf"]
        if method_info["compression_methods"]:
            details["compression_methods"] = ", ".join(method_info["compression_methods"])
        if method_info["header_encrypted"] is not None:
            details["header_encrypted"] = method_info["header_encrypted"]

    if "encryption_algorithm" in details:
        rationale = "Header matches the 7z signature and exposed coder metadata includes an encryption method."
    else:
        rationale = "Header matches the 7z file signature."
        details["note"] = "No encryption coder was visible in the parsed 7z header."

    return Detection(
        label="7z archive",
        confidence="high",
        rationale=rationale,
        details=details,
    )


def detect_unknown_high_entropy(
    data: bytes,
    entropy: float,
    chi_square: float,
    ratio: float,
) -> Detection | None:
    if len(data) < 256 or entropy < 7.5:
        return None

    details = {
        "printable_ratio": f"{ratio:.3f}",
        "entropy_hint": f"{entropy:.2f}",
        "chi_square_hint": f"{chi_square:.2f}",
        "possible_examples": "raw ciphertext, compressed data, VeraCrypt/TrueCrypt-style container",
    }
    return Detection(
        label="Unknown high-entropy blob",
        confidence="medium",
        rationale="The analyzed bytes look opaque and random but do not match any recognized structured header.",
        details=details,
    )


def parse_age_stanza_types(data: bytes) -> list[str]:
    stanza_types: list[str] = []
    for line in data.splitlines():
        if line.startswith(b"-> "):
            stanza = line[3:].decode("ascii", errors="ignore").split(" ", 1)[0].strip()
            if stanza and stanza not in stanza_types:
                stanza_types.append(stanza)
        elif line == b"---":
            break
    return stanza_types


def unique_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def parse_7z_method_summary(data: bytes) -> dict[str, object] | None:
    if len(data) < 32 or not data.startswith(SEVEN_Z_SIGNATURE):
        return None

    next_header_offset = struct.unpack_from("<Q", data, 12)[0]
    next_header_size = struct.unpack_from("<Q", data, 20)[0]
    header_start = 32 + next_header_offset
    header_end = header_start + next_header_size
    if header_end > len(data):
        return None

    header_bytes = data[header_start:header_end]
    reader = BinaryReader(header_bytes)
    first_nid = header_bytes[0] if header_bytes else None
    try:
        methods = parse_7z_next_header(reader)
    except ValueError:
        return None

    if not methods:
        return None

    method_names = [SEVEN_Z_METHOD_NAMES.get(method_id, method_id.hex()) for method_id in methods]
    compression_methods = [name for name in method_names if name not in {"7zAES"}]
    encryption_algorithm = None
    kdf = None
    header_encrypted = None
    if first_nid == 0x01:
        header_encrypted = "no"
    if "7zAES" in method_names:
        encryption_algorithm = "AES-256"
        kdf = "SHA-256 based key derivation"
        if first_nid == 0x17:
            header_encrypted = "yes"

    return {
        "methods": method_names,
        "compression_methods": compression_methods,
        "encryption_algorithm": encryption_algorithm,
        "kdf": kdf,
        "header_encrypted": header_encrypted,
    }


def parse_7z_next_header(reader: BinaryReader) -> list[bytes]:
    first_nid = reader.read_byte()
    if first_nid == 0x01:
        return parse_7z_header(reader)
    if first_nid == 0x17:
        return parse_7z_streams_info(reader)
    return []


def parse_7z_header(reader: BinaryReader) -> list[bytes]:
    methods: list[bytes] = []
    while reader.remaining() > 0:
        nid = reader.read_byte()
        if nid == 0x00:
            break
        if nid == 0x02:
            skip_7z_properties_block(reader)
        elif nid in {0x03, 0x04}:
            methods.extend(parse_7z_streams_info(reader))
        elif nid == 0x05:
            skip_7z_files_info(reader)
        else:
            raise ValueError(f"unsupported 7z header nid: {nid:#x}")
    return methods


def parse_7z_streams_info(reader: BinaryReader) -> list[bytes]:
    methods: list[bytes] = []
    num_folders = 0
    while reader.remaining() > 0:
        nid = reader.read_byte()
        if nid == 0x00:
            break
        if nid == 0x06:
            skip_7z_pack_info(reader)
        elif nid == 0x07:
            unpack_methods, num_folders = parse_7z_unpack_info(reader)
            methods.extend(unpack_methods)
        elif nid == 0x08:
            skip_7z_substreams_info(reader, num_folders)
        else:
            raise ValueError(f"unsupported 7z streams nid: {nid:#x}")
    return methods


def skip_7z_properties_block(reader: BinaryReader) -> None:
    while reader.remaining() > 0:
        nid = reader.read_byte()
        if nid == 0x00:
            return
        size = reader.read_uint64_7z()
        reader.skip(size)


def skip_7z_pack_info(reader: BinaryReader) -> None:
    reader.read_uint64_7z()
    num_pack_streams = reader.read_uint64_7z()
    while True:
        nid = reader.read_byte()
        if nid == 0x00:
            return
        if nid == 0x09:
            for _ in range(num_pack_streams):
                reader.read_uint64_7z()
            continue
        if nid == 0x0A:
            skip_7z_crc_block(reader, num_pack_streams)
            continue
        raise ValueError(f"unsupported 7z pack-info nid: {nid:#x}")


def parse_7z_unpack_info(reader: BinaryReader) -> tuple[list[bytes], int]:
    methods: list[bytes] = []
    nid = reader.read_byte()
    if nid != 0x0B:
        raise ValueError("expected Folder block in 7z unpack info")
    num_folders = reader.read_uint64_7z()
    external = reader.read_byte()
    if external != 0:
        raise ValueError("external 7z folder data is unsupported")
    num_unpack_sizes = 0
    for _ in range(num_folders):
        folder_methods, folder_outputs = parse_7z_folder(reader)
        methods.extend(folder_methods)
        num_unpack_sizes += folder_outputs

    while True:
        nid = reader.read_byte()
        if nid == 0x00:
            return methods, num_folders
        if nid == 0x0C:
            for _ in range(num_unpack_sizes):
                reader.read_uint64_7z()
        elif nid == 0x0A:
            skip_7z_crc_block(reader, num_folders)
        else:
            raise ValueError(f"unsupported 7z unpack-info nid: {nid:#x}")


def parse_7z_folder(reader: BinaryReader) -> tuple[list[bytes], int]:
    methods: list[bytes] = []
    num_coders = reader.read_uint64_7z()
    total_in_streams = 0
    total_out_streams = 0

    for _ in range(num_coders):
        flags = reader.read_byte()
        method_id_size = flags & 0x0F
        is_complex = bool(flags & 0x10)
        has_attributes = bool(flags & 0x20)
        has_alt_methods = bool(flags & 0x80)
        if has_alt_methods:
            raise ValueError("alternative 7z methods are unsupported")

        method_id = reader.read_bytes(method_id_size)
        methods.append(method_id)

        if is_complex:
            num_in_streams = reader.read_uint64_7z()
            num_out_streams = reader.read_uint64_7z()
        else:
            num_in_streams = 1
            num_out_streams = 1

        total_in_streams += num_in_streams
        total_out_streams += num_out_streams

        if has_attributes:
            properties_size = reader.read_uint64_7z()
            reader.skip(properties_size)

    num_bind_pairs = total_out_streams - 1
    for _ in range(num_bind_pairs):
        reader.read_uint64_7z()
        reader.read_uint64_7z()

    num_packed_streams = total_in_streams - num_bind_pairs
    if num_packed_streams > 1:
        for _ in range(num_packed_streams - 1):
            reader.read_uint64_7z()

    return methods, total_out_streams


def skip_7z_substreams_info(reader: BinaryReader, num_folders: int) -> None:
    unpack_stream_counts = [1] * num_folders
    total_unpack_streams = sum(unpack_stream_counts)

    while True:
        nid = reader.read_byte()
        if nid == 0x00:
            return
        if nid == 0x0D:
            unpack_stream_counts = [reader.read_uint64_7z() for _ in range(num_folders)]
            total_unpack_streams = sum(unpack_stream_counts)
            continue
        if nid == 0x09:
            num_sizes = total_unpack_streams - num_folders
            for _ in range(max(num_sizes, 0)):
                reader.read_uint64_7z()
            continue
        if nid == 0x0A:
            skip_7z_crc_block(reader, total_unpack_streams)
            continue
        raise ValueError(f"unsupported 7z substreams nid: {nid:#x}")


def skip_7z_files_info(reader: BinaryReader) -> None:
    _num_files = reader.read_uint64_7z()
    while True:
        nid = reader.read_byte()
        if nid == 0x00:
            return
        size = reader.read_uint64_7z()
        reader.skip(size)


def skip_7z_boolean_vector(reader: BinaryReader, count: int) -> list[bool]:
    all_defined = reader.read_byte()
    if all_defined != 0:
        return [True] * count

    flags: list[bool] = []
    mask = 0
    current = 0
    for _ in range(count):
        if mask == 0:
            current = reader.read_byte()
            mask = 0x80
        flags.append(bool(current & mask))
        mask >>= 1
    return flags


def skip_7z_crc_block(reader: BinaryReader, count: int) -> None:
    defined = skip_7z_boolean_vector(reader, count)
    for is_present in defined:
        if is_present:
            reader.skip(4)
