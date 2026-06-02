from __future__ import annotations

import base64
import json
from pathlib import Path
import struct
import tempfile
import unittest

from container_probe.cli import render_text
from container_probe.detectors import inspect_bytes, inspect_file


def der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def der(tag: int, *chunks: bytes) -> bytes:
    payload = b"".join(chunks)
    return bytes([tag]) + der_length(len(payload)) + payload


def oid(oid_string: str) -> bytes:
    nodes = [int(part) for part in oid_string.split(".")]
    first = 40 * nodes[0] + nodes[1]
    encoded = bytearray([first])
    for node in nodes[2:]:
        stack = [node & 0x7F]
        node >>= 7
        while node:
            stack.append(0x80 | (node & 0x7F))
            node >>= 7
        encoded.extend(reversed(stack))
    return der(0x06, bytes(encoded))


def ssh_string(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def kdbx_field(field_id: int, value: bytes) -> bytes:
    return bytes([field_id]) + struct.pack("<I", len(value)) + value


class DetectorTests(unittest.TestCase):
    def test_detects_ansible_vault(self) -> None:
        payload = (
            b"$ANSIBLE_VAULT;1.2;AES256;dev\n"
            b"616263646566\n"
        )
        report = inspect_bytes(payload)
        self.assertEqual(report.detections[0].label, "Ansible Vault file")
        self.assertEqual(report.detections[0].details["encryption_algorithm"], "AES256")
        self.assertEqual(report.detections[0].details["vault_id_label"], "dev")

    def test_detects_keepass_kdb(self) -> None:
        payload = bytearray(124)
        struct.pack_into("<II", payload, 0, 0x9AA2D903, 0xB54BFB65)
        struct.pack_into("<I", payload, 8, 0x00000002)
        struct.pack_into("<I", payload, 12, 0x00030001)
        struct.pack_into("<I", payload, 16, 3)
        struct.pack_into("<I", payload, 20, 7)
        struct.pack_into("<I", payload, 120, 6000)
        report = inspect_bytes(bytes(payload))
        self.assertEqual(report.detections[0].label, "KeePass KDB database")
        self.assertEqual(report.detections[0].details["encryption_algorithm"], "AES")

    def test_detects_openssh_private_key(self) -> None:
        body = (
            b"openssh-key-v1\x00"
            + ssh_string(b"aes256-ctr")
            + ssh_string(b"bcrypt")
            + ssh_string(b"")
            + struct.pack(">I", 1)
        )
        pem = (
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + base64.b64encode(body)
            + b"\n-----END OPENSSH PRIVATE KEY-----\n"
        )
        report = inspect_bytes(pem)
        self.assertEqual(report.detections[0].label, "OpenSSH private key")
        self.assertEqual(report.detections[0].details["encryption_algorithm"], "aes256-ctr")
        self.assertEqual(report.detections[0].details["kdf"], "bcrypt")

    def test_detects_pkcs8_encrypted_private_key(self) -> None:
        payload = der(
            0x30,
            der(
                0x30,
                oid("1.2.840.113549.1.5.13"),
                der(
                    0x30,
                    der(
                        0x30,
                        oid("1.2.840.113549.1.5.12"),
                        der(0x04, b"salt"),
                    ),
                    der(
                        0x30,
                        oid("2.16.840.1.101.3.4.1.42"),
                        der(0x04, b"iviviviviviviviv"),
                    ),
                ),
            ),
            der(0x04, b"\x00\x01\x02"),
        )
        pem = (
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            + base64.b64encode(payload)
            + b"\n-----END ENCRYPTED PRIVATE KEY-----\n"
        )
        report = inspect_bytes(pem)
        self.assertEqual(report.detections[0].label, "PKCS#8 encrypted private key")
        self.assertIn("AES-256-CBC", report.detections[0].details["encryption_algorithm"])
        self.assertIn("PBKDF2", report.detections[0].details["kdf"])

    def test_detects_traditional_pem_private_key(self) -> None:
        pem = (
            b"-----BEGIN RSA PRIVATE KEY-----\n"
            b"Proc-Type: 4,ENCRYPTED\n"
            b"DEK-Info: AES-256-CBC,0123456789ABCDEF\n\n"
            b"ZmFrZQ==\n"
            b"-----END RSA PRIVATE KEY-----\n"
        )
        report = inspect_bytes(pem)
        self.assertEqual(report.detections[0].label, "Traditional PEM encrypted private key")
        self.assertEqual(report.detections[0].details["encryption_algorithm"], "AES-256-CBC")

    def test_detects_keepass_kdbx(self) -> None:
        variant_dict = (
            struct.pack("<H", 0x0100)
            + bytes([0x42])
            + struct.pack("<I", 5)
            + b"$UUID"
            + struct.pack("<I", 16)
            + bytes.fromhex("9E298B1956DB4773B23DFC3EC6F0A1E6")
            + bytes([0x05])
            + struct.pack("<I", 1)
            + b"I"
            + struct.pack("<I", 8)
            + struct.pack("<Q", 4)
            + b"\x00"
        )
        payload = (
            struct.pack("<II", 0x9AA2D903, 0xB54BFB67)
            + struct.pack("<I", 0x00040001)
            + kdbx_field(2, bytes.fromhex("31C1F2E6BF714350BE5805216AFC5AFF"))
            + kdbx_field(11, variant_dict)
            + kdbx_field(0, b"\x0d\x0a\x0d\x0a")
        )
        report = inspect_bytes(payload)
        self.assertEqual(report.detections[0].label, "KeePass KDBX database")
        self.assertEqual(report.detections[0].details["encryption_algorithm"], "AES-256-CBC")
        self.assertEqual(report.detections[0].details["kdf"], "Argon2id")

    def test_detects_java_jks_keystore(self) -> None:
        payload = struct.pack(">III", 0xFEEDFEED, 2, 3) + b"\x00" * 32
        report = inspect_bytes(payload)
        self.assertEqual(report.detections[0].label, "Java JKS keystore")

    def test_detects_java_jceks_keystore(self) -> None:
        payload = struct.pack(">III", 0xCECECECE, 1, 2) + b"\x00" * 32
        report = inspect_bytes(payload)
        self.assertEqual(report.detections[0].label, "Java JCEKS keystore")

    def test_detects_bks_keystore(self) -> None:
        payload = (
            struct.pack(">I", 2)
            + struct.pack(">I", 1)
            + struct.pack(">I", 16)
            + (b"\x01" * 16)
            + struct.pack(">I", 2048)
            + b"\x00" * 32
        )
        report = inspect_bytes(payload)
        self.assertEqual(report.detections[0].label, "Bouncy Castle BKS keystore")

    def test_detects_apple_dmg(self) -> None:
        payload = bytearray(1024)
        payload[-512:-508] = b"koly"
        payload[-508:-504] = struct.pack(">I", 4)
        report = inspect_bytes(bytes(payload))
        self.assertEqual(report.detections[0].label, "Apple DMG disk image")

    def test_detects_openssl_salted(self) -> None:
        report = inspect_bytes(b"Salted__12345678payload")
        self.assertEqual(report.detections[0].label, "OpenSSL salted blob")

    def test_detects_safehouse_virtual_disk(self) -> None:
        payload = bytearray(512)
        payload[0:56] = b"WARNING: This file is a SafeHouse virtual disk volume.\r\n"
        payload[56:77] = b"header version: 2.00"
        payload[0x60:0x69] = b"SafeDisk\x00"
        payload[0x74:0x79] = b"3.00\x00"
        payload[0x84:0x95] = b"My Private Files\x00"
        payload[0xCE:0xD8] = b"SafeHouse\x00"
        struct.pack_into("<H", payload, 0x128, 4138)
        payload[0x130:0x1B0] = bytes(range(128))
        payload[0x1B0:0x1C0] = bytes.fromhex("80000e00b00101f32000140000000000")
        payload[0x1C0:0x1D0] = bytes.fromhex("8c878a0c287dbe9b6ce3d1a57cc03f61")
        payload[0x248:0x268] = b"C835E18F3A779443D67527873ADAF9AB"
        report = inspect_bytes(bytes(payload))
        self.assertEqual(report.detections[0].label, "SafeHouse virtual disk")
        self.assertEqual(report.detections[0].details["product_name"], "SafeDisk")
        self.assertEqual(report.detections[0].details["app_version"], "3.00")
        self.assertEqual(report.detections[0].details["version_text"], "SafeDisk 3.00 / SafeHouse header 2.00")
        self.assertEqual(report.detections[0].details["volume_name"], "My Private Files")
        self.assertEqual(report.detections[0].details["vendor_name"], "SafeHouse")
        self.assertEqual(report.detections[0].details["header_identifier"], "C835E18F3A779443D67527873ADAF9AB")
        self.assertEqual(report.detections[0].details["kdf_iterations"], "4138")
        self.assertEqual(report.detections[0].details["kdf_salt_length"], "128")
        self.assertEqual(report.detections[0].details["kdf_salt_offset"], "0x130")
        self.assertEqual(report.detections[0].details["kdf_salt_end"], "0x1af")
        self.assertEqual(report.detections[0].details["cipher_chunk_offset"], "0x1b0")
        self.assertEqual(report.detections[0].details["cipher_chunk"], "80000e00b00101f32000140000000000")
        self.assertEqual(report.detections[0].details["encrypted_password_verifier_offset"], "0x1c0")
        self.assertEqual(report.detections[0].details["encrypted_password_verifier"], "8c878a0c287dbe9b6ce3d1a57cc03f61")

    def test_detects_bitlocker_signature(self) -> None:
        payload = bytearray(512)
        payload[3:11] = b"-FVE-FS-"
        struct.pack_into("<H", payload, 11, 512)
        report = inspect_bytes(bytes(payload))
        self.assertEqual(report.detections[0].label, "BitLocker volume")

    def test_detects_age_header(self) -> None:
        report = inspect_bytes(b"age-encryption.org/v1\n-> X25519 example\n")
        self.assertEqual(report.detections[0].label, "age file format")
        self.assertEqual(report.detections[0].details["payload_encryption"], "ChaCha20-Poly1305")

    def test_detects_ascii_armored_pgp(self) -> None:
        report = inspect_bytes(b"-----BEGIN PGP MESSAGE-----\nVersion: test\n\nSGVsbG8=\n")
        self.assertEqual(report.detections[0].label, "ASCII-armored OpenPGP message")

    def test_detects_binary_pgp_and_extracts_algorithm(self) -> None:
        payload = bytes([0xC3, 0x0D, 0x04, 0x09, 0x03, 0x08]) + (b"\x00" * 8) + bytes([96])
        report = inspect_bytes(payload)
        self.assertEqual(report.detections[0].label, "Probable binary OpenPGP packet stream")
        self.assertEqual(report.detections[0].details["encryption_algorithm"], "AES-256")
        self.assertEqual(report.detections[0].details["s2k_type"], "iterated-and-salted")
        self.assertEqual(report.detections[0].details["s2k_hash"], "SHA-256")

    def test_detects_cms_and_algorithm_oid(self) -> None:
        cms_der = der(
            0x30,
            oid("1.2.840.113549.1.7.6"),
            der(
                0xA0,
                der(
                    0x30,
                    oid("2.16.840.1.101.3.4.1.46"),
                ),
            ),
        )
        report = inspect_bytes(cms_der)
        self.assertEqual(report.detections[0].label, "CMS/PKCS#7 encrypted content")
        self.assertEqual(report.detections[0].details["encryption_algorithm"], "AES-256-GCM")

    def test_detects_pkcs12_container(self) -> None:
        pfx_der = der(
            0x30,
            der(0x02, b"\x03"),
            der(
                0x30,
                oid("1.2.840.113549.1.7.1"),
                der(
                    0xA0,
                    der(
                        0x30,
                        oid("1.2.840.113549.1.12.1.3"),
                    ),
                ),
            ),
        )
        report = inspect_bytes(pfx_der)
        self.assertEqual(report.detections[0].label, "PKCS#12 / PFX container")
        self.assertIn("TripleDES", report.detections[0].details["encryption_algorithm"])

    def test_detects_luks1_and_extracts_fields(self) -> None:
        payload = bytearray(592)
        payload[0:6] = b"LUKS\xba\xbe"
        payload[6:8] = struct.pack(">H", 1)
        payload[8:40] = b"aes\x00".ljust(32, b"\x00")
        payload[40:72] = b"xts-plain64\x00".ljust(32, b"\x00")
        payload[72:104] = b"sha256\x00".ljust(32, b"\x00")
        payload[104:108] = struct.pack(">I", 4096)
        payload[108:112] = struct.pack(">I", 64)
        payload[168:208] = b"12345678-1234-5678-1234-567812345678\x00".ljust(40, b"\x00")
        report = inspect_bytes(bytes(payload))
        self.assertEqual(report.detections[0].label, "LUKS1 container")
        self.assertEqual(report.detections[0].details["cipher_name"], "aes")
        self.assertEqual(report.detections[0].details["cipher_mode"], "xts-plain64")
        self.assertEqual(report.detections[0].details["hash_spec"], "sha256")

    def test_detects_luks2_and_extracts_json_fields(self) -> None:
        header = bytearray(8192)
        header[0:6] = b"SKUL\xba\xbe"
        header[6:8] = struct.pack(">H", 2)
        metadata = {
            "segments": {
                "0": {
                    "type": "crypt",
                    "encryption": "aes-xts-plain64",
                    "sector_size": 4096,
                }
            },
            "keyslots": {
                "0": {
                    "kdf": {
                        "type": "argon2id",
                        "hash": "sha256",
                    }
                }
            },
        }
        encoded = json.dumps(metadata).encode("utf-8")
        header[4096 : 4096 + len(encoded)] = encoded
        report = inspect_bytes(bytes(header))
        self.assertEqual(report.detections[0].label, "LUKS2 container")
        self.assertEqual(report.detections[0].details["encryption_algorithm"], "aes-xts-plain64")
        self.assertEqual(report.detections[0].details["kdf"], "argon2id")

    def test_detects_encrypted_pdf(self) -> None:
        payload = (
            b"%PDF-1.7\n"
            b"1 0 obj\n<< /Filter /Standard /V 4 /R 4 /Length 128 /CF << /StdCF << /CFM /AESV2 >> >> >>\nendobj\n"
            b"trailer\n<< /Encrypt 1 0 R >>\n%%EOF"
        )
        report = inspect_bytes(payload)
        self.assertEqual(report.detections[0].label, "Encrypted PDF document")
        self.assertEqual(report.detections[0].details["encryption_algorithm"], "AES-128-CBC")

    def test_detects_encrypted_office_document(self) -> None:
        payload = (
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
            + b"\x00" * 64
            + "EncryptionInfo".encode("utf-16le")
            + b"\x00" * 16
            + "EncryptedPackage".encode("utf-16le")
            + b"\x00" * 16
            + b"<encryption cipherAlgorithm=\"AES256\" hashAlgorithm=\"SHA512\" />"
        )
        report = inspect_bytes(payload)
        self.assertEqual(report.detections[0].label, "Encrypted Microsoft Office document")
        self.assertEqual(report.detections[0].details["encryption_algorithm"], "AES-256")
        self.assertEqual(report.detections[0].details["kdf_hash"], "SHA512")

    def test_detects_sqlcipher_like_database(self) -> None:
        payload = bytes(range(256)) * 20
        report = inspect_bytes(payload)
        labels = [item.label for item in report.detections]
        self.assertTrue(
            "SQLCipher-like encrypted SQLite candidate" in labels
            or "Unknown high-entropy blob" in labels
        )

    def test_detects_encrypted_zip(self) -> None:
        filename = b"secret.txt"
        flags = 0x0001
        header = b"PK\x03\x04" + struct.pack(
            "<HHHHHIIIHH",
            20,
            flags,
            8,
            0,
            0,
            0,
            0,
            0,
            len(filename),
            0,
        )
        report = inspect_bytes(header + filename)
        self.assertEqual(report.detections[0].label, "Encrypted ZIP archive")
        self.assertEqual(report.detections[0].details["encryption_algorithm"], "ZipCrypto")

    def test_detects_winzip_aes(self) -> None:
        filename = b"secret.txt"
        extra = struct.pack("<HH", 0x9901, 7) + b"\x02\x00AE\x03\x08\x00"
        header = b"PK\x03\x04" + struct.pack(
            "<HHHHHIIIHH",
            20,
            0x0001,
            99,
            0,
            0,
            0,
            0,
            0,
            len(filename),
            len(extra),
        )
        report = inspect_bytes(header + filename + extra)
        self.assertEqual(report.detections[0].label, "ZIP archive with WinZip AES")
        self.assertEqual(report.detections[0].details["encryption_algorithm"], "AES-256")

    def test_detects_rar5_signature(self) -> None:
        report = inspect_bytes(b"Rar!\x1a\x07\x01\x00" + b"\x00" * 32)
        self.assertEqual(report.detections[0].label, "RAR archive")

    def test_detects_rar5_encryption_header(self) -> None:
        payload = (
            b"Rar!\x1a\x07\x01\x00"
            + b"\x00\x00\x00\x00"
            + b"\x21"
            + b"\x04"
            + b"\x00"
            + b"\x00"
            + b"\x01"
            + b"\x0f"
            + (b"\x11" * 16)
            + (b"\x22" * 12)
        )
        report = inspect_bytes(payload)
        self.assertEqual(report.detections[0].label, "RAR archive")
        self.assertEqual(report.detections[0].details["encryption_algorithm"], "AES-256")
        self.assertEqual(report.detections[0].details["kdf"], "PBKDF2")
        self.assertEqual(report.detections[0].details["password_check"], "present")

    def test_detects_7z_aes_method(self) -> None:
        payload = bytes.fromhex(
            "377abcaf271c0004794434c32000000000000000720000000000000032b352cf"
            "d009822dcc3d1273e4e66407e394a4afabafbd5c8b0e975379935f126af8980e"
            "0104060001092000070b0100022406f1070112530ff741aa7dc1ac65c39b85d0"
            "b52322ada32121010001000c110d00080a016678fd2400000501190100111b00"
            "43006f006e00670072006100740073002e0074007800740000001900140a0100"
            "697e0086c7eedc0115060100200000000000"
        )
        report = inspect_bytes(payload)
        self.assertEqual(report.detections[0].details["encryption_algorithm"], "AES-256")
        self.assertEqual(report.detections[0].details["compression_methods"], "LZMA2")
        self.assertEqual(report.detections[0].details["header_encrypted"], "no")

    def test_uses_entropy_and_block_heuristics(self) -> None:
        payload = bytes(range(256)) * 8
        report = inspect_bytes(payload, full_data=payload)
        labels = [item.label for item in report.heuristics]
        self.assertIn("Statistical profile", labels)
        self.assertIn("16-byte alignment heuristic", labels)
        self.assertEqual(report.detections[0].label, "Unknown high-entropy blob")

    def test_detects_pkcs7_padding_heuristic(self) -> None:
        payload = (b"\x01\x02\x03\x04" * 8) + (b"\x04" * 4)
        report = inspect_bytes(payload, full_data=payload)
        labels = [item.label for item in report.heuristics]
        self.assertIn("PKCS#7 padding candidate (16-byte blocks)", labels)

    def test_scans_sidecar_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir) / "secret.bin"
            base.write_bytes(b"Salted__12345678payload")
            sidecar = Path(temp_dir) / "secret.json"
            sidecar.write_text(json.dumps({"cipher": "AES-256-GCM", "iv": "deadbeef"}))
            report = inspect_file(base)
            self.assertEqual(len(report.sidecar_hints), 1)
            self.assertEqual(report.sidecar_hints[0].details["cipher"], "AES-256-GCM")

    def test_render_text_includes_new_sections(self) -> None:
        report = inspect_bytes(bytes.fromhex("377abcaf271c0004794434c32000000000000000720000000000000032b352cfd009822dcc3d1273e4e66407e394a4afabafbd5c8b0e975379935f126af8980e0104060001092000070b0100022406f1070112530ff741aa7dc1ac65c39b85d0b52322ada32121010001000c110d00080a016678fd2400000501190100111b0043006f006e00670072006100740073002e0074007800740000001900140a0100697e0086c7eedc0115060100200000000000"))
        text = render_text(report.to_dict())
        self.assertIn("Encryption Details", text)
        self.assertIn("Algorithm: AES-256", text)
        self.assertIn("Compression: LZMA2", text)
        self.assertIn("Header Encrypted: No", text)
        self.assertIn("Password Recovery: Supported by Hashcat and John the Ripper", text)
        self.assertIn("Algorithm Summary", text)
        self.assertIn("Format Matches", text)
        self.assertIn("Heuristics", text)
        self.assertNotIn("Analysis Guidance", text)

    def test_render_text_includes_analysis_guidance_when_useful(self) -> None:
        payload = bytearray(512)
        payload[0:56] = b"WARNING: This file is a SafeHouse virtual disk volume.\r\n"
        payload[56:77] = b"header version: 2.00"
        payload[0x60:0x69] = b"SafeDisk\x00"
        payload[0x70:0x75] = b"3.00\x00"
        payload[0x84:0x95] = b"My Private Files\x00"
        payload[0xCE:0xD8] = b"SafeHouse\x00"
        struct.pack_into("<H", payload, 0x128, 4138)
        payload[0x130:0x1B0] = bytes(range(128))
        payload[0x1B0:0x1C0] = bytes.fromhex("80000e00b00101f32000140000000000")
        payload[0x1C0:0x1D0] = bytes.fromhex("8c878a0c287dbe9b6ce3d1a57cc03f61")
        payload[0x248:0x268] = b"77C835E18F3A779443D67527873ADAF9"
        report = inspect_bytes(bytes(payload))
        text = render_text(report.to_dict())
        self.assertIn("KDF Iterations: 4138", text)
        self.assertIn("KDF Salt: 128 bytes (0x130-0x1af)", text)
        self.assertIn("Cipher Chunk: 80000e00b00101f32000140000000000 at 0x1b0", text)
        self.assertIn("Encrypted Password Verifier: 8c878a0c287dbe9b6ce3d1a57cc03f61 at 0x1c0", text)
        self.assertIn("Analysis Guidance", text)
        self.assertIn("Container format identified as SafeHouse virtual disk.", text)
        self.assertIn("Encryption algorithm is not exposed in the parsed header metadata.", text)
        self.assertIn("Further SafeHouse-specific reverse engineering may be needed", text)
        self.assertIn("Any password-recovery approach should target the identified container format", text)


if __name__ == "__main__":
    unittest.main()
