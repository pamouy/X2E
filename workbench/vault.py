"""Encryption at rest.

A key-encryption key (KEK) is derived from the shared passphrase with scrypt and exists only in memory
after someone has signed in. Every project has its own random data key, stored wrapped by the KEK.
Everything a project holds (name, connector secrets, snapshots, analyses) is encrypted with that data key
using AES-256-GCM, bound to its place in the database by associated data. Deleting a project deletes
the wrapped key, which makes whatever remains of its ciphertext unreadable.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import zlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VERIFIER_PLAINTEXT = b"entra-migration-workbench/vault/v1"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1


class VaultError(Exception):
    pass


def derive_kek(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(passphrase.encode("utf-8"))


def seal(key: bytes, plaintext: bytes, aad: str) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad.encode("utf-8"))


def unseal(key: bytes, blob: bytes, aad: str) -> bytes:
    try:
        return AESGCM(key).decrypt(bytes(blob[:12]), bytes(blob[12:]), aad.encode("utf-8"))
    except InvalidTag as exc:
        raise VaultError("Decryption failed: wrong key, or the stored data was modified") from exc


def seal_json(key: bytes, value, aad: str) -> bytes:
    return seal(key, zlib.compress(json.dumps(value, separators=(",", ":"), default=str).encode("utf-8"), 6), aad)


def unseal_json(key: bytes, blob: bytes, aad: str):
    return json.loads(zlib.decompress(unseal(key, blob, aad)).decode("utf-8"))


def new_verifier(kek: bytes) -> bytes:
    return seal(kek, VERIFIER_PLAINTEXT, "verifier")


def check_verifier(kek: bytes, verifier: bytes) -> bool:
    try:
        return hmac.compare_digest(unseal(kek, verifier, "verifier"), VERIFIER_PLAINTEXT)
    except VaultError:
        return False


def new_project_key() -> bytes:
    return os.urandom(32)


def wrap_key(kek: bytes, project_id: str, key: bytes) -> bytes:
    return seal(kek, key, f"project-key:{project_id}")


def unwrap_key(kek: bytes, project_id: str, wrapped: bytes) -> bytes:
    return unseal(kek, wrapped, f"project-key:{project_id}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
