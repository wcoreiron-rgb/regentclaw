from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


_SECRETS_DIR = Path(__file__).resolve().parents[3] / ".secrets"
_KEY_FILE = _SECRETS_DIR / ".agent_signing_key.pem"
_KEY_ENV = "AGENT_SIGNING_PRIVATE_KEY_PEM"


@dataclass(frozen=True)
class AgentSignerStatus:
    available: bool
    algorithm: str
    key_id: str | None


class AgentSigner:
    def __init__(self) -> None:
        self._private_key = self._load_or_create_private_key()
        self._public_key = self._private_key.public_key()
        self._key_id = self._derive_key_id(self._public_key)

    @staticmethod
    def _derive_key_id(public_key: Ed25519PublicKey) -> str:
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return hashlib.sha256(pub_bytes).hexdigest()[:16]

    def _load_or_create_private_key(self) -> Ed25519PrivateKey:
        env_key = os.getenv(_KEY_ENV, "").strip()
        if env_key:
            try:
                return serialization.load_pem_private_key(env_key.encode("utf-8"), password=None)
            except Exception:
                pass

        if _KEY_FILE.exists():
            try:
                key_bytes = _KEY_FILE.read_bytes()
                return serialization.load_pem_private_key(key_bytes, password=None)
            except Exception:
                pass

        key = Ed25519PrivateKey.generate()
        _SECRETS_DIR.mkdir(parents=True, exist_ok=True)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        _KEY_FILE.write_bytes(pem)
        return key

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> str:
        return "ed25519"

    def status(self) -> AgentSignerStatus:
        return AgentSignerStatus(available=True, algorithm=self.algorithm, key_id=self.key_id)

    def sign(self, message: bytes) -> str:
        signature = self._private_key.sign(message)
        return base64.b64encode(signature).decode("ascii")

    def verify(self, message: bytes, signature_b64: str, key_id: str | None = None) -> bool:
        if key_id and key_id != self.key_id:
            return False
        try:
            signature = base64.b64decode(signature_b64.encode("ascii"))
            self._public_key.verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False


_signer: AgentSigner | None = None


def get_agent_signer() -> AgentSigner:
    global _signer
    if _signer is None:
        _signer = AgentSigner()
    return _signer

