"""
Tests for backend/app/services/provenance.py

Pure Python — no async, no database, no HTTP client required.
Run with:  pytest backend/tests/test_provenance.py
"""
import base64
import dataclasses
import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    NoEncryption,
    PrivateFormat,
)

from app.services.provenance import (
    ProvenanceResult,
    compute_manifest_hash,
    verify_manifest_signature,
    verify_package,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

SAMPLE_MANIFEST = '{"name": "test-pack", "version": "1.0.0", "skills": []}'
TAMPERED_MANIFEST = '{"name": "evil-pack", "version": "9.9.9", "skills": []}'


def _generate_keypair():
    """Return (private_key_pem: str, public_key_pem: str) for a fresh Ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


def _sign(manifest_json: str, private_key_pem: str) -> str:
    """Sign *manifest_json* with the given PEM private key; return base64 signature."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    private_key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    sig_bytes = private_key.sign(manifest_json.encode("utf-8"))
    return base64.b64encode(sig_bytes).decode("utf-8")


# ─── Hash tests ───────────────────────────────────────────────────────────────

def test_hash_matches():
    """Correct manifest + expected hash → valid=True, hash_verified=True."""
    expected = compute_manifest_hash(SAMPLE_MANIFEST)
    result = verify_package(
        manifest_json=SAMPLE_MANIFEST,
        expected_hash=expected,
        signature_b64=None,
        public_key_pem=None,
    )
    assert result.valid is True
    assert result.hash_verified is True
    assert result.sig_verified is False
    assert result.error is None
    assert result.hash == expected


def test_hash_mismatch_blocked():
    """Tampered manifest content with the original expected hash → valid=False."""
    expected = compute_manifest_hash(SAMPLE_MANIFEST)
    result = verify_package(
        manifest_json=TAMPERED_MANIFEST,
        expected_hash=expected,
        signature_b64=None,
        public_key_pem=None,
    )
    assert result.valid is False
    assert result.hash_verified is False
    assert result.error is not None
    assert "mismatch" in result.error.lower()


# ─── Unsigned community package ───────────────────────────────────────────────

def test_unsigned_package_allowed():
    """No hash and no signature → valid=True, both verified flags False (community package)."""
    result = verify_package(
        manifest_json=SAMPLE_MANIFEST,
        expected_hash=None,
        signature_b64=None,
        public_key_pem=None,
    )
    assert result.valid is True
    assert result.hash_verified is False
    assert result.sig_verified is False
    assert result.error is None


# ─── Ed25519 signature tests ──────────────────────────────────────────────────

def test_valid_ed25519_signature():
    """Generate real Ed25519 keypair, sign manifest, verify passes."""
    priv_pem, pub_pem = _generate_keypair()
    sig_b64 = _sign(SAMPLE_MANIFEST, priv_pem)

    result = verify_package(
        manifest_json=SAMPLE_MANIFEST,
        expected_hash=None,
        signature_b64=sig_b64,
        public_key_pem=pub_pem,
    )
    assert result.valid is True
    assert result.sig_verified is True
    assert result.hash_verified is False
    assert result.error is None


def test_invalid_ed25519_signature_blocked():
    """Signature from a different key → valid=False."""
    priv_pem_a, _ = _generate_keypair()
    _, pub_pem_b = _generate_keypair()          # wrong public key

    sig_b64 = _sign(SAMPLE_MANIFEST, priv_pem_a)

    result = verify_package(
        manifest_json=SAMPLE_MANIFEST,
        expected_hash=None,
        signature_b64=sig_b64,
        public_key_pem=pub_pem_b,
    )
    assert result.valid is False
    assert result.sig_verified is False
    assert result.error is not None


def test_tampered_manifest_invalid_sig():
    """Correct keypair but manifest content was tampered → valid=False."""
    priv_pem, pub_pem = _generate_keypair()
    sig_b64 = _sign(SAMPLE_MANIFEST, priv_pem)  # signed original

    result = verify_package(
        manifest_json=TAMPERED_MANIFEST,          # tampered content
        expected_hash=None,
        signature_b64=sig_b64,
        public_key_pem=pub_pem,
    )
    assert result.valid is False
    assert result.sig_verified is False
    assert result.error is not None


# ─── ProvenanceResult field coverage ─────────────────────────────────────────

def test_provenance_result_fields():
    """ProvenanceResult must expose all required fields with correct types."""
    r = ProvenanceResult(
        valid=True,
        hash_verified=True,
        sig_verified=False,
        hash="abc123",
        error=None,
    )
    assert hasattr(r, "valid")
    assert hasattr(r, "hash_verified")
    assert hasattr(r, "sig_verified")
    assert hasattr(r, "hash")
    assert hasattr(r, "error")

    assert isinstance(r.valid, bool)
    assert isinstance(r.hash_verified, bool)
    assert isinstance(r.sig_verified, bool)
    assert isinstance(r.hash, str)
    assert r.error is None

    # Confirm it is a proper dataclass
    assert dataclasses.is_dataclass(r)

    # Confirm error field can hold a string
    r2 = ProvenanceResult(
        valid=False,
        hash_verified=False,
        sig_verified=False,
        hash="deadbeef",
        error="something went wrong",
    )
    assert isinstance(r2.error, str)


# ─── verify_manifest_signature unit tests ────────────────────────────────────

def test_verify_manifest_signature_directly_valid():
    """verify_manifest_signature returns True for a correctly signed payload."""
    priv_pem, pub_pem = _generate_keypair()
    sig_b64 = _sign(SAMPLE_MANIFEST, priv_pem)
    assert verify_manifest_signature(SAMPLE_MANIFEST, sig_b64, pub_pem) is True


def test_verify_manifest_signature_directly_invalid():
    """verify_manifest_signature returns False for a bad signature."""
    _, pub_pem = _generate_keypair()
    bad_sig = base64.b64encode(b"\x00" * 64).decode("utf-8")
    assert verify_manifest_signature(SAMPLE_MANIFEST, bad_sig, pub_pem) is False


def test_compute_manifest_hash_deterministic():
    """Same input always produces same SHA-256 digest."""
    h1 = compute_manifest_hash(SAMPLE_MANIFEST)
    h2 = compute_manifest_hash(SAMPLE_MANIFEST)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex is 64 characters
