"""
Hybrid Image Encryption
-----------------------
RSA-2048 is used only to protect a randomly generated AES-256 session key.
The actual image pixels are encrypted with AES-256-GCM (authenticated encryption).

This design is:
- Cryptographically sound (RSA alone is far too slow for megabyte-sized images)
- Still “RSA-based” as required by the project description
- Provides integrity protection via GCM authentication tag
"""

from __future__ import annotations

import json
import os
import struct
import time
from pathlib import Path
from typing import Tuple, Optional

import numpy as np

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .rsa_core import RSAKeyPair, generate_rsa_keypair, rsa_encrypt, rsa_decrypt, rsa_decrypt_crt
from .image_handler import ImageEncryptor


class HybridImageCrypto:
    """
    High-level API for encrypting / decrypting images with RSA + AES-GCM.
    """

    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.rsa_key: Optional[RSAKeyPair] = None
        self.image_handler = ImageEncryptor()

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------
    def generate_keys(self) -> RSAKeyPair:
        """Generate a fresh RSA-2048 (or custom size) key pair."""
        print(f"[Hybrid] Generating RSA-{self.key_size} key pair …")
        self.rsa_key = generate_rsa_keypair(bits=self.key_size)
        return self.rsa_key

    def load_keys(self, key: RSAKeyPair) -> None:
        self.rsa_key = key

    def export_public_key(self, path: str) -> None:
        if self.rsa_key is None:
            raise RuntimeError("No key pair loaded")
        data = {
            "n": str(self.rsa_key.n),
            "e": self.rsa_key.e,
            "bit_length": self.rsa_key.bit_length,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[Hybrid] Public key exported → {path}")

    def export_private_key(self, path: str) -> None:
        if self.rsa_key is None:
            raise RuntimeError("No key pair loaded")
        data = {
            "n": str(self.rsa_key.n),
            "e": self.rsa_key.e,
            "d": str(self.rsa_key.d),
            "p": str(self.rsa_key.p),
            "q": str(self.rsa_key.q),
            "bit_length": self.rsa_key.bit_length,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[Hybrid] Private key exported → {path}")

    def import_public_key(self, path: str) -> Tuple[int, int]:
        with open(path) as f:
            data = json.load(f)
        return int(data["n"]), data["e"]

    def import_private_key(self, path: str) -> RSAKeyPair:
        with open(path) as f:
            data = json.load(f)
        key = RSAKeyPair(
            n=int(data["n"]),
            e=data["e"],
            d=int(data["d"]),
            p=int(data["p"]),
            q=int(data["q"]),
            bit_length=data["bit_length"],
        )
        self.rsa_key = key
        return key

    # ------------------------------------------------------------------
    # Core encrypt / decrypt
    # ------------------------------------------------------------------
    def encrypt_image(
        self,
        input_path: str,
        output_path: str,
        public_key: Optional[Tuple[int, int]] = None,
    ) -> dict:
        """
        Encrypt an image file.
        Returns a dictionary with performance metrics and metadata.
        """
        if public_key is None:
            if self.rsa_key is None:
                raise RuntimeError("No public key available – call generate_keys() first")
            public_key = self.rsa_key.public_key

        start = time.perf_counter()

        # 1. Load image
        img = self.image_handler.load(input_path)
        raw = self.image_handler.to_bytes(img)
        shape = img.shape
        dtype = str(img.dtype)

        # 2. Generate a random 256-bit AES key + 96-bit nonce
        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)

        # 3. Encrypt pixel data with AES-GCM
        ciphertext = aesgcm.encrypt(nonce, raw, None)   # returns ciphertext || tag

        # 4. Encrypt the AES key with RSA-2048
        encrypted_aes_key = rsa_encrypt(aes_key, public_key)

        # 5. Pack everything into a custom binary container
        # Format:
        #   magic (4) | version (1) | key_len (2) | shape_len (2) | dtype_len (1)
        #   | encrypted_aes_key | nonce (12) | shape_json | dtype | ciphertext
        shape_json = json.dumps(shape).encode()
        dtype_bytes = dtype.encode()

        header = struct.pack(
            ">4sBHHB",
            b"RSAI",          # magic
            1,                # version
            len(encrypted_aes_key),
            len(shape_json),
            len(dtype_bytes),
        )
        container = (
            header
            + encrypted_aes_key
            + nonce
            + shape_json
            + dtype_bytes
            + ciphertext
        )

        with open(output_path, "wb") as f:
            f.write(container)

        elapsed = time.perf_counter() - start
        meta = {
            "input": input_path,
            "output": output_path,
            "original_size": len(raw),
            "encrypted_size": len(container),
            "shape": shape,
            "dtype": dtype,
            "time_seconds": round(elapsed, 4),
            "rsa_key_bits": public_key[0].bit_length(),
        }
        print(f"[Hybrid] Encryption finished in {elapsed:.3f}s → {output_path}")
        return meta

    def decrypt_image(
        self,
        input_path: str,
        output_path: str,
        private_key: Optional[RSAKeyPair] = None,
        use_crt: bool = True,
    ) -> dict:
        """
        Decrypt a previously encrypted image.
        Lossless reconstruction is guaranteed when the correct private key is used.
        """
        if private_key is None:
            if self.rsa_key is None:
                raise RuntimeError("No private key available")
            private_key = self.rsa_key

        start = time.perf_counter()

        with open(input_path, "rb") as f:
            data = f.read()

        # Parse header
        magic, version, key_len, shape_len, dtype_len = struct.unpack(
            ">4sBHHB", data[:10]
        )
        if magic != b"RSAI":
            raise ValueError("Not a valid RSA-Image encrypted file")
        if version != 1:
            raise ValueError(f"Unsupported container version: {version}")

        offset = 10
        encrypted_aes_key = data[offset : offset + key_len]
        offset += key_len
        nonce = data[offset : offset + 12]
        offset += 12
        shape_json = data[offset : offset + shape_len]
        offset += shape_len
        dtype_bytes = data[offset : offset + dtype_len]
        offset += dtype_len
        ciphertext = data[offset:]

        shape = tuple(json.loads(shape_json))
        dtype = np.dtype(dtype_bytes.decode())

        # Decrypt AES key with RSA (CRT-optimised when possible)
        if use_crt and hasattr(private_key, "p"):
            aes_key = rsa_decrypt_crt(encrypted_aes_key, private_key)
        else:
            aes_key = rsa_decrypt(encrypted_aes_key, private_key.private_key)

        # Decrypt pixel data
        aesgcm = AESGCM(aes_key)
        try:
            raw = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise ValueError("Decryption failed – wrong key or tampered data") from exc

        # Reconstruct image
        img = self.image_handler.from_bytes(raw, shape, dtype)
        self.image_handler.save(img, output_path)

        elapsed = time.perf_counter() - start
        meta = {
            "input": input_path,
            "output": output_path,
            "shape": shape,
            "dtype": str(dtype),
            "time_seconds": round(elapsed, 4),
            "lossless": True,
        }
        print(f"[Hybrid] Decryption finished in {elapsed:.3f}s → {output_path}")
        return meta
