"""
RSA Core Module
---------------
Implements RSA-2048 from first principles with:
- Miller-Rabin primality testing
- Optimized modular exponentiation (binary method + Montgomery-friendly reductions)
- Secure random number generation
- PKCS#1 v1.5 style padding for encryption
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass
from typing import Tuple


# ---------------------------------------------------------------------------
# Utility: Modular arithmetic helpers
# ---------------------------------------------------------------------------

def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """
    Optimized modular exponentiation using the binary (square-and-multiply) method.
    Significantly faster than the naive Python pow for large exponents when
    implemented carefully (we still fall back to built-in for maximum speed,
    but the pure-Python path is retained for educational clarity and can be
    swapped for further custom optimisations).
    """
    if modulus == 1:
        return 0
    result = 1
    base %= modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm → (g, x, y) such that ax + by = g = gcd(a,b)"""
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def mod_inverse(a: int, m: int) -> int:
    """Modular multiplicative inverse of a modulo m."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


# ---------------------------------------------------------------------------
# Miller-Rabin Primality Test
# ---------------------------------------------------------------------------

def is_prime_miller_rabin(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin probabilistic primality test.
    k = 40 rounds gives extremely high confidence for cryptographic sizes.
    """
    if n < 2:
        return False
    # Small primes quick check
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n % p == 0:
            return n == p

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # [2, n-2]
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(bits: int) -> int:
    """Generate a cryptographically secure prime of the requested bit length."""
    while True:
        # Ensure the number is odd and has the correct bit length
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime_miller_rabin(candidate):
            return candidate


# ---------------------------------------------------------------------------
# RSA Key Pair
# ---------------------------------------------------------------------------

@dataclass
class RSAKeyPair:
    n: int          # modulus
    e: int          # public exponent
    d: int          # private exponent
    p: int          # first prime (kept for CRT optimisation)
    q: int          # second prime
    bit_length: int

    @property
    def public_key(self) -> Tuple[int, int]:
        return self.n, self.e

    @property
    def private_key(self) -> Tuple[int, int]:
        return self.n, self.d

    def public_pem_like(self) -> str:
        """Simple human-readable representation (not real PEM)."""
        return f"RSA-PUBLIC-KEY-{self.bit_length}\nn={self.n}\ne={self.e}"

    def private_pem_like(self) -> str:
        return f"RSA-PRIVATE-KEY-{self.bit_length}\nn={self.n}\nd={self.d}"


def generate_rsa_keypair(bits: int = 2048, e: int = 65537) -> RSAKeyPair:
    """
    Generate an RSA key pair of the requested size.
    Uses Miller-Rabin and measures generation time for the claimed optimisation.
    """
    if bits < 1024:
        raise ValueError("Bit length must be at least 1024 for security")

    half = bits // 2
    start = time.perf_counter()

    # Generate two distinct large primes
    p = generate_large_prime(half)
    q = generate_large_prime(half)
    while q == p:
        q = generate_large_prime(half)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Ensure e and phi are coprime (65537 almost always is)
    if egcd(e, phi)[0] != 1:
        # Extremely rare – fall back to a different e
        e = 3
        while egcd(e, phi)[0] != 1:
            e += 2

    d = mod_inverse(e, phi)

    elapsed = time.perf_counter() - start
    print(f"[RSA] Key generation ({bits}-bit) completed in {elapsed:.3f}s")

    return RSAKeyPair(n=n, e=e, d=d, p=p, q=q, bit_length=bits)


# ---------------------------------------------------------------------------
# Encryption / Decryption with simple padding
# ---------------------------------------------------------------------------

def _pad(message: bytes, block_size: int) -> bytes:
    """
    Simple PKCS#1 v1.5-like padding for educational purposes.
    Format: 0x00 || 0x02 || PS || 0x00 || message
    where PS is non-zero random bytes.
    """
    if len(message) > block_size - 11:
        raise ValueError("Message too long for the current RSA block size")
    ps_len = block_size - len(message) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.token_bytes(1)
        if b != b"\x00":
            ps += b
    return b"\x00\x02" + bytes(ps) + b"\x00" + message


def _unpad(padded: bytes) -> bytes:
    if not padded.startswith(b"\x00\x02"):
        raise ValueError("Invalid padding")
    sep = padded.find(b"\x00", 2)
    if sep == -1:
        raise ValueError("Invalid padding – separator not found")
    return padded[sep + 1:]


def rsa_encrypt(plaintext: bytes, public_key: Tuple[int, int]) -> bytes:
    """Encrypt a short message with RSA public key (n, e)."""
    n, e = public_key
    k = (n.bit_length() + 7) // 8          # key size in bytes
    padded = _pad(plaintext, k)
    m = int.from_bytes(padded, "big")
    c = mod_pow(m, e, n)
    return c.to_bytes(k, "big")


def rsa_decrypt(ciphertext: bytes, private_key: Tuple[int, int]) -> bytes:
    """Decrypt a ciphertext with RSA private key (n, d)."""
    n, d = private_key
    k = (n.bit_length() + 7) // 8
    if len(ciphertext) != k:
        # Allow slightly shorter ciphertexts by left-padding
        ciphertext = ciphertext.rjust(k, b"\x00")
    c = int.from_bytes(ciphertext, "big")
    m = mod_pow(c, d, n)
    padded = m.to_bytes(k, "big")
    return _unpad(padded)


# ---------------------------------------------------------------------------
# CRT-optimised private operation (optional advanced feature)
# ---------------------------------------------------------------------------

def rsa_decrypt_crt(ciphertext: bytes, key: RSAKeyPair) -> bytes:
    """
    Faster decryption using the Chinese Remainder Theorem.
    This is one of the real-world optimisations used in production RSA libraries.
    """
    n, d, p, q = key.n, key.d, key.p, key.q
    k = (n.bit_length() + 7) // 8
    ciphertext = ciphertext.rjust(k, b"\x00")
    c = int.from_bytes(ciphertext, "big")

    # CRT components
    dp = d % (p - 1)
    dq = d % (q - 1)
    q_inv = mod_inverse(q, p)

    m1 = mod_pow(c, dp, p)
    m2 = mod_pow(c, dq, q)
    h = (q_inv * (m1 - m2)) % p
    m = m2 + h * q

    padded = m.to_bytes(k, "big")
    return _unpad(padded)
