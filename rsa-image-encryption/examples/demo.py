#!/usr/bin/env python3
"""
Quick demonstration of the RSA Image Encryption System.
Creates a synthetic test image, encrypts it, decrypts it, and verifies lossless recovery.
"""

import sys
from pathlib import Path

import cv2
import numpy as np

# Allow running from the examples/ folder
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rsa_image_crypto import HybridImageCrypto


def create_test_image(path: str = "test_image.png", size=(640, 480)):
    """Generate a colourful test pattern."""
    h, w = size[1], size[0]
    img = np.zeros((h, w, 3), dtype=np.uint8)
    # Gradient + some shapes
    for y in range(h):
        img[y, :, 0] = (y * 255) // h
        img[y, :, 1] = 128
        img[y, :, 2] = 255 - img[y, :, 0]
    cv2.rectangle(img, (50, 50), (200, 150), (0, 255, 0), -1)
    cv2.circle(img, (400, 300), 80, (255, 0, 0), -1)
    cv2.putText(img, "RSA-2048 Demo", (180, 50), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
    cv2.imwrite(path, img)
    print(f"Created test image → {path}")
    return path


def main():
    print("=" * 60)
    print("RSA-Based Image Encryption – Demo")
    print("=" * 60)

    # 1. Create a test image
    img_path = create_test_image()

    # 2. Initialise crypto system and generate keys
    crypto = HybridImageCrypto(key_size=2048)
    crypto.generate_keys()
    crypto.export_public_key("demo_public.json")
    crypto.export_private_key("demo_private.json")

    # 3. Encrypt
    enc_path = "test_image.enc"
    meta_enc = crypto.encrypt_image(img_path, enc_path)
    print(f"Encrypted size : {meta_enc['encrypted_size']} bytes")

    # 4. Decrypt
    recovered_path = "test_image_recovered.png"
    meta_dec = crypto.decrypt_image(enc_path, recovered_path)

    # 5. Verify lossless recovery
    original = cv2.imread(img_path)
    recovered = cv2.imread(recovered_path)
    if original is not None and recovered is not None and np.array_equal(original, recovered):
        print("\n✅ SUCCESS – Lossless decryption verified!")
    else:
        print("\n❌ FAILURE – Images do not match")
        sys.exit(1)

    print("\nDemo completed successfully.")
    print("Generated files:")
    print("  • test_image.png")
    print("  • test_image.enc")
    print("  • test_image_recovered.png")
    print("  • demo_public.json / demo_private.json")


if __name__ == "__main__":
    main()
