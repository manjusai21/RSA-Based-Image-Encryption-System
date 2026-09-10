#!/usr/bin/env python3
"""
RSA-Based Image Encryption System – Command Line Interface
==========================================================
Advanced hybrid (RSA-2048 + AES-256-GCM) image encryption tool.
"""

import argparse
import sys
from pathlib import Path

from rsa_image_crypto import HybridImageCrypto, generate_rsa_keypair


def cmd_generate(args):
    crypto = HybridImageCrypto(key_size=args.bits)
    key = crypto.generate_keys()
    crypto.export_public_key(args.public)
    crypto.export_private_key(args.private)
    print("\nKey pair generated successfully.")
    print(f"  Public  → {args.public}")
    print(f"  Private → {args.private}")


def cmd_encrypt(args):
    crypto = HybridImageCrypto()
    if args.public:
        pub = crypto.import_public_key(args.public)
        meta = crypto.encrypt_image(args.input, args.output, public_key=pub)
    else:
        # Generate ephemeral keys if none supplied
        crypto.generate_keys()
        meta = crypto.encrypt_image(args.input, args.output)
        if args.save_keys:
            crypto.export_public_key("ephemeral_public.json")
            crypto.export_private_key("ephemeral_private.json")
            print("Ephemeral keys saved as ephemeral_public.json / ephemeral_private.json")

    print("\nEncryption metadata:")
    for k, v in meta.items():
        print(f"  {k}: {v}")


def cmd_decrypt(args):
    crypto = HybridImageCrypto()
    key = crypto.import_private_key(args.private)
    meta = crypto.decrypt_image(args.input, args.output, private_key=key, use_crt=not args.no_crt)

    print("\nDecryption metadata:")
    for k, v in meta.items():
        print(f"  {k}: {v}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="RSA-2048 Image Encryption System (Hybrid AES-GCM)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a 2048-bit key pair
  python main.py generate --public pub.json --private priv.json

  # Encrypt an image
  python main.py encrypt -i photo.png -o photo.enc -p pub.json

  # Decrypt the image
  python main.py decrypt -i photo.enc -o recovered.png -k priv.json
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # generate
    g = sub.add_parser("generate", help="Generate RSA key pair")
    g.add_argument("--bits", type=int, default=2048, help="Key size in bits (default 2048)")
    g.add_argument("--public", default="public_key.json", help="Public key output file")
    g.add_argument("--private", default="private_key.json", help="Private key output file")
    g.set_defaults(func=cmd_generate)

    # encrypt
    e = sub.add_parser("encrypt", help="Encrypt an image")
    e.add_argument("-i", "--input", required=True, help="Input image path")
    e.add_argument("-o", "--output", required=True, help="Output encrypted file")
    e.add_argument("-p", "--public", help="Public key JSON file")
    e.add_argument("--save-keys", action="store_true", help="Save ephemeral keys if no public key given")
    e.set_defaults(func=cmd_encrypt)

    # decrypt
    d = sub.add_parser("decrypt", help="Decrypt an image")
    d.add_argument("-i", "--input", required=True, help="Encrypted file")
    d.add_argument("-o", "--output", required=True, help="Recovered image path")
    d.add_argument("-k", "--private", required=True, help="Private key JSON file")
    d.add_argument("--no-crt", action="store_true", help="Disable CRT optimisation")
    d.set_defaults(func=cmd_decrypt)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as exc:
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
