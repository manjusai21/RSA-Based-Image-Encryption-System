# RSA-Based Image Encryption System

**Advanced hybrid image encryption** using RSA-2048 public-key cryptography combined with AES-256-GCM for high-performance, lossless protection of images.

---

## 📌 Project Highlights

- **RSA-2048** key generation with custom **Miller-Rabin** primality testing
- Optimised modular exponentiation and **CRT-accelerated** private-key operations
- **Hybrid design**: RSA protects a random AES-256 session key; image pixels are encrypted with AES-GCM (authenticated encryption)
- Lossless decryption verified across multiple image formats
- OpenCV + NumPy pipelines supporting images up to **4K resolution**
- Clean CLI and importable Python package

---

## 🏗️ Architecture

```
┌─────────────┐     RSA-2048      ┌──────────────────┐
│  AES Key    │ ────────────────► │ Encrypted AES Key│
└─────────────┘                   └──────────────────┘
       │
       │ AES-256-GCM
       ▼
┌─────────────┐                   ┌──────────────────┐
│ Image Pixels│ ────────────────► │ Ciphertext + Tag │
└─────────────┘                   └──────────────────┘
```

This hybrid approach solves the classic performance problem of pure RSA on large data while still being an RSA-based system.

---

## 📁 Project Structure

```
rsa-image-encryption/
├── rsa_image_crypto/
│   ├── __init__.py
│   ├── rsa_core.py          # Miller-Rabin, keygen, RSA encrypt/decrypt, CRT
│   ├── image_handler.py     # OpenCV / NumPy image I/O
│   └── hybrid_crypto.py     # High-level hybrid encrypt/decrypt API
├── main.py                  # Command-line interface
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

---

## ⚙️ Installation

```bash
git clone https://github.com/<your-username>/rsa-image-encryption.git
cd rsa-image-encryption

python3 -m venv venv
source venv/bin/activate          # macOS / Linux
# venv\Scripts\activate           # Windows

pip install -r requirements.txt
```

---

## 🚀 Usage

### 1. Generate RSA-2048 key pair
```bash
python main.py generate --public public_key.json --private private_key.json
```

### 2. Encrypt an image
```bash
python main.py encrypt -i photo.png -o photo.enc -p public_key.json
```

### 3. Decrypt the image (lossless recovery)
```bash
python main.py decrypt -i photo.enc -o recovered.png -k private_key.json
```

### Python API example
```python
from rsa_image_crypto import HybridImageCrypto

crypto = HybridImageCrypto(key_size=2048)
crypto.generate_keys()

crypto.encrypt_image("input.jpg", "encrypted.enc")
crypto.decrypt_image("encrypted.enc", "recovered.jpg")
```

---

## 🔬 Technical Details

| Feature                    | Implementation                              |
|---------------------------|---------------------------------------------|
| Primality testing         | Miller-Rabin (40 rounds)                    |
| Modular exponentiation    | Binary square-and-multiply                  |
| Private-key optimisation  | Chinese Remainder Theorem (CRT)             |
| Symmetric cipher          | AES-256-GCM (authenticated)                 |
| Image backend             | OpenCV + NumPy                              |
| Supported formats         | PNG, JPEG, BMP, TIFF, WebP, PPM, PGM …      |
| Max tested resolution     | 4K (3840×2160)                              |

---

## 📊 Performance Notes

- Key generation time is reduced by custom prime generation and optimised modular arithmetic compared with naïve approaches.
- Encryption/decryption of a typical 1080p image completes in well under a second on modern hardware.
- CRT decryption provides a measurable speed-up over classic RSA private exponentiation.

---

## 🔒 Security Notes

- RSA-2048 remains secure against classical attacks as of 2026.
- AES-GCM provides both confidentiality and integrity.
- Private keys are stored in plain JSON for simplicity – protect them appropriately in real deployments.
- This project is intended for educational / portfolio use.

---

## 📄 License

MIT License – see [LICENSE](LICENSE).

---

## 🙏 Acknowledgements

Built with Python, OpenCV, NumPy and the `cryptography` library.
EOF