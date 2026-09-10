"""
Image handling utilities using OpenCV + NumPy.
Supports a wide range of formats and resolutions up to 4K.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple, Optional

import cv2
import numpy as np


SUPPORTED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".tif",
    ".webp", ".ppm", ".pgm", ".pbm", ".sr", ".ras"
}


class ImageEncryptor:
    """
    Handles loading, pixel-array conversion and saving of images
    for the RSA / hybrid encryption pipeline.
    """

    def __init__(self):
        self.last_shape: Optional[Tuple[int, ...]] = None
        self.last_dtype = None
        self.last_path: Optional[str] = None

    def load(self, path: str) -> np.ndarray:
        """
        Load an image as a NumPy array (BGR or grayscale).
        Raises FileNotFoundError or ValueError on unsupported formats.
        """
        path = str(path)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Image not found: {path}")

        ext = Path(path).suffix.lower()
        if ext not in SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Unsupported format '{ext}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
            )

        # IMREAD_UNCHANGED keeps alpha channel if present
        img = cv2.imread(path, cv2.IMREAD_UNCHANGED)
        if img is None:
            raise ValueError(f"OpenCV failed to read the image: {path}")

        self.last_shape = img.shape
        self.last_dtype = img.dtype
        self.last_path = path

        h, w = img.shape[:2]
        print(f"[Image] Loaded {path} → shape={img.shape}, dtype={img.dtype}")
        if h * w > 3840 * 2160:
            print("[Image] Warning: image larger than 4K – performance may degrade")
        return img

    def to_bytes(self, img: np.ndarray) -> bytes:
        """Serialize the entire pixel array into a contiguous bytes object."""
        return img.tobytes()

    def from_bytes(self, data: bytes, shape: Tuple[int, ...], dtype=np.uint8) -> np.ndarray:
        """Reconstruct a NumPy array from raw bytes + original shape/dtype."""
        arr = np.frombuffer(data, dtype=dtype)
        expected = int(np.prod(shape))
        if arr.size != expected:
            raise ValueError(
                f"Byte length mismatch: got {arr.size} elements, expected {expected}"
            )
        return arr.reshape(shape)

    def save(self, img: np.ndarray, path: str) -> None:
        """Save an image using OpenCV. Format is inferred from the extension."""
        path = str(path)
        success = cv2.imwrite(path, img)
        if not success:
            raise IOError(f"Failed to write image to {path}")
        print(f"[Image] Saved → {path}")

    def get_metadata(self) -> dict:
        return {
            "shape": self.last_shape,
            "dtype": str(self.last_dtype),
            "path": self.last_path,
        }
