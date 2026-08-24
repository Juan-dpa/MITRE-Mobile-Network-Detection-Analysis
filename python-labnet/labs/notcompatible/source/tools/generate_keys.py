from __future__ import annotations

import argparse
from pathlib import Path

from shared.crypto import generate_global_keys


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the lab RSAGlobal key pair")
    parser.add_argument("--force", action="store_true", help="Replace existing keys")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    key_dir = root / "keys"
    private_path = key_dir / "global_private.pem"
    public_path = key_dir / "global_public.pem"
    modulus_path = key_dir / "global_public_modulus.bin"

    existing = [path for path in (private_path, public_path, modulus_path) if path.exists()]
    if existing and not args.force:
        print("Keys already exist. Use --force to replace them:")
        for path in existing:
            print(f"  {path}")
        return

    generate_global_keys(private_path, public_path, modulus_path)
    print("Generated RSAGlobal laboratory keys:")
    print(f"  Private: {private_path}")
    print(f"  Public:  {public_path}")
    print(f"  Modulus: {modulus_path} (128 raw bytes)")


if __name__ == "__main__":
    main()
