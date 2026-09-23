#!/usr/bin/env python3
"""
One-step private setup.

Run:  python configure.py

It copies YOUR original Python script (the one with your API_URL,
AUDIO_API_BASE and USER_TOKEN filled in) into this folder as
`local_config.py`.

`local_config.py` is git-ignored, so it is NEVER uploaded to GitHub and
nobody else — including the person who wrote this code — ever sees it.
Everything runs on your own computer.

After this, just run:  python app.py
"""

import os
import shutil


HERE = os.path.dirname(os.path.abspath(__file__))
DEST = os.path.join(HERE, "local_config.py")


def main():
    print("=" * 60)
    print("  Private setup — your info stays on THIS computer only")
    print("=" * 60)
    print()
    print("Your script will be copied to 'local_config.py'.")
    print("That file is git-ignored and is NEVER uploaded to GitHub.")
    print()

    path = input(
        "Path to your original Python script (with your info filled in): "
    ).strip().strip('"').strip("'")

    if not path:
        print("\nNothing entered. Run 'python configure.py' again when ready.")
        return

    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        print(f"\n[X] File not found: {path}")
        print("    Check the path and try again.")
        return

    try:
        shutil.copyfile(path, DEST)
    except Exception as exc:  # noqa: BLE001
        print(f"\n[X] Could not copy the file: {exc}")
        return

    # Sanity check: does it define the values we need?
    found = {"API_URL": False, "AUDIO_API_BASE": False, "USER_TOKEN": False}
    try:
        with open(DEST, "r", encoding="utf-8") as f:
            text = f.read()
        for key in found:
            found[key] = (key in text)
    except Exception:  # noqa: BLE001
        pass

    print(f"\n[OK] Copied to: {DEST}")
    print("     This file will NOT be uploaded to GitHub.")

    missing = [k for k, ok in found.items() if not ok]
    if missing:
        print("\n[!] Heads up: could not find these names in your script:")
        for k in missing:
            print(f"      - {k}")
        print("    Make sure your script defines them at the top.")

    print("\nNext step:")
    print("    python app.py")
    print("Then open  http://localhost:5000  in your browser.")


if __name__ == "__main__":
    main()
