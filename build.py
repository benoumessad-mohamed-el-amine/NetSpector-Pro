#!/usr/bin/env python3
"""Build script for packaging NetShark Pro into executable netshark.pyz via stdlib zipapp."""

import os
import shutil
import stat
import sys
import tempfile
import zipapp

SOURCE_DIR = "netshark"
OUTPUT_PYZ = "netshark.pyz"
SHEBANG = "/usr/bin/env python3"


def build():
    print(f"[*] Packaging NetShark Pro 🦈 from '{SOURCE_DIR}' into '{OUTPUT_PYZ}'...")

    if not os.path.exists(SOURCE_DIR):
        print(f"Error: Source directory '{SOURCE_DIR}' not found.")
        sys.exit(1)

    # Remove existing pyz if present
    if os.path.exists(OUTPUT_PYZ):
        os.remove(OUTPUT_PYZ)

    with tempfile.TemporaryDirectory() as temp_dir:
        # Copy netshark package into temp staging directory
        dest_pkg = os.path.join(temp_dir, "netshark")
        shutil.copytree(SOURCE_DIR, dest_pkg)

        # Create root __main__.py inside zipapp staging
        root_main = os.path.join(temp_dir, "__main__.py")
        with open(root_main, "w", encoding="utf-8") as f:
            f.write(
                "import sys\n"
                "from netshark.__main__ import main\n\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            )

        try:
            zipapp.create_archive(
                temp_dir,
                target=OUTPUT_PYZ,
                interpreter=SHEBANG,
            )

            # Make the output executable (chmod +x)
            st = os.stat(OUTPUT_PYZ)
            os.chmod(OUTPUT_PYZ, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            file_size_kb = os.path.getsize(OUTPUT_PYZ) / 1024.0
            print(f"[+] Successfully built standalone executable '{OUTPUT_PYZ}' ({file_size_kb:.1f} KB)")
            print(f"[+] Run directly with: ./{OUTPUT_PYZ} <pcap_file>")

        except Exception as e:
            print(f"Build failed: {e}")
            sys.exit(1)


if __name__ == "__main__":
    build()
