#!/usr/bin/env python3
"""Exercises Debian package creation."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class TestPackageDeb(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.script = Path(__file__).resolve().parent / "package-deb.sh"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_package_deb_amd64(self):
        fake_bin = self.temp_dir / "shoes"
        fake_bin.write_bytes(b"\x7fELFfakebinary")
        fake_bin.chmod(0o755)

        out_dir = self.temp_dir / "artifacts"
        cmd = [
            str(self.script),
            str(fake_bin),
            "amd64",
            "0.3.9",
            str(out_dir),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        self.assertIn("Successfully built", result.stdout)

        deb_file = out_dir / "shoes_0.3.9_amd64.deb"
        self.assertTrue(deb_file.exists())

        # Inspect control info
        info = subprocess.run(
            ["dpkg-deb", "-I", str(deb_file)],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("Package: shoes", info.stdout)
        self.assertIn("Version: 0.3.9", info.stdout)
        self.assertIn("Architecture: amd64", info.stdout)

        # Inspect file list
        contents = subprocess.run(
            ["dpkg-deb", "-c", str(deb_file)],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("./usr/bin/shoes", contents.stdout)
        self.assertIn("./lib/systemd/system/shoes.service", contents.stdout)
        self.assertIn("./usr/share/doc/shoes/copyright", contents.stdout)

    def test_package_deb_target_triple_mapping(self):
        fake_bin = self.temp_dir / "shoes"
        fake_bin.write_bytes(b"\x7fELFfakebinary")
        fake_bin.chmod(0o755)

        out_dir = self.temp_dir / "artifacts"
        cmd = [
            str(self.script),
            str(fake_bin),
            "aarch64-unknown-linux-musl",
            "v0.3.9",
            str(out_dir),
        ]
        subprocess.run(cmd, capture_output=True, text=True, check=True)

        deb_file = out_dir / "shoes_0.3.9_arm64.deb"
        self.assertTrue(deb_file.exists())

        info = subprocess.run(
            ["dpkg-deb", "-I", str(deb_file)],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("Architecture: arm64", info.stdout)
        self.assertIn("Version: 0.3.9", info.stdout)


if __name__ == "__main__":
    unittest.main()
