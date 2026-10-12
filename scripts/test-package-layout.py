"""Verify the shipped module archive layout without compiling native code."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parent.parent

class PackageTests(unittest.TestCase):
    def test_archive_accepts_dotted_release_host_key_and_attests_library(self):
        """Package a dotted release host key and preserve the archive attestation."""
        target = ROOT / "target"; target.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=target) as directory:
            root = Path(directory); (root/"scripts").mkdir(); (root/"bin").mkdir()
            shutil.copy2(ROOT/"scripts/build-module.sh", root/"scripts/build-module.sh")
            for file in ["LICENSE", "README.md", "MODULE.md"]: (root/file).write_text("fixture")
            cargo = root/"bin/cargo"
            cargo.write_text(
                "#!/usr/bin/env python3\nimport json,sys\nfrom pathlib import Path\n"
                "root=Path.cwd()\n"
                "if 'metadata' in sys.argv: print(json.dumps({'target_directory':str(root/'target')}))\n"
                "else:\n"
                " target=sys.argv[sys.argv.index('--target')+1]\n"
                " output=root/'target'/target/'release'; output.mkdir(parents=True,exist_ok=True)\n"
                " (output/'libtinybox.so').write_bytes(b'compiled-fixture')\n"
            )
            cargo.chmod(0o755)
            env = dict(os.environ, PATH=str(root/"bin")+os.pathsep+os.environ["PATH"])
            env.pop("CARGO_TARGET_DIR", None)
            result = subprocess.run(
                ["bash", str(ROOT/"scripts/build-module.sh"),
                 "--crate", "tinybox-module", "--version", "0.1.22",
                 "--target", "x86_64-unknown-linux-gnu", "--host", "ubuntu-24.04-x86_64"],
                cwd=root, env=env, text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            archive = root/"release-assets/tinybox-0.1.22-ubuntu-24.04-x86_64.tar.gz"
            with tarfile.open(archive) as package:
                data = package.extractfile("./libtinybox.so").read()
                manifest = tomllib.loads(package.extractfile("./modules.toml").read().decode())
                self.assertEqual(data, b"compiled-fixture")
                self.assertEqual(manifest, {"libtinybox.so": hashlib.sha256(data).hexdigest()})

    def test_linux_verifier_hands_admitted_archive_to_workspace_owner(self):
        """Run the prebuilt admission verifier as the mounted-workspace owner."""
        target = ROOT / "target"; target.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=target) as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            setpriv = bin_dir / "setpriv"
            setpriv.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SET_PRIV_ARGS\"\n"
                "while [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n"
            )
            setpriv.chmod(0o755)
            uname = bin_dir / "uname"
            uname.write_text("#!/bin/sh\necho Linux\n")
            uname.chmod(0o755)
            verifier = root / "verify-module-fixture"
            verifier.write_text(
                "#!/bin/sh\n"
                "test -f \"$1\" && test -f \"$(dirname \"$1\")/modules.toml\" && "
                "cmp -s \"$1\" \"$EXPECTED_LIBRARY\"\n"
            )
            verifier.chmod(0o755)

            library_data = b"prebuilt-module-fixture"
            archive = root / "tinybox.tar.gz"
            manifest = f'"libtinybox.so" = "{hashlib.sha256(library_data).hexdigest()}"\n'
            with tarfile.open(archive, "w:gz") as package:
                for name, data in [
                    ("./libtinybox.so", library_data),
                    ("./modules.toml", manifest.encode()),
                ]:
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    package.addfile(info, io.BytesIO(data))

            expected_library = root / "expected.so"
            expected_library.write_bytes(library_data)
            observed_args = root / "setpriv-args"
            host_uid = os.getuid() + 1
            host_gid = os.getgid() + 1
            env = dict(
                os.environ,
                HOST_UID=str(host_uid),
                HOST_GID=str(host_gid),
                EXPECTED_LIBRARY=str(expected_library),
                SET_PRIV_ARGS=str(observed_args),
                PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
            )
            result = subprocess.run(
                [
                    str(ROOT / "scripts/verify-module.sh"),
                    "--archive", str(archive),
                    "--uid", env["HOST_UID"],
                    "--gid", env["HOST_GID"],
                    "--verifier-bin", str(verifier),
                ],
                cwd=ROOT, env=env, text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            actual_args = observed_args.read_text().splitlines()
            self.assertEqual(
                actual_args[:5],
                [
                    f"--reuid={host_uid}",
                    f"--regid={host_gid}",
                    "--clear-groups",
                    "--",
                    str(verifier),
                ],
            )
            extracted_library = Path(actual_args[5])
            self.assertEqual(extracted_library.name, "libtinybox.so")
            self.assertEqual(extracted_library.parent.parent, ROOT / "target")

    def test_linux_verifier_rejects_archive_traversal_before_handoff(self):
        """Reject unsafe archive paths before invoking setpriv or the verifier."""
        target = ROOT / "target"; target.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=target) as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            setpriv_args = root / "setpriv-args"
            setpriv = bin_dir / "setpriv"
            setpriv.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SET_PRIV_ARGS\"\n"
            )
            setpriv.chmod(0o755)
            uname = bin_dir / "uname"
            uname.write_text("#!/bin/sh\necho Linux\n")
            uname.chmod(0o755)
            archive = root / "unsafe.tar.gz"
            with tarfile.open(archive, "w:gz") as package:
                data = b"escape"
                info = tarfile.TarInfo("../escape")
                info.size = len(data)
                package.addfile(info, io.BytesIO(data))
            env = dict(
                os.environ,
                HOST_UID=str(os.getuid()),
                HOST_GID=str(os.getgid()),
                SET_PRIV_ARGS=str(setpriv_args),
                PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
            )
            result = subprocess.run(
                [
                    str(ROOT / "scripts/verify-module.sh"),
                    "--archive", str(archive),
                    "--uid", env["HOST_UID"],
                    "--gid", env["HOST_GID"],
                    "--verifier-bin", str(root / "unused-verifier"),
                ],
                cwd=ROOT, env=env, text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("archive member escapes the extraction directory", result.stderr)
            self.assertFalse(setpriv_args.exists(), "unsafe archive reached setpriv")

    def test_archive_attests_host_library_bytes_from_a_symlinked_checkout(self):
        """Package the actual build script and verify the shipped bytes and attestation."""
        target = ROOT / "target"; target.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=target) as directory:
            root = Path(directory); (root/"scripts").mkdir(); (root/"bin").mkdir()
            shutil.copy2(ROOT/"scripts/build-module.sh", root/"scripts/build-module.sh")
            for file in ["LICENSE","README.md","MODULE.md"]: (root/file).write_text("fixture")
            cargo = root/"bin/cargo"
            cargo.write_text("#!/usr/bin/env python3\nimport json,sys\nfrom pathlib import Path\n"
                "root=Path.cwd()\n"
                "if 'metadata' in sys.argv: print(json.dumps({'target_directory':str(root/'target')}))\n"
                "else:\n"
                " target=sys.argv[sys.argv.index('--target')+1]\n"
                " output=root/'target'/target/'release'; output.mkdir(parents=True,exist_ok=True)\n"
                " (output/'libtinybox.so').write_bytes(b'compiled-fixture')\n")
            cargo.chmod(0o755)
            env = dict(os.environ, PATH=str(root/"bin")+os.pathsep+os.environ["PATH"])
            env.pop("CARGO_TARGET_DIR", None)
            alias = root/"checkout-link"; alias.symlink_to(root, target_is_directory=True)
            result = subprocess.run(["bash",str(alias/"scripts/build-module.sh"),
                "--crate","tinybox-module","--version","1.2.3-beta.1",
                "--target","x86_64-unknown-linux-gnu","--host","linux-fixture"],
                cwd=root,env=env,text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            archive=root/"release-assets/tinybox-1.2.3-beta.1-linux-fixture.tar.gz"
            with tarfile.open(archive) as package:
                data=package.extractfile("./libtinybox.so").read()
                manifest=tomllib.loads(package.extractfile("./modules.toml").read().decode())
                self.assertEqual(data,b"compiled-fixture")
                self.assertEqual(manifest,{"libtinybox.so":hashlib.sha256(data).hexdigest()})
                for name in ["./LICENSE","./README.md","./MODULE.md"]:
                    self.assertIsNotNone(package.extractfile(name))

if __name__ == "__main__": unittest.main()
