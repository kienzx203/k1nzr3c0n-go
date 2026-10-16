import copy
from contextlib import nullcontext
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("repair", Path(__file__).with_name("repair-release-notices.py"))
repair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair)
NOTICE = Path(__file__).resolve().parents[1].joinpath(repair.NOTICE).read_bytes()


class ReleaseNoticeTests(unittest.TestCase):
    def fixture(self, root):
        source = root / "original"
        source.mkdir()
        sums = []
        for target in repair.TARGETS:
            name = f"scopeweaver-0.2.1-{target}"
            with zipfile.ZipFile(source / f"{name}.zip", "w") as archive:
                binary = "scopeweaver.exe" if target.startswith("windows") else "scopeweaver"
                info = zipfile.ZipInfo(f"{name}/{binary}")
                info.external_attr = 0o100755 << 16
                archive.writestr(info, b"original executable\x00\xff" + target.encode())
                archive.writestr(f"{name}/docs/guide.md", b"original documentation")
            sums.append(f"{repair.sha256_file(source / (name + '.zip'))}  {name}.zip\n")
        (source / "SHA256SUMS").write_text("".join(sums))
        return source

    def test_all_archives_preserve_original_entries_permissions_and_binaries(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.fixture(root)
            output = root / "repaired"
            repair.repair_archives(source, output, NOTICE)
            self.assertEqual((source / "SHA256SUMS").read_bytes(), (output / "SHA256SUMS.original").read_bytes())
            for original in source.glob("*.zip"):
                with zipfile.ZipFile(original) as before, zipfile.ZipFile(output / original.name) as after:
                    self.assertEqual(len(after.infolist()), len(before.infolist()) + 1)
                    for member in before.infolist():
                        self.assertEqual(before.read(member), after.read(member.filename))
                        self.assertEqual(member.external_attr, after.getinfo(member.filename).external_attr)
                    self.assertEqual(after.read(f"{original.stem}/{repair.NOTICE}"), NOTICE)

    def test_wrong_original_checksum_fails_before_output_is_created(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.fixture(root)
            archive = next(source.glob("*.zip"))
            archive.write_bytes(archive.read_bytes() + b"changed")
            with self.assertRaisesRegex(ValueError, "Original checksum mismatch"):
                repair.repair_archives(source, root / "repaired", NOTICE)
            self.assertFalse((root / "repaired").exists())

    def test_changed_original_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.fixture(root)
            real_entries = repair.archive_entries

            def corrupt_replacement_hash(archive):
                entries = real_entries(archive)
                if Path(archive).parent.name == "repaired":
                    entries[next(name for name in entries if "scopeweaver" == name.split("/")[-1])] = "0" * 64
                return entries

            with patch.object(repair, "archive_entries", side_effect=corrupt_replacement_hash):
                with self.assertRaisesRegex(ValueError, "Original file changed"):
                    repair.repair_archives(source, root / "repaired", NOTICE)

    def test_image_preserves_layers_and_runtime_configuration(self):
        before = {"layers": [{"digest": "original-layer"}]}
        after = {"layers": [{"digest": "original-layer"}, {"digest": "notice-layer"}]}
        config = {"os": "linux", "architecture": "amd64", "config": {"Cmd": ["unchanged"]}, "rootfs": {"diff_ids": ["original-diff"]}}
        fixed = copy.deepcopy(config)
        fixed["rootfs"]["diff_ids"].append("notice-diff")
        repair.verify_image_config(before, after, config, fixed)
        for changed in ("layer", "configuration", "uncompressed-layer"):
            with self.subTest(changed=changed):
                bad_manifest, bad_config = copy.deepcopy(after), copy.deepcopy(fixed)
                if changed == "layer":
                    bad_manifest["layers"][0]["digest"] = "changed"
                elif changed == "configuration":
                    bad_config["config"]["Cmd"] = ["different"]
                else:
                    bad_config["rootfs"]["diff_ids"][0] = "changed"
                with self.assertRaises(ValueError):
                    repair.verify_image_config(before, bad_manifest, config, bad_config)

    def test_image_verification_reads_raw_child_manifests_instead_of_descriptors(self):
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w:gz") as archive:
            member = tarfile.TarInfo(f"app/{repair.NOTICE}")
            member.size = len(NOTICE)
            archive.addfile(member, io.BytesIO(NOTICE))
        layer_bytes = layer.getvalue()
        layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
        base_digest, fixed_digest = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        candidate = f"{repair.IMAGE}:notice-repair-fixture"
        indexes, children = {}, {}
        for fixed, digest in ((False, base_digest), (True, fixed_digest)):
            index = {"schemaVersion": 2, "digest": digest, "manifests": []}
            for number, arch in enumerate(("amd64", "arm64")):
                child_digest = "sha256:" + str(number + (3 if fixed else 1)) * 64
                descriptor = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": child_digest, "size": 2579}
                index["manifests"].append({**descriptor, "platform": {"os": "linux", "architecture": arch}})
                raw = {"schemaVersion": 2, "mediaType": descriptor["mediaType"],
                       "config": {"digest": "sha256:" + "c" * 64}, "layers": [{"digest": "original-layer", "size": 100}]}
                config = {"os": "linux", "architecture": arch, "config": {"Cmd": ["unchanged"]},
                          "rootfs": {"diff_ids": ["original-diff"]}}
                if fixed:
                    raw["layers"].append({"digest": layer_digest, "size": len(layer_bytes)})
                    config["rootfs"]["diff_ids"].append("notice-diff")
                children[f"{repair.IMAGE}@{child_digest}"] = (descriptor, raw, config)
            indexes[candidate if fixed else f"{repair.IMAGE}@{digest}"] = index

        def docker_response(command, **kwargs):
            reference, options = command[4], command[5:]
            if reference in indexes:
                self.assertEqual(options, ["--format", "{{json .Manifest}}"])
                return json.dumps(indexes[reference])
            descriptor, raw, config = children[reference]
            if options == ["--raw"]:
                return json.dumps(raw)
            if options == ["--format", "{{json .Image}}"]:
                return json.dumps(config)
            # Docker's actual .Manifest child response lacks layers; the old caller fails here.
            self.assertEqual(options, ["--format", "{{json .Manifest}}"])
            return json.dumps(descriptor)

        def registry_response(request, **kwargs):
            body = b'{"token":"fixture-read-only-token"}' if "/token?" in request.full_url else layer_bytes
            return nullcontext(io.BytesIO(body))

        with tempfile.TemporaryDirectory() as temp, \
                patch.object(repair.subprocess, "check_output", side_effect=docker_response) as docker, \
                patch.object(repair.urllib.request, "urlopen", side_effect=registry_response), \
                patch.dict(repair.os.environ, {"GITHUB_ACTOR": "fixture", "GH_TOKEN": "fixture"}):
            repair.verify_images(base_digest, candidate, temp, NOTICE)
            self.assertEqual(sum(call.args[0][-1] == "--raw" for call in docker.call_args_list), 4)
            report = json.loads(Path(temp, "image-verification.json").read_text())
            self.assertEqual(set(report["platforms"]), {"linux/amd64", "linux/arm64"})
            self.assertEqual(report["corrected_image_digest"], fixed_digest)

    def test_notice_layer_rejects_modified_notice_or_application_file(self):
        for name, body, valid in ((f"app/{repair.NOTICE}", NOTICE, True),
                                  (f"app/{repair.NOTICE}", b"modified notice", False),
                                  ("app/scopeweaver", b"changed application", False)):
            with self.subTest(name=name, valid=valid):
                data = io.BytesIO()
                with tarfile.open(fileobj=data, mode="w:gz") as archive:
                    directory = tarfile.TarInfo("app/")
                    directory.type = tarfile.DIRTYPE
                    archive.addfile(directory)
                    member = tarfile.TarInfo(name)
                    member.size = len(body)
                    archive.addfile(member, io.BytesIO(body))
                if valid:
                    repair.verify_notice_layer(data.getvalue(), NOTICE)
                else:
                    with self.assertRaises(ValueError):
                        repair.verify_notice_layer(data.getvalue(), NOTICE)


if __name__ == "__main__":
    unittest.main()
