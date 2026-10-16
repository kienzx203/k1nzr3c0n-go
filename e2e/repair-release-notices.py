#!/usr/bin/env python3
"""One-time v0.2.1 packaging repair; never rebuild or execute application code."""

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile


IMAGE = "ghcr.io/cskwork/scopeweaver"
TAG = "v0.2.1"
NOTICE = "THIRD_PARTY_NOTICES.txt"
TARGETS = ("linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256_file(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def archive_entries(archive):
    entries = {}
    with zipfile.ZipFile(archive) as source:
        for item in source.infolist():
            require(item.filename not in entries, f"Duplicate ZIP entry: {item.filename}")
            with source.open(item) as stream:
                entries[item.filename] = hashlib.file_digest(stream, "sha256").hexdigest()
    return entries


def repair_archives(source, destination, notice):
    source, destination = Path(source), Path(destination)
    require(not destination.exists(), "Output directory already exists")
    names = {f"scopeweaver-0.2.1-{target}.zip" for target in TARGETS}
    checksums = {}
    for line in (source / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](scopeweaver-0\.2\.1-[a-z0-9-]+\.zip)", line)
        require(match is not None, f"Unexpected checksum line: {line}")
        digest, name = match.groups()
        require(name not in checksums, f"Duplicate checksum: {name}")
        checksums[name] = digest
    require(set(checksums) == names, "Expected exactly the five v0.2.1 archive checksums")
    # Validate the complete input set before preparing any replacement.
    for name, digest in checksums.items():
        require(sha256_file(source / name) == digest, f"Original checksum mismatch: {name}")
    destination.mkdir()
    shutil.copyfile(source / "SHA256SUMS", destination / "SHA256SUMS.original")
    report = {"release_tag": TAG, "notice_sha256": hashlib.sha256(notice).hexdigest(), "archives": {}}
    for name in sorted(names):
        original, replacement = source / name, destination / name
        root = name.removesuffix(".zip")
        notice_name = f"{root}/{NOTICE}"
        before = archive_entries(original)
        require(notice_name not in before, f"Notice already present: {name}")
        require(all(entry.startswith(root + "/") for entry in before), f"Unexpected archive root: {name}")
        executable = f"{root}/scopeweaver" + (".exe" if "windows" in name else "")
        require(executable in before, f"Missing executable: {name}")
        # Append to a byte-for-byte copy: every existing compressed entry is retained.
        shutil.copyfile(original, replacement)
        with zipfile.ZipFile(replacement, "a", compression=zipfile.ZIP_DEFLATED) as archive:
            item = zipfile.ZipInfo(notice_name, (2026, 10, 11, 0, 0, 0))
            item.external_attr = 0o100644 << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(item, notice)
        after = archive_entries(replacement)
        require(set(after) == set(before) | {notice_name}, f"Archive entries changed: {name}")
        require(all(after[entry] == digest for entry, digest in before.items()), f"Original file changed: {name}")
        require(after[notice_name] == report["notice_sha256"], f"Incorrect notice: {name}")
        report["archives"][name] = {
            "original_sha256": checksums[name], "corrected_sha256": sha256_file(replacement),
            "executable": executable, "unchanged_executable_sha256": before[executable],
            "unchanged_entries": before,
        }
    (destination / "SHA256SUMS").write_text("".join(
        f"{record['corrected_sha256']}  {name}\n" for name, record in report["archives"].items()
    ))
    (destination / "archive-verification.json").write_text(json.dumps(report, indent=2) + "\n")


def inspect(reference, field=None):
    # .Manifest on a single-platform image is only a descriptor, without layers.
    options = ["--raw"] if field is None else ["--format", "{{json ." + field + "}}"]
    return json.loads(subprocess.check_output([
        "docker", "buildx", "imagetools", "inspect", reference, *options,
    ], text=True))


def platform_manifests(index):
    platforms = {}
    for manifest in index["manifests"]:
        platform = manifest.get("platform", {})
        if platform.get("os") == "unknown":
            continue  # Existing BuildKit provenance attestations contain no runtime filesystem.
        key = f"{platform.get('os')}/{platform.get('architecture')}"
        require(key not in platforms, f"Duplicate platform: {key}")
        platforms[key] = manifest["digest"]
    require(set(platforms) == {"linux/amd64", "linux/arm64"}, "Expected exactly Linux amd64 and arm64")
    return platforms


def verify_image_config(base_manifest, fixed_manifest, base_config, fixed_config):
    base_layers, fixed_layers = base_manifest["layers"], fixed_manifest["layers"]
    require(len(fixed_layers) == len(base_layers) + 1, "Expected exactly one added notice layer")
    require([layer["digest"] for layer in fixed_layers[:-1]] == [layer["digest"] for layer in base_layers],
            "Existing image layer changed")
    require(base_config.get("config") == fixed_config.get("config"), "Image runtime configuration changed")
    for key in ("os", "architecture", "variant"):
        require(base_config.get(key) == fixed_config.get(key), f"Image {key} changed")
    require(fixed_config["rootfs"]["diff_ids"][:-1] == base_config["rootfs"]["diff_ids"],
            "Existing uncompressed image layer changed")


def verify_notice_layer(data, notice):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as layer:
        files = []
        for member in layer.getmembers():
            if member.isdir() and member.name.rstrip("/") in ("app", "."):
                continue
            require(member.isfile() and member.name == f"app/{NOTICE}", f"Unexpected image layer entry: {member.name}")
            files.append(member)
        require(len(files) == 1, "Expected one notice file in the added layer")
        require(layer.extractfile(files[0]).read() == notice, "Image notice differs from canonical notice")


def verify_images(base_digest, candidate, destination, notice):
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", base_digest) is not None, "Invalid immutable base image digest")
    destination = Path(destination)
    base_ref = f"{IMAGE}@{base_digest}"
    base_index, fixed_index = inspect(base_ref, "Manifest"), inspect(candidate, "Manifest")
    require(base_index["digest"] == base_digest, "Base index digest mismatch")
    base_platforms, fixed_platforms = platform_manifests(base_index), platform_manifests(fixed_index)
    credentials = base64.b64encode(f"{os.environ['GITHUB_ACTOR']}:{os.environ['GH_TOKEN']}".encode()).decode()
    request = urllib.request.Request(
        "https://ghcr.io/token?service=ghcr.io&scope=repository:cskwork/scopeweaver:pull",
        headers={"Authorization": f"Basic {credentials}"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        token = json.load(response)["token"]
    report = {"original_image_digest": base_digest, "corrected_image_digest": fixed_index["digest"], "platforms": {}}
    for platform in base_platforms:
        base_ref = f"{IMAGE}@{base_platforms[platform]}"
        fixed_ref = f"{IMAGE}@{fixed_platforms[platform]}"
        before, after = inspect(base_ref), inspect(fixed_ref)
        before_config, after_config = inspect(base_ref, "Image"), inspect(fixed_ref, "Image")
        verify_image_config(before, after, before_config, after_config)
        added = after["layers"][-1]
        require(added["size"] < 1024 * 1024, "Unexpectedly large notice layer")
        request = urllib.request.Request(f"https://ghcr.io/v2/cskwork/scopeweaver/blobs/{added['digest']}",
                                         headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(1024 * 1024)
        require("sha256:" + hashlib.sha256(data).hexdigest() == added["digest"], "Notice layer digest mismatch")
        verify_notice_layer(data, notice)
        report["platforms"][platform] = {
            "original_manifest": before, "corrected_manifest": after,
            "original_image_config": before_config, "corrected_image_config": after_config,
            "application_unchanged_proof": "All original layer digests retained; sole added layer contains only the license notice.",
        }
    (destination / "image-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    (destination / "corrected-image-digest.txt").write_text(fixed_index["digest"] + "\n")


if __name__ == "__main__":
    mode, first, second, output, notice_path = sys.argv[1:]
    notice_bytes = Path(notice_path).read_bytes()
    require(b"Copyright (c) 2023 shadcn" in notice_bytes, "Canonical shadcn notice missing")
    if mode == "archives":
        require(second == TAG, "This workflow repairs v0.2.1 only")
        repair_archives(first, output, notice_bytes)
    elif mode == "images":
        verify_images(first, second, output, notice_bytes)
    else:
        raise ValueError("Unknown repair mode")
