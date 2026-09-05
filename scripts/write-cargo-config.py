#!/usr/bin/python3
import json
import os
import pathlib
import sys
import tomllib


if len(sys.argv) not in (3, 4):
    raise SystemExit(
        "usage: write-cargo-config.py <output> <vendor-directory> "
        "[panic-unwind]"
    )

output = pathlib.Path(sys.argv[1])
vendor = pathlib.Path(sys.argv[2])
vendor_real = vendor.resolve(strict=True)
if not vendor_real.is_dir() or vendor.is_symlink():
    raise SystemExit("vendor source must be a real directory")

prefix = ""
if len(sys.argv) == 4:
    if sys.argv[3] != "panic-unwind":
        raise SystemExit("unknown Cargo configuration profile")
    prefix = '[build]\nrustflags = ["-Cpanic=unwind"]\n\n'

content = (
    prefix
    + '[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
    + "[source.vendored-sources]\ndirectory = "
    + json.dumps(str(vendor_real), ensure_ascii=False)
    + "\n\n[net]\noffline = true\n"
)
parsed = tomllib.loads(content)
if parsed["source"]["vendored-sources"]["directory"] != str(vendor_real):
    raise SystemExit("Cargo vendor path did not survive TOML serialization")

flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(output, flags, 0o600)
try:
    encoded = content.encode("utf-8")
    offset = 0
    while offset != len(encoded):
        offset += os.write(fd, encoded[offset:])
    os.fsync(fd)
finally:
    os.close(fd)
