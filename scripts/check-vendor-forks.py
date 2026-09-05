#!/usr/bin/python3
import hashlib
import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json_map(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["package"], data["files"]


def load_sum_map(path):
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        value, name = line.split("  ", 1)
        result[name] = value
    return result


def check(name, package_hash, upstream, allowed):
    directory = ROOT / "vendor" / name
    active_package, active = load_json_map(directory / ".cargo-checksum.json")
    if active_package != package_hash:
        raise RuntimeError(f"{name}: unexpected package checksum")

    changed = set()
    for relative, upstream_hash in upstream.items():
        path = directory / relative
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"{name}: missing regular upstream file {relative}")
        actual = digest(path)
        if actual != upstream_hash:
            changed.add(relative)
        if active.get(relative) != actual:
            raise RuntimeError(f"{name}: stale active checksum for {relative}")

    if changed != allowed:
        raise RuntimeError(
            f"{name}: patch surface differs: expected {sorted(allowed)}, "
            f"found {sorted(changed)}"
        )
    print(f"vendor_fork={name} package={package_hash} changed={','.join(sorted(changed))}")


def main():
    crypto_package, crypto_upstream = load_json_map(
        ROOT / "vendor/crypto-bigint/UPSTREAM_CARGO_CHECKSUM.json"
    )
    check(
        "crypto-bigint",
        crypto_package,
        crypto_upstream,
        {"Cargo.toml", "src/modular/mul.rs", "src/modular/safegcd.rs"},
    )

    check(
        "cpufeatures",
        "8b2a41393f66f16b0823bb79094d54ac5fbd34ab292ddafb9a0456ac9f87d201",
        load_sum_map(ROOT / "vendor/cpufeatures/UPSTREAM_SHA256SUMS"),
        {"src/aarch64.rs", "tests/aarch64.rs"},
    )
    print("vendor_fork_check=PASS forks=2")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print(f"vendor_fork_check=FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
