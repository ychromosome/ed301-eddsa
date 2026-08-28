#!/usr/bin/env python3
"""Independent textual/DER/OID boundary checks for the v1 re-review."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
V1_OID = "1.3.6.1.4.1.66282.301.4"
HISTORICAL_OID = "1.3.6.1.4.1.66282.301.1"
X301_OID = "1.3.6.1.4.1.66282.301.2"
DRAFT00_OID = "1.3.6.1.4.1.66282.301.3"


def base128(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative OID arc")
    encoded = [value & 0x7F]
    value >>= 7
    while value:
        encoded.append(0x80 | (value & 0x7F))
        value >>= 7
    return bytes(reversed(encoded))


def oid_content(text: str) -> bytes:
    arcs = [int(part) for part in text.split(".")]
    if len(arcs) < 2 or arcs[0] not in (0, 1, 2):
        raise ValueError("invalid leading OID arcs")
    if arcs[0] < 2 and arcs[1] > 39:
        raise ValueError("invalid second OID arc")
    return base128(40 * arcs[0] + arcs[1]) + b"".join(
        base128(arc) for arc in arcs[2:]
    )


def tlv(tag: int, body: bytes) -> bytes:
    if len(body) >= 128:
        raise ValueError("long-form length not needed by this test")
    return bytes((tag, len(body))) + body


def c_array(path: Path, name: str) -> bytes:
    source = path.read_text(encoding="utf-8")
    match = re.search(
        rf"\b{name}\s*\[[^]]*\]\s*=\s*\{{(?P<body>.*?)\}}\s*;",
        source,
        re.DOTALL,
    )
    if not match:
        raise AssertionError(f"missing C byte array {name} in {path}")
    return bytes(
        int(item, 16)
        for item in re.findall(r"0x([0-9a-fA-F]{2})", match.group("body"))
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    checks = 0
    provider = ROOT / "provider/crates/ed301-eddsa-provider/c/provider_shim.c"
    strict = ROOT / "provider-tests/strict_serialization.h"
    serialization = ROOT / "provider-tests/provider_serialization.c"
    registry = (ROOT / "docs/OID_REGISTRY.md").read_text(encoding="utf-8")
    provider_text = provider.read_text(encoding="utf-8")

    oid_tlv = tlv(0x06, oid_content(V1_OID))
    algorithm_id = tlv(0x30, oid_tlv)
    require(
        oid_tlv.hex() == "060b2b0601040184856a822d04",
        "unexpected independent v1 OID DER",
    )
    checks += 1
    require(
        c_array(provider, "ED301V1_ALGORITHM_ID_DER") == algorithm_id,
        "provider AlgorithmIdentifier does not encode .301.4 exactly",
    )
    checks += 1

    expected_spki = bytes.fromhex("3038300d") + oid_tlv + bytes.fromhex("032700")
    expected_pkcs8 = (
        bytes.fromhex("303c020100300d") + oid_tlv + bytes.fromhex("04280426")
    )
    require(
        c_array(provider, "ED301V1_SPKI_PREFIX") == expected_spki,
        "provider SPKI prefix does not encode .301.4 exactly",
    )
    checks += 1
    require(
        c_array(provider, "ED301V1_PKCS8_PREFIX") == expected_pkcs8,
        "provider PKCS#8 prefix does not encode .301.4 exactly",
    )
    checks += 1
    require(
        c_array(strict, "ED301V1_SPKI_PREFIX") == expected_spki,
        "test SPKI prefix diverges from independent .301.4 encoding",
    )
    checks += 1
    require(
        c_array(strict, "ED301V1_PKCS8_PREFIX") == expected_pkcs8,
        "test PKCS#8 prefix diverges from independent .301.4 encoding",
    )
    checks += 1

    def prefix_for(oid: str, public: bool) -> bytes:
        local_tlv = tlv(0x06, oid_content(oid))
        if public:
            return bytes.fromhex("3038300d") + local_tlv + bytes.fromhex("032700")
        return bytes.fromhex("303c020100300d") + local_tlv + bytes.fromhex("04280426")

    require(
        c_array(serialization, "HISTORICAL_SPKI_PREFIX")
        == prefix_for(HISTORICAL_OID, True),
        "historical rejection fixture is not .301.1",
    )
    checks += 1
    require(
        c_array(serialization, "HISTORICAL_PKCS8_PREFIX")
        == prefix_for(HISTORICAL_OID, False),
        "historical PKCS#8 rejection fixture is not .301.1",
    )
    checks += 1
    require(
        c_array(serialization, "X301_SPKI_PREFIX") == prefix_for(X301_OID, True),
        "X301 rejection fixture is not .301.2",
    )
    checks += 1
    require(
        c_array(serialization, "X301_PKCS8_PREFIX") == prefix_for(X301_OID, False),
        "X301 PKCS#8 rejection fixture is not .301.2",
    )
    checks += 1

    require(f'"{V1_OID}"' in provider_text, "compiled provider text OID is not .301.4")
    checks += 1
    require(
        DRAFT00_OID not in provider_text,
        "frozen draft-00 OID leaked into active provider source",
    )
    checks += 1
    require(
        "0xfe84" in provider_text and "ed301_eddsa_v1_test" in provider_text,
        "TLS private-use codepoint/name boundary is inconsistent",
    )
    checks += 1
    for oid, label in (
        (HISTORICAL_OID, "Historical and retired"),
        (X301_OID, "Existing assignment"),
        (DRAFT00_OID, "Historical and frozen"),
        (V1_OID, "Active experimental assignment"),
    ):
        require(oid in registry and label in registry, f"registry row missing or stale for {oid}")
        checks += 1

    object_lists = [
        Path(item)
        for item in os.environ.get("OPENSSL_OBJECT_LISTS", "").split(":")
        if item
    ]
    for object_list in object_lists:
        text = object_list.read_text(encoding="utf-8", errors="strict")
        require(
            "1.3.6.1.4.1.66282.301." not in text,
            f"OpenSSL object collision in {object_list}",
        )
        require(
            "Ed301" not in text and "X301" not in text,
            f"OpenSSL name collision in {object_list}",
        )
        checks += 2

    print(
        "oid_independent_check=PASS "
        f"oid={V1_OID} der={oid_tlv.hex()} checks={checks} "
        f"openssl_object_lists={len(object_lists)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, ValueError, OSError) as exc:
        print(f"oid_independent_check=FAIL error={exc}", file=sys.stderr)
        raise SystemExit(1)
