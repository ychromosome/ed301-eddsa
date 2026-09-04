#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
sh "$ROOT/scripts/check-rust-build-environment.sh"
sh "$ROOT/scripts/require-verified-snapshot.sh"
if [ "$#" -ne 3 ]; then
    echo "usage: $0 <provider-module.so> <toolchain-marker> <evidence-directory>" >&2
    exit 2
fi
MODULE=$1
TOOLCHAIN=$2
EVIDENCE=$3

for tool in awk cp find grep mkdir nm objdump readelf sha256sum sort tee \
        xargs; do
    test -x "/usr/bin/$tool" || {
        echo "missing AArch64 codegen tool: /usr/bin/$tool" >&2
        exit 127
    }
done
test -f "$MODULE" && test ! -L "$MODULE"
test -s "$TOOLCHAIN" && test ! -L "$TOOLCHAIN"
test ! -e "$EVIDENCE" && test ! -L "$EVIDENCE"
/usr/bin/mkdir -m 700 "$EVIDENCE"

/usr/bin/readelf -h "$MODULE" >"$EVIDENCE/elf-header.txt"
/usr/bin/grep -Eq 'Type:[[:space:]]+DYN \(Shared object file\)$' \
    "$EVIDENCE/elf-header.txt"
/usr/bin/grep -Eq 'Machine:[[:space:]]+AArch64$' \
    "$EVIDENCE/elf-header.txt"
/usr/bin/readelf -S "$MODULE" >"$EVIDENCE/elf-sections.txt"
/usr/bin/grep -Eq '[[:space:]]\.symtab[[:space:]]+SYMTAB[[:space:]]' \
    "$EVIDENCE/elf-sections.txt"
/usr/bin/objdump -d -C --no-show-raw-insn --disassemble-zeroes --wide \
    "$MODULE" >"$EVIDENCE/provider.objdump"
/usr/bin/nm -C --defined-only "$MODULE" >"$EVIDENCE/provider.nm"
/usr/bin/objdump --version >"$EVIDENCE/objdump-version.txt"
/usr/bin/cp -- "$TOOLCHAIN" "$EVIDENCE/toolchain.txt"
SUMMARY=$EVIDENCE/summary.txt
: >"$SUMMARY"

extract_symbol() {
    symbol=$1
    output=$2
    count=$(/usr/bin/awk -v symbol="$symbol" '
        function canonical(name) {
            if (substr(name, 1, 1) == "<") {
                sub(/^</, "", name)
                sub(/>::/, "::", name)
            }
            return name
        }
        /^[[:space:]]*[[:xdigit:]]+ <.*>:/ {
            name = $0
            sub(/^[^<]*</, "", name)
            sub(/>:[[:space:]]*$/, "", name)
            if (canonical(name) == symbol)
                count++
        }
        END { print count + 0 }
    ' "$EVIDENCE/provider.objdump")
    test "$count" -eq 1 || {
        echo "expected one AArch64 symbol $symbol, found $count" >&2
        exit 1
    }
    /usr/bin/awk -v symbol="$symbol" '
        function canonical(name) {
            if (substr(name, 1, 1) == "<") {
                sub(/^</, "", name)
                sub(/>::/, "::", name)
            }
            return name
        }
        /^[[:space:]]*[[:xdigit:]]+ <.*>:/ {
            name = $0
            sub(/^[^<]*</, "", name)
            sub(/>:[[:space:]]*$/, "", name)
            active = canonical(name) == symbol
        }
        active { print }
    ' "$EVIDENCE/provider.objdump" >"$output"
    test -s "$output"
}

forbidden_straight_line() {
    /usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ {
            mnemonic = $2
            if (mnemonic ~ /^b\./ || mnemonic == "b" ||
                    mnemonic == "bl" || mnemonic == "blr" ||
                    mnemonic == "br" || mnemonic == "cbz" ||
                    mnemonic == "cbnz" || mnemonic == "tbz" ||
                    mnemonic == "tbnz" || mnemonic == "udiv" ||
                    mnemonic == "sdiv" || mnemonic == "brk" ||
                    mnemonic == "hlt" || mnemonic == "udf") {
                print
                bad = 1
            }
        }
        END { exit bad ? 0 : 1 }
    ' "$1"
}

check_symbol() {
    label=$1
    symbol=$2
    require_borrow=$3
    output=$EVIDENCE/$label.asm

    extract_symbol "$symbol" "$output"
    if forbidden_straight_line "$output"; then
        echo "forbidden AArch64 control flow in $symbol" >&2
        exit 1
    fi
    if /usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ &&
                $0 ~ /\[[^]]*,[[:space:]]*(x|w)[0-9]+/ {
            print
            bad = 1
        }
        END { exit bad ? 0 : 1 }
    ' "$output"; then
        echo "indexed AArch64 memory access in $symbol" >&2
        exit 1
    fi
    selects=$(/usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ &&
                $2 ~ /^(csel|csinc|csinv|csneg|cset|csetm|cinc|cinv|cneg)$/ {
            count++
        }
        END { print count + 0 }
    ' "$output")
    borrows=$(/usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^(sbc|sbcs)$/ { count++ }
        END { print count + 0 }
    ' "$output")
    test "$selects" -gt 0
    if [ "$require_borrow" = yes ]; then
        test "$borrows" -gt 0
    fi
    printf 'PASS aarch64_symbol=%s conditional_select=%s subtract_carry=%s branches=0 calls=0 indexed_memory=0\n' \
        "$symbol" "$selects" "$borrows" | tee -a "$SUMMARY"
}

check_symbol point_double \
    'ed301_eddsa::edwards::EdwardsPoint::double' yes
check_symbol point_add \
    'ed301_eddsa::edwards::EdwardsPoint::add' yes
check_symbol point_add_affine \
    'ed301_eddsa::edwards::EdwardsPoint::add_affine' yes
check_symbol point_is_valid \
    'ed301_eddsa::edwards::EdwardsPoint::is_valid' yes
check_symbol affine_select \
    'ed301_eddsa::edwards::AffineNielsPoint::conditional_select' no

NEGATIVE=$EVIDENCE/negative-control.asm
printf '0: b.ne 0\n' >"$NEGATIVE"
if ! forbidden_straight_line "$NEGATIVE" >/dev/null; then
    echo "AArch64 codegen checker negative control failed" >&2
    exit 1
fi
printf 'PASS aarch64_negative_control=conditional-branch-rejected\n' \
    | tee -a "$SUMMARY"
(cd "$EVIDENCE" && \
    find . -type f ! -name SHA256SUMS -print0 \
        | sort -z | xargs -0 sha256sum >SHA256SUMS && \
    sha256sum --strict --quiet -c SHA256SUMS)
printf 'PASS final_provider_codegen_aarch64 module_sha256=%s toolchain_sha256=%s evidence=%s\n' \
    "$(sha256sum "$MODULE" | awk '{ print $1 }')" \
    "$(sha256sum "$TOOLCHAIN" | awk '{ print $1 }')" "$EVIDENCE"
