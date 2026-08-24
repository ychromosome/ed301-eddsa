#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
sh "$ROOT/scripts/require-verified-snapshot.sh"
if [ "$#" -ne 3 ]; then
    printf 'usage: %s <provider-module.so> <toolchain-marker> <evidence-directory>\n' \
        "$0" >&2
    exit 2
fi
MODULE=$1
TOOLCHAIN=$2
EVIDENCE=$3

for tool in /usr/bin/awk /usr/bin/cat /usr/bin/grep /usr/bin/mkdir \
        /usr/bin/nm /usr/bin/objdump /usr/bin/readelf /usr/bin/sha256sum; do
    test -x "$tool" || {
        echo "missing canonical codegen-gate tool: $tool" >&2
        exit 127
    }
done
test -f "$MODULE" && test ! -L "$MODULE" || {
    echo "provider module must be a regular non-symlink file: $MODULE" >&2
    exit 2
}
test -s "$TOOLCHAIN" && test ! -L "$TOOLCHAIN" || {
    echo "missing regular toolchain marker: $TOOLCHAIN" >&2
    exit 2
}
test ! -e "$EVIDENCE" || {
    echo "codegen evidence directory already exists: $EVIDENCE" >&2
    exit 2
}
/usr/bin/mkdir -m 700 "$EVIDENCE"

ELF_HEADER=$EVIDENCE/elf-header.txt
/usr/bin/readelf -h "$MODULE" >"$ELF_HEADER"
/usr/bin/grep -Eq 'Type:[[:space:]]+DYN \(Shared object file\)$' \
    "$ELF_HEADER" || {
        echo "codegen input is not a shared object" >&2
        exit 1
    }
/usr/bin/grep -Eq \
    'Machine:[[:space:]]+Advanced Micro Devices X86-64$' "$ELF_HEADER" || {
        echo "the current codegen policy is defined only for x86-64" >&2
        exit 1
    }
/usr/bin/readelf -S "$MODULE" >"$EVIDENCE/elf-sections.txt"
/usr/bin/grep -Eq '[[:space:]]\.symtab[[:space:]]+SYMTAB[[:space:]]' \
    "$EVIDENCE/elf-sections.txt" || {
        echo "final provider lacks the review-required symbol table" >&2
        exit 1
    }

DUMP=$EVIDENCE/provider.objdump
SUMMARY=$EVIDENCE/summary.txt
/usr/bin/objdump -d -C --no-show-raw-insn --disassemble-zeroes --wide \
    "$MODULE" >"$DUMP"
/usr/bin/nm -C --defined-only "$MODULE" >"$EVIDENCE/provider.nm"
/usr/bin/nm -n -C --defined-only "$MODULE" \
    >"$EVIDENCE/provider.nm-by-address"
/usr/bin/readelf -rW "$MODULE" >"$EVIDENCE/provider.relocations"
/usr/bin/objdump --version >"$EVIDENCE/objdump-version.txt"
: >"$SUMMARY"

# Resolve local R_X86_64_RELATIVE GOT entries back to their named functions.
# This lets the call-closure check name Rust panic/cleanup callees without
# pinning the policy to load addresses or RIP displacements.
/usr/bin/awk '
    function normalize(value) {
        sub(/^0+/, "", value)
        return value == "" ? "0" : value
    }
    FNR == NR && $1 ~ /^[[:xdigit:]]+$/ && $2 ~ /^[A-Za-z]$/ {
        address = normalize($1)
        $1 = ""
        $2 = ""
        sub(/^[[:space:]]+/, "")
        symbols[address] = $0
        next
    }
    FNR != NR && $3 == "R_X86_64_RELATIVE" {
        got = normalize($1)
        target = normalize($NF)
        # Most relative relocations point to anonymous read-only data rather
        # than callable symbols. Record only named code targets; a call through
        # any unrecorded entry still fails below as UNRESOLVED_RELATIVE_GOT.
        if (target in symbols)
            printf "%s\t%s\n", got, symbols[target]
    }
' "$EVIDENCE/provider.nm-by-address" "$EVIDENCE/provider.relocations" \
    >"$EVIDENCE/relative-got-targets.txt"

extract_symbol() {
    symbol=$1
    destination=$2
    count=$(/usr/bin/awk -v symbol="$symbol" '
        /^[[:space:]]*[[:xdigit:]]+ <.*>:/ &&
                index($0, "<" symbol ">:") != 0 { count++ }
        END { print count + 0 }
    ' "$DUMP")
    if [ "$count" -ne 1 ]; then
        printf 'expected exactly one final-binary symbol %s, found %s\n' \
            "$symbol" "$count" >&2
        exit 1
    fi
    /usr/bin/awk -v symbol="$symbol" '
        /^[[:space:]]*[[:xdigit:]]+ <.*>:/ {
            active = index($0, "<" symbol ">:") != 0
        }
        active { print }
    ' "$DUMP" >"$destination"
    test -s "$destination"
}

extract_symbol_instances() {
    symbol=$1
    expected_count=$2
    destination=$3
    count=$(/usr/bin/awk -v symbol="$symbol" '
        /^[[:space:]]*[[:xdigit:]]+ <.*>:/ &&
                index($0, "<" symbol ">:") != 0 { count++ }
        END { print count + 0 }
    ' "$DUMP")
    if [ "$count" -ne "$expected_count" ]; then
        printf 'expected %s final-binary instances of %s, found %s\n' \
            "$expected_count" "$symbol" "$count" >&2
        exit 1
    fi
    /usr/bin/awk -v symbol="$symbol" '
        /^[[:space:]]*[[:xdigit:]]+ <.*>:/ {
            active = index($0, "<" symbol ">:") != 0
        }
        active { print }
    ' "$DUMP" >"$destination"
    test -s "$destination"
}

# Return success only when a conditional transfer, variable-time division, or
# deliberate trap is present. SETcc is permitted only without a following
# conditional branch; the latter is rejected here independently of spelling.
contains_forbidden_instruction() {
    /usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ {
            mnemonic = $2
            if ((mnemonic ~ /^j/ && mnemonic !~ /^jmpq?$/) ||
                    mnemonic ~ /^loop/ || mnemonic ~ /^div/ ||
                    mnemonic ~ /^idiv/ || mnemonic == "ud2" ||
                    mnemonic == "int3") {
                print
                found = 1
            }
        }
        END { exit found ? 0 : 1 }
    ' "$1"
}

count_mnemonic() {
    pattern=$1
    file=$2
    /usr/bin/awk -v pattern="$pattern" '
        /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ pattern { count++ }
        END { print count + 0 }
    ' "$file"
}

check_no_indexed_load() {
    file=$1
    if /usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ &&
                $0 ~ /\([^)]*,[^)]*\)/ &&
                $2 !~ /^lea/ &&
                $0 !~ /[[:space:]]nop[a-z]*[[:space:]]/ {
            print
            found = 1
        }
        END { exit found ? 0 : 1 }
    ' "$file"; then
        echo "FAIL indexed memory access in constant-time selector" >&2
        exit 1
    fi
}

check_call_closure() {
    file=$1
    allowed=$2
    if /usr/bin/awk -v allowed="$allowed" '
        /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^call/ &&
                $0 !~ allowed {
            print
            found = 1
        }
        END { exit found ? 0 : 1 }
    ' "$file"; then
        echo "FAIL unexpected call in branch-free arithmetic symbol" >&2
        exit 1
    fi
}

# Record the exact direct and resolved-indirect call sequence of a reviewed
# secret-path symbol. Register-indirect memcpy calls are accepted only when
# the register was populated from the named memcpy GOT slot and has not been
# overwritten. Any unresolved or newly introduced call therefore changes the
# manifest and fails closed.
check_exact_call_graph() {
    label=$1
    file=$2
    expected=$3
    observed=$EVIDENCE/$label.calls

    /usr/bin/awk '
        function normalize_address(value) {
            sub(/^0+/, "", value)
            return value == "" ? "0" : value
        }
        function canonical_register(value) {
            gsub(/[[:space:]]/, "", value)
            sub(/^\*/, "", value)
            if (value ~ /^%(r|e)?bx$/ || value ~ /^%b[lh]$/)
                return "%rbx"
            if (value ~ /^%r13([dwb])?$/)
                return "%r13"
            return value
        }
        function comment_symbol(line, target, position) {
            position = index(line, "<")
            if (position == 0)
                return ""
            target = substr(line, position + 1)
            sub(/>[[:space:]]*$/, "", target)
            if (target ~ /^memcpy@/)
                target = "memcpy"
            return target
        }
        function got_address(line, tail, parts) {
            tail = line
            sub(/^.*#[[:space:]]*/, "", tail)
            split(tail, parts, /[[:space:]]+/)
            return normalize_address(parts[1])
        }
        FNR == NR {
            tab = index($0, "\t")
            if (tab != 0)
                got[normalize_address(substr($0, 1, tab - 1))] = \
                    substr($0, tab + 1)
            next
        }
        /^[[:space:]]*[[:xdigit:]]+:/ {
            mnemonic = $2
            operands = $3
            line = $0

            # Track only named, callee-saved register loads. Calls preserve
            # these registers under the x86-64 ABI; any explicit write below
            # invalidates the provenance before a later indirect call.
            loaded_register = ""
            loaded_target = ""
            if (mnemonic ~ /^(mov|lea)/ && line ~ /<memcpy@/) {
                count = split(operands, pieces, ",")
                loaded_register = canonical_register(pieces[count])
                loaded_target = "memcpy"
            }

            if (mnemonic ~ /^call/) {
                target = ""
                if (line ~ /<_GLOBAL_OFFSET_TABLE_/) {
                    address = got_address(line)
                    target = got[address]
                    if (target == "")
                        target = "UNRESOLVED_RELATIVE_GOT:" address
                } else if (index(line, "<") != 0) {
                    target = comment_symbol(line)
                } else if (operands ~ /^\*%/) {
                    register = canonical_register(operands)
                    target = register_target[register]
                    if (target == "")
                        target = "UNRESOLVED_REGISTER:" register
                } else {
                    target = "UNRESOLVED_CALL:" operands
                }
                print target
            }

            # Most AT&T instructions write their last register operand. The
            # exclusions below are read-only/control instructions. Clear a
            # tracked target before installing a new reviewed GOT load.
            count = split(operands, pieces, ",")
            destination = canonical_register(pieces[count])
            if (destination in register_target &&
                    mnemonic !~ /^(cmp|test|push|call|j|ret|nop|data16)/)
                delete register_target[destination]
            if (loaded_register == "%rbx" || loaded_register == "%r13")
                register_target[loaded_register] = loaded_target
        }
    ' "$EVIDENCE/relative-got-targets.txt" "$file" >"$observed"

    if [ "$(/usr/bin/cat "$observed")" != "$expected" ]; then
        printf 'FAIL changed or unresolved call graph in %s\n' "$label" >&2
        /usr/bin/cat "$observed" >&2
        exit 1
    fi
    printf 'PASS call_graph=%s sha256=%s\n' "$label" \
        "$(/usr/bin/sha256sum "$observed" | /usr/bin/awk '{ print $1 }')" \
        | tee -a "$SUMMARY"
}

check_branch_free() {
    label=$1
    symbol=$2
    minimum_sbb=$3
    minimum_cmov=$4
    allow_jmp=$5
    call_pattern=$6
    indexed_policy=$7
    section=$EVIDENCE/$label.asm

    extract_symbol "$symbol" "$section"
    if contains_forbidden_instruction "$section"; then
        echo "FAIL conditional control flow in final symbol $symbol" >&2
        exit 1
    fi
    if [ "$allow_jmp" = no ] \
            && [ "$(count_mnemonic '^jmpq?$' "$section")" -ne 0 ]; then
        echo "FAIL unexpected jump in straight-line symbol $symbol" >&2
        exit 1
    fi
    if [ "$call_pattern" != unrestricted ]; then
        check_call_closure "$section" "$call_pattern"
    fi
    if [ "$indexed_policy" = reject ]; then
        check_no_indexed_load "$section"
    fi

    sbb=$(count_mnemonic '^sbb' "$section")
    cmov=$(count_mnemonic '^cmov' "$section")
    setcc=$(count_mnemonic '^set' "$section")
    if [ "$sbb" -lt "$minimum_sbb" ] || [ "$cmov" -lt "$minimum_cmov" ]; then
        printf 'FAIL changed borrow/select lowering in %s: sbb=%s cmov=%s\n' \
            "$symbol" "$sbb" "$cmov" >&2
        exit 1
    fi
    printf 'PASS symbol=%s sbb=%s cmov=%s setcc=%s\n' \
        "$symbol" "$sbb" "$cmov" "$setcc" | tee -a "$SUMMARY"
}

check_all_branch_free() {
    label=$1
    symbol=$2
    expected_count=$3
    section=$EVIDENCE/$label.asm

    extract_symbol_instances "$symbol" "$expected_count" "$section"
    if contains_forbidden_instruction "$section" \
            || [ "$(count_mnemonic '^jmpq?$' "$section")" -ne 0 ]; then
        echo "FAIL control flow in final symbol instances $symbol" >&2
        exit 1
    fi
    check_call_closure "$section" '^$'
    printf 'PASS symbol_instances=%s count=%s branch_free=1\n' \
        "$symbol" "$expected_count" | tee -a "$SUMMARY"
}

# These are the actual Thin-LTO symbols in the loadable provider. Minimum
# counts bind the accepted Rust-1.97 lowering shape: any materially different
# compiler result fails closed and requires manual review.
check_branch_free field_reduce \
    'ed301_eddsa::field_5x64::reduce_wide' 2 5 no '^$' allow
check_branch_free field_square \
    'ed301_eddsa::field_5x64::square_wide' 0 0 no '^$' allow
check_branch_free point_double \
    '<ed301_eddsa::edwards::EdwardsPoint>::double' 20 35 no \
    'field_5x64::(reduce_wide|square_wide)' allow
check_branch_free point_add \
    '<ed301_eddsa::edwards::EdwardsPoint>::add' 25 45 no \
    'field_5x64::reduce_wide' allow
check_branch_free point_add_affine \
    '<ed301_eddsa::edwards::EdwardsPoint>::add_affine' 20 30 no \
    'field_5x64::reduce_wide' allow
check_branch_free point_is_valid \
    '<ed301_eddsa::edwards::EdwardsPoint>::is_valid' 10 25 no \
    'field_5x64::(reduce_wide|square_wide)' allow
check_branch_free affine_select \
    '<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select' 0 16 no \
    '^$' reject
check_branch_free affine_negate \
    '<ed301_eddsa::edwards::AffineNielsPoint>::negate' 8 10 no '^$' allow
check_branch_free scalar_reduce \
    '<ed301_eddsa::scalar::Scalar>::reduce_hash_le' 2 5 yes \
    unrestricted allow
check_branch_free basepoint_select \
    'ed301_eddsa::edwards::select_basepoint' 0 0 no \
    unrestricted reject

# Branch-sensitive leaf helpers reached from the secret scalar reducer are
# checked in the same final DSO. The duplicate zeroize instance is expected
# from Thin LTO and both copies must remain straight-line.
check_branch_free scalar_uint_from_le38 \
    'ed301_eddsa::scalar::uint_from_le38' 0 0 no '^$' allow
check_branch_free scalar_retrieve \
    '<crypto_bigint::modular::const_monty_form::ConstMontyForm<ed301_eddsa::scalar::ScalarModulus, 5>>::retrieve' \
    0 0 no '^$' allow
check_all_branch_free scalar_zeroize \
    'core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>' 2
check_branch_free safegcd_lincomb \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int::<1>' \
    0 0 no '^$' allow

# Fixed secret-path loops are allowed only in these exact compiler shapes.
check_fixed_branches() {
    label=$1
    symbol=$2
    expected=$3
    section=$EVIDENCE/$label.asm
    observed=$EVIDENCE/$label.branches
    extract_symbol "$symbol" "$section"
    /usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ {
            mnemonic = $2
            operands = $3
            if (mnemonic ~ /^j/ && mnemonic !~ /^jmpq?$/)
                print previous_mnemonic " " previous_operands "|" mnemonic
            previous_mnemonic = mnemonic
            previous_operands = mnemonic ~ /^j/ ? "TARGET" : operands
        }
    ' "$section" >"$observed"
    if [ "$(cat "$observed")" != "$expected" ]; then
        printf 'FAIL changed fixed-loop shape in %s\n' "$symbol" >&2
        cat "$observed" >&2
        exit 1
    fi
    if /usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ &&
                ($2 ~ /^loop/ || $2 ~ /^div/ || $2 ~ /^idiv/ ||
                 $2 == "ud2" || $2 == "int3") { found = 1 }
        END { exit found ? 0 : 1 }
    ' "$section"; then
        echo "FAIL forbidden instruction in fixed-loop symbol $symbol" >&2
        exit 1
    fi
    printf 'PASS fixed_loop_symbol=%s branches=%s\n' \
        "$symbol" "$(count_mnemonic '^j' "$section")" | tee -a "$SUMMARY"
}

check_fixed_branches field_invert \
    '<ed301_eddsa::field_5x64::Fe301>::invert' \
    'dec %edx|jne
sub %r13d,%ecx|jne'
check_fixed_branches montgomery_mul \
    'crypto_bigint::modular::mul::mul_montgomery_form::<5>' \
    'cmp $0x5,%rdx|jne'
check_fixed_branches scalar_mul_base \
    '<ed301_eddsa::edwards::EdwardsPoint>::scalar_mul_base_encoded' \
    'cmp $0x4d,%rax|jne
cmp $0x4c,%rax|je
cmp $0x4a,%rbp|jb
cmp $0x4a,%rbp|jb
cmp $0x4c,%rax|jne
cmp $0x4c,%rcx|jne'
check_fixed_branches safegcd_shift \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift::<1>' \
    'cmp $0x40,%eax|jae
cmp $0x40,%ebp|jae
test %ebp,%ebp|je'
check_fixed_branches safegcd_shift_mod \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift_mod::<1>' \
    'cmp $0x40,%edi|jae
cmp $0x40,%ebp|je
je TARGET|jae
mov %ebp,0xc(%rsp)|je'

# Exact reviewed call closure for every non-leaf secret-path symbol above.
# The manifests deliberately include unwind/panic-only edges: a compiler bump
# that adds, removes, or relocates work into a helper requires fresh review.
check_exact_call_graph scalar_reduce "$EVIDENCE/scalar_reduce.asm" \
    'ed301_eddsa::scalar::uint_from_le38
ed301_eddsa::scalar::uint_from_le38
crypto_bigint::modular::mul::mul_montgomery_form::<5>
crypto_bigint::modular::mul::mul_montgomery_form::<5>
crypto_bigint::modular::mul::mul_montgomery_form::<5>
<crypto_bigint::modular::const_monty_form::ConstMontyForm<ed301_eddsa::scalar::ScalarModulus, 5>>::retrieve
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
_Unwind_Resume@plt
core::panicking::panic_in_cleanup'
check_exact_call_graph basepoint_select "$EVIDENCE/basepoint_select.asm" \
    '<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::negate
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select'
check_exact_call_graph field_invert "$EVIDENCE/field_invert.asm" \
    'crypto_bigint::modular::mul::mul_montgomery_form::<5>
<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift::<1>
<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift::<1>
<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift_mod::<1>
<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift_mod::<1>'
check_exact_call_graph montgomery_mul "$EVIDENCE/montgomery_mul.asm" ''
check_exact_call_graph scalar_mul_base "$EVIDENCE/scalar_mul_base.asm" \
    'memcpy
ed301_eddsa::edwards::select_basepoint
<ed301_eddsa::edwards::EdwardsPoint>::add_affine
memcpy
<ed301_eddsa::edwards::EdwardsPoint>::double
<ed301_eddsa::edwards::EdwardsPoint>::double
<ed301_eddsa::edwards::EdwardsPoint>::double
<ed301_eddsa::edwards::EdwardsPoint>::double
ed301_eddsa::edwards::select_basepoint
<ed301_eddsa::edwards::EdwardsPoint>::add_affine
memcpy
_Unwind_Resume@plt'
check_exact_call_graph safegcd_shift "$EVIDENCE/safegcd_shift.asm" \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int::<1>
core::option::expect_failed
core::option::expect_failed
core::panicking::panic_bounds_check'
check_exact_call_graph safegcd_shift_mod "$EVIDENCE/safegcd_shift_mod.asm" \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int::<1>
core::option::expect_failed
core::panicking::panic_bounds_check'

# Prove that the closure checker itself rejects a newly introduced helper
# edge. Run it in a subshell because the normal failure path intentionally
# exits immediately.
CALL_NEGATIVE=$EVIDENCE/call-graph-negative-control.asm
/usr/bin/awk '{ print } END {
    print "   deadbeef: call   0 <unexpected::secret_helper>"
}' "$EVIDENCE/basepoint_select.asm" >"$CALL_NEGATIVE"
if (check_exact_call_graph call_graph_negative_control "$CALL_NEGATIVE" \
        "$(/usr/bin/cat "$EVIDENCE/basepoint_select.calls")" \
        >/dev/null 2>&1); then
    echo "FAIL call-graph checker accepted an unexpected helper" >&2
    exit 1
fi
printf '%s\n' 'PASS negative_control=unexpected-call-rejected' \
    | tee -a "$SUMMARY"

# Same-DSO negative control: the exported provider initializer legitimately
# contains a conditional branch and therefore must fail the branch-free rule.
extract_symbol OSSL_provider_init "$EVIDENCE/negative-control.asm"
negative_jcc=$(count_mnemonic '^j' "$EVIDENCE/negative-control.asm")
if [ "$negative_jcc" -lt 1 ] \
        || ! contains_forbidden_instruction \
            "$EVIDENCE/negative-control.asm" \
            >"$EVIDENCE/negative-control-detected.txt"; then
    echo "FAIL same-binary codegen checker negative control" >&2
    exit 1
fi
printf '%s\n' 'PASS negative_control=OSSL_provider_init-jcc-detected' \
    | tee -a "$SUMMARY"

if /usr/bin/grep -Eq 'ed301_eddsa::scalar::.*(rem_wide|div3by2)' \
        "$EVIDENCE/provider.nm"; then
    echo "FAIL test-oracle wide division reached the provider binary" >&2
    exit 1
fi
printf '%s\n' 'PASS scalar_wide_division_oracle=absent' | tee -a "$SUMMARY"

/usr/bin/sha256sum "$MODULE" "$TOOLCHAIN" "$DUMP" "$SUMMARY" \
    >"$EVIDENCE/SHA256SUMS"
printf 'PASS final_provider_codegen module_sha256=%s toolchain_sha256=%s evidence=%s\n' \
    "$(/usr/bin/sha256sum "$MODULE" | /usr/bin/awk '{ print $1 }')" \
    "$(/usr/bin/sha256sum "$TOOLCHAIN" | /usr/bin/awk '{ print $1 }')" \
    "$EVIDENCE"
sh "$ROOT/scripts/require-verified-snapshot.sh"
