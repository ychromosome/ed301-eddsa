#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
    echo "rustc-profile-guard: missing rustc command" >&2
    exit 2
fi
if [ -z "${ED301_PROFILE_MARKER_DIR:-}" ]; then
    echo "rustc-profile-guard: ED301_PROFILE_MARKER_DIR is unset" >&2
    exit 2
fi

crate_name=
overflow_state=absent
previous=
for argument in "$@"; do
    if [ "$previous" = crate-name ]; then
        crate_name=$argument
        previous=
        continue
    fi
    if [ "$previous" = codegen ]; then
        case "$argument" in
            overflow-checks=on) overflow_state=on ;;
            overflow-checks=off) overflow_state=off ;;
        esac
        previous=
        continue
    fi
    case "$argument" in
        --crate-name) previous=crate-name ;;
        --crate-name=*) crate_name=${argument#--crate-name=} ;;
        -C) previous=codegen ;;
        -Coverflow-checks=on) overflow_state=on ;;
        -Coverflow-checks=off) overflow_state=off ;;
    esac
done

case "$crate_name" in
    crypto_bigint|ed301_eddsa)
        printf '%s\n' "$overflow_state" >>"$ED301_PROFILE_MARKER_DIR/$crate_name"
        ;;
esac

exec "$@"
