#!/bin/bash
# Build one public OpenSSL release lane from a caller-staged tarball.
# No clone, download, private fork, package, or release operation occurs here.
set -Eeuo pipefail
export LC_ALL=C
umask 022

VER="${1:?usage: build_lane.sh <version> [<upstream-dir> [<lane-root>]]}"
if (( $# > 3 )); then
  printf 'usage: build_lane.sh <version> [<upstream-dir> [<lane-root>]]\n' >&2
  exit 2
fi
case "$VER" in
  3.5.7)
    SHLIB_MAJOR=3
    RELEASE_NAME=openssl-3.5.7
    PUBLIC_URL=https://www.openssl.org/source/openssl-3.5.7.tar.gz
    EXPECTED_TAR_SHA256=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8
    ;;
  4.0.1)
    SHLIB_MAJOR=4
    RELEASE_NAME=openssl-4.0.1
    PUBLIC_URL=https://www.openssl.org/source/openssl-4.0.1.tar.gz
    EXPECTED_TAR_SHA256=2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09
    ;;
  *) printf 'unsupported public OpenSSL lane: %s\n' "$VER" >&2; exit 2 ;;
esac
if (( $# >= 2 )); then
  UPSTREAM_ARG=$2
else
  : "${OPENSSL_UPSTREAM_DIR:?set OPENSSL_UPSTREAM_DIR or pass <upstream-dir>}"
  UPSTREAM_ARG=$OPENSSL_UPSTREAM_DIR
fi
if (( $# >= 3 )); then
  ROOT_ARG=$3
else
  : "${OPENSSL_LANE_ROOT:?set OPENSSL_LANE_ROOT or pass <lane-root>}"
  ROOT_ARG=$OPENSSL_LANE_ROOT
fi
if [[ -L "$ROOT_ARG" ]]; then
  printf 'lane root may not be a symlink: %s\n' "$ROOT_ARG" >&2
  exit 2
fi
if [[ -e "$ROOT_ARG" && ! -d "$ROOT_ARG" ]]; then
  printf 'lane root is not a directory: %s\n' "$ROOT_ARG" >&2
  exit 2
fi
mkdir -p -- "$ROOT_ARG"
UPSTREAM=$(readlink -f -- "$UPSTREAM_ARG")
ROOT=$(readlink -f -- "$ROOT_ARG")
[[ -d "$UPSTREAM" ]] || {
  printf 'upstream directory does not exist: %s\n' "$UPSTREAM_ARG" >&2
  exit 2
}

TOP=openssl-$VER
TAR=$UPSTREAM/$TOP.tar.gz
CHECKSUM=$UPSTREAM/$TOP.tar.gz.sha256
SRC=$ROOT/src/$TOP
INST=$ROOT/inst/$VER
LOGD=$ROOT/logs/$VER
for path in "$SRC" "$INST" "$LOGD"; do
  case "$path" in
    "$ROOT/"*) ;;
    *) printf 'derived path escapes lane root: %s\n' "$path" >&2; exit 2 ;;
  esac
done
for component in "$ROOT/src" "$ROOT/inst" "$ROOT/logs"; do
  [[ ! -L "$component" ]] || {
    printf 'lane-root component may not be a symlink: %s\n' "$component" >&2
    exit 2
  }
  mkdir -p -- "$component"
  component_real=$(readlink -f -- "$component")
  [[ "$component_real" == "$component" ]] || {
    printf 'lane-root component resolves unexpectedly: %s -> %s\n' \
      "$component" "$component_real" >&2
    exit 2
  }
done
for managed in "$SRC" "$INST" "$LOGD"; do
  [[ ! -L "$managed" ]] || {
    printf 'managed lane path may not be a symlink: %s\n' "$managed" >&2
    exit 2
  }
done
[[ ! -L "$TAR" && ! -L "$CHECKSUM" ]] || {
  printf 'tarball and checksum inputs must be regular non-symlink files\n' >&2
  exit 2
}
[[ -f "$TAR" ]] || {
  printf 'missing public tarball: %s\n' "$TAR" >&2; exit 2;
}
[[ -f "$CHECKSUM" ]] || {
  printf 'missing tarball checksum sidecar: %s\n' "$CHECKSUM" >&2; exit 2;
}
rm -rf -- "$LOGD"
mkdir -p -- "$LOGD"
[[ ! -L "$LOGD" && "$(readlink -f -- "$LOGD")" == "$LOGD" ]] || {
  printf 'log directory resolves unexpectedly: %s\n' "$LOGD" >&2
  exit 2
}
export CCACHE_DISABLE=1

BUILDER=$(readlink -f -- "$0")
PROVENANCE=$(readlink -f -- +  "$(dirname -- "$0")/../docs/PROVIDER_OPENSSL_LANE_PROVENANCE.md")
[[ -f "$BUILDER" && -f "$PROVENANCE" ]] || {
  printf 'builder or provenance document is missing\n' >&2
  exit 2
}

STATUS=$LOGD/lane_status
rm -f -- "$STATUS" "$STATUS.tmp" "$LOGD/lane_status.exit"
STATUS_WRITTEN=0
CURRENT_STEP=initialise
fail_lane() {
  local rc=$1 step=$2
  set +e
  if (( STATUS_WRITTEN == 0 )); then
    printf 'LANE %s FAILED at %s (exit %d)\n' "$VER" "$step" "$rc" > "$STATUS.tmp"
    mv -f -- "$STATUS.tmp" "$STATUS"
    printf '%d\n' "$rc" > "$LOGD/lane_status.exit"
    STATUS_WRITTEN=1
  fi
  exit "$rc"
}
on_err() {
  local rc=$?
  set +e
  if (( STATUS_WRITTEN == 0 )); then
    printf 'LANE %s FAILED at %s (exit %d, line %d, command=%q)\n' \
      "$VER" "$CURRENT_STEP" "$rc" "${BASH_LINENO[0]:-0}" "$BASH_COMMAND" > "$STATUS.tmp"
    mv -f -- "$STATUS.tmp" "$STATUS"
    printf '%d\n' "$rc" > "$LOGD/lane_status.exit"
    STATUS_WRITTEN=1
  fi
  exit "$rc"
}
trap on_err ERR

run_step() {
  local name=$1; shift
  local log=$LOGD/$name.log rc
  CURRENT_STEP=$name
  {
    printf 'CMD:'
    printf ' %q' "$@"
    printf '\nPWD: %s\nDATE: %s\n' "$PWD" "$(date -u +%FT%TZ)"
  } > "$log"
  if "$@" >> "$log" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  printf '%d\n' "$rc" > "$LOGD/$name.exit"
  printf 'EXIT: %d\n' "$rc" >> "$log"
  (( rc == 0 )) || fail_lane "$rc" "$name"
}

record_builder_inputs() {
  sha256sum -- "$BUILDER" "$PROVENANCE" \
    > "$LOGD/builder_inputs.sha256" || return 1
  {
    printf 'builder_path=%s\n' "$BUILDER"
    printf 'provenance_path=%s\n' "$PROVENANCE"
    printf 'builder_sha256=%s\n' "$(sha256sum "$BUILDER" | awk '{print $1}')"
    printf 'provenance_sha256=%s\n' \
      "$(sha256sum "$PROVENANCE" | awk '{print $1}')"
  } > "$LOGD/builder_identity.tsv"
}

verify_builder_inputs() {
  sha256sum --strict --quiet -c "$LOGD/builder_inputs.sha256"
}

record_toolchain_identity() {
  local tool selected resolved
  {
    printf 'schema=ed301-openssl-build-toolchain-v1\n'
    printf 'uname='; uname -a || return 1
    if [[ -f /etc/os-release ]]; then
      printf '%s\n' '--- /etc/os-release'
      cat /etc/os-release || return 1
    fi
    for tool in bash python3 tar sha256sum make perl gcc cc ld readelf ldd; do
      selected=$(command -v "$tool") || return 1
      resolved=$(readlink -f -- "$selected") || return 1
      printf '%s_selected_path=%s\n' "$tool" "$selected"
      printf '%s_resolved_path=%s\n' "$tool" "$resolved"
      case "$tool" in
        bash) "$tool" --version | sed -n '1p' || return 1 ;;
        python3) "$tool" --version || return 1 ;;
        tar|sha256sum|make|gcc|cc|ld|readelf|ldd)
          "$tool" --version | sed -n '1p' || return 1 ;;
        perl) "$tool" -e 'printf "perl_version=%vd\n", $^V' \
          || return 1 ;;
      esac
    done
  } | tee "$LOGD/toolchain_identity.tsv" || return 1
  {
    printf 'PATH=%s\n' "$PATH"
    printf 'OPENSSL_BUILD_JOBS=%s\n' "${OPENSSL_BUILD_JOBS:-UNSET}"
    printf 'CC=%s\n' "${CC:-UNSET}"
    printf 'CFLAGS=%s\n' "${CFLAGS:-UNSET}"
    printf 'CPPFLAGS=%s\n' "${CPPFLAGS:-UNSET}"
    printf 'LDFLAGS=%s\n' "${LDFLAGS:-UNSET}"
    printf 'MAKEFLAGS=%s\n' "${MAKEFLAGS:-UNSET}"
    printf 'LD_LIBRARY_PATH=%s\n' "${LD_LIBRARY_PATH:-UNSET}"
    printf 'LD_PRELOAD=%s\n' "${LD_PRELOAD:-UNSET}"
    printf 'OPENSSL_CONF=%s\n' "${OPENSSL_CONF:-UNSET}"
    printf 'OPENSSL_MODULES=%s\n' "${OPENSSL_MODULES:-UNSET}"
    printf 'CCACHE_DISABLE=%s\n' "$CCACHE_DISABLE"
  } > "$LOGD/build_environment.tsv"
}

verify_tarball_hash() {
  local refs=$LOGD/tarball_checksum.refs actual sidecar_digest
  awk 'NF >= 2 && length($1) == 64 { n=$2; sub(/^\*/, "", n); print n }' \
    "$CHECKSUM" > "$refs"
  mapfile -t checksum_names < "$refs"
  if (( ${#checksum_names[@]} != 1 )) ||
     [[ "${checksum_names[0]}" != "$TOP.tar.gz" ]]; then
    printf 'checksum sidecar must name exactly %s.tar.gz\n' "$TOP" >&2
    return 1
  fi
  sidecar_digest=$(awk 'NF >= 2 { print $1; exit }' "$CHECKSUM") || return 1
  [[ "$sidecar_digest" == "$EXPECTED_TAR_SHA256" ]] || {
    printf 'checksum sidecar digest is not the pinned release digest\n' >&2
    return 1
  }
  if ! ( cd "$UPSTREAM" &&
         sha256sum --strict --quiet -c "$(basename -- "$CHECKSUM")" ); then
    return 1
  fi
  actual=$(sha256sum -- "$TAR" | awk '{print $1}') || return 1
  [[ "$actual" == "$EXPECTED_TAR_SHA256" ]] || {
    printf 'tarball digest is not the pinned release digest\n' >&2
    return 1
  }
  sha256sum -- "$TAR" > "$LOGD/tarball.sha256"
  sha256sum -- "$CHECKSUM" > "$LOGD/tarball_checksum.sha256"
  printf 'public_source_url=%s\nrelease_name=%s\n' \
    "$PUBLIC_URL" "$RELEASE_NAME"
}

verify_tarball_layout() {
  local members=$LOGD/tarball.members

  tar --list --gzip --file "$TAR" > "$members" || return 1
  python3 - "$TAR" "$TOP" <<'PY'
import pathlib
import sys
import tarfile

archive, expected_root = sys.argv[1:]
seen = set()
root_count = 0
version_count = 0
with tarfile.open(archive, mode="r:gz") as source:
    for member in source.getmembers():
        name = member.name.rstrip("/")
        path = pathlib.PurePosixPath(name)
        if not name or path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"unsafe tar member path: {member.name}")
        if path.parts[0] != expected_root:
            raise SystemExit(f"member outside {expected_root}/: {member.name}")
        if name in seen:
            raise SystemExit(f"duplicate canonical tar member: {member.name}")
        seen.add(name)
        if not (member.isfile() or member.isdir()):
            raise SystemExit(
                f"unsupported tar member type for {member.name}: {member.type!r}"
            )
        if name == expected_root:
            if not member.isdir():
                raise SystemExit("top-level archive root is not a directory")
            root_count += 1
        if name == f"{expected_root}/VERSION.dat":
            if not member.isfile():
                raise SystemExit("VERSION.dat is not a regular file")
            version_count += 1
if root_count != 1 or version_count != 1:
    raise SystemExit(
        f"archive root/version cardinality mismatch: root={root_count} "
        f"version={version_count}"
    )
print(f"validated_members={len(seen)}")
PY
}

extract_source() {
  rm -rf -- "$SRC" "$INST" || return 1
  mkdir -p -- "$ROOT/src" "$INST" || return 1
  printf 'prefix_pre_state=empty\n' > "$LOGD/openssl_modules_pre.tsv"
  tar --extract --gzip --file "$TAR" --directory "$ROOT/src" \
    --no-same-owner --no-same-permissions --no-overwrite-dir || return 1
  [[ -d "$SRC" && -f "$SRC/VERSION.dat" ]]
}

verify_source_version() {
  local version_file=$SRC/VERSION.dat
  case "$VER" in
    3.5.7)
      grep -qx 'MAJOR=3' "$version_file" || return 1
      grep -qx 'MINOR=5' "$version_file" || return 1
      grep -qx 'PATCH=7' "$version_file" || return 1 ;;
    4.0.1)
      grep -qx 'MAJOR=4' "$version_file" || return 1
      grep -qx 'MINOR=0' "$version_file" || return 1
      grep -qx 'PATCH=1' "$version_file" || return 1 ;;
    *) return 1 ;;
  esac
  grep -qx "SHLIB_VERSION=$SHLIB_MAJOR" "$version_file" || return 1
  cat "$version_file"
}

write_source_manifest() {
  local manifest=$1 files=$2 tmp=$1.tmp
  if ! ( cd "$SRC"; find . -type f -print0 | sort -z | xargs -0 -r sha256sum ) > "$tmp"; then
    rm -f -- "$tmp"
    return 1
  fi
  mv -f -- "$tmp" "$manifest" || return 1
  if ! ( cd "$SRC"; find . -type f -printf '%P\n' | sort ) > "$files"; then
    return 1
  fi
  sha256sum -- "$manifest" > "$manifest.seal"
}
write_source_manifest_pre() {
  write_source_manifest "$LOGD/source_manifest_pristine.sha256" \
    "$LOGD/source_files_pre.lst"
}
write_source_manifest_post() {
  write_source_manifest "$LOGD/source_manifest_post.sha256" \
    "$LOGD/source_files_post.lst"
}

check_source_pristine() {
  ( cd "$SRC" &&
    sha256sum --strict --quiet -c "$LOGD/source_manifest_pristine.sha256" ) || return 1
  comm -23 "$LOGD/source_files_pre.lst" "$LOGD/source_files_post.lst" \
    > "$LOGD/source_files_removed.lst" || return 1
  comm -13 "$LOGD/source_files_pre.lst" "$LOGD/source_files_post.lst" \
    > "$LOGD/source_files_added.lst" || return 1
  [[ ! -s "$LOGD/source_files_removed.lst" ]] || {
    printf 'pre-existing source files disappeared\n' >&2
    return 1
  }
  printf 'pre_existing_regular_files_unchanged=true\nadded_build_files=%s\nremoved_preexisting_files=0\nscope=regular-file-content-and-presence-from-pristine-manifest\n' \
    "$(wc -l < "$LOGD/source_files_added.lst")" > "$LOGD/source_change.tsv"
}

write_source_identity() {
  {
    printf 'schema=ed301-openssl-lane-v1\nlane=%s\nsource_kind=pinned-release-tarball\nrelease_name=%s\nsource_url=%s\n' \
      "$VER" "$RELEASE_NAME" "$PUBLIC_URL"
    printf 'authenticated_git_tag=NOT_VERIFIED_FROM_RELEASE_TARBALL\n'
    printf 'source_fetch=not-performed-by-helper;caller-staged-input\nsource_commit=NOT_AVAILABLE_FROM_RELEASE_TARBALL\nsource_tree=NOT_AVAILABLE_FROM_RELEASE_TARBALL\n'
    printf 'tarball_name=%s.tar.gz\npinned_tar_sha256=%s\ntarball_sha256=%s\nchecksum_sidecar_sha256=%s\n' \
      "$TOP" "$EXPECTED_TAR_SHA256" \
      "$(awk '{print $1}' "$LOGD/tarball.sha256")" \
      "$(awk '{print $1}' "$LOGD/tarball_checksum.sha256")"
    printf 'source_root_rel=src/%s\nprefix_rel=inst/%s\npristine_manifest_rel=logs/%s/source_manifest_pristine.sha256\n' \
      "$TOP" "$VER" "$VER"
  } > "$LOGD/source_identity.tsv"
}

write_linker_selection() {
  printf 'include_dir_rel=inst/%s/include\nlibrary_dir_rel=inst/%s/lib\nconfigure_search_flag=-L%s/lib\nconfigure_runtime_flag=-Wl,-rpath,%s/lib\nexpected_runtime_directory=%s/lib\n' \
    "$VER" "$VER" "$INST" "$INST" "$INST" > "$LOGD/linker_selection.tsv"
}

hash_installed_artifacts() {
  shopt -s nullglob
  local files=("$INST/bin/openssl" "$INST/lib/libcrypto.so" \
    "$INST/lib/libcrypto.so.$SHLIB_MAJOR" "$INST/lib/libssl.so" \
    "$INST/lib/libssl.so.$SHLIB_MAJOR" "$INST/lib/ossl-modules/"*.so)
  (( ${#files[@]} > 0 )) || return 1
  : > "$LOGD/artifact_hashes.sha256"
  local path rel
  for path in "${files[@]}"; do
    [[ -e "$path" || -L "$path" ]] || return 1
    rel=${path#"$ROOT/"}
    ( cd "$ROOT" && sha256sum -- "$rel" ) >> "$LOGD/artifact_hashes.sha256" || return 1
  done
  sha256sum -- "$LOGD/artifact_hashes.sha256" > "$LOGD/artifact_hashes.seal"
}

verify_installed_artifacts() {
  local name link canonical expected

  ( cd "$ROOT" &&
    sha256sum --strict --quiet -c "logs/$VER/artifact_hashes.sha256" \
  ) || return 1
  : > "$LOGD/library_symlinks.tsv"
  for name in libcrypto libssl; do
    link="$INST/lib/$name.so"
    expected="$INST/lib/$name.so.$SHLIB_MAJOR"
    [[ -L "$link" && -f "$expected" ]] || return 1
    canonical=$(readlink -f -- "$link") || return 1
    [[ "$canonical" == "$expected" ]] || {
      printf '%s resolves outside its exact versioned lane target: %s\n' \
        "$link" "$canonical" >&2
      return 1
    }
    printf '%s\t%s\t%s\n' "$link" "$(readlink -- "$link")" "$canonical" \
      >> "$LOGD/library_symlinks.tsv" || return 1
  done
}

hash_installed_modules() {
  shopt -s nullglob
  local files=("$INST/lib/ossl-modules/"*.so)
  (( ${#files[@]} > 0 )) || return 1
  : > "$LOGD/openssl_modules_post.sha256"
  local path
  for path in "${files[@]}"; do
    ( cd "$INST/lib/ossl-modules" &&
      sha256sum -- "$(basename -- "$path")" ) >> "$LOGD/openssl_modules_post.sha256" || return 1
  done
  sha256sum -- "$LOGD/openssl_modules_post.sha256" > "$LOGD/openssl_modules_post.seal"
}

check_runtime_identity() {
  local bin=$INST/bin/openssl hdr=$INST/include/openssl/opensslv.h
  local header_version cli_version runpath rpath chosen soname resolved canonical expected
  [[ -x "$bin" && -f "$hdr" ]] || return 1
  header_version=$(awk -F'"' '/# *define +OPENSSL_FULL_VERSION_STR/{print $2; exit}' "$hdr") || return 1
  [[ "$header_version" == "$VER" ]] || return 1
  mkdir -p "$LOGD/clean-home" || return 1
  env -i PATH=/usr/bin:/bin HOME="$LOGD/clean-home" \
    OPENSSL_CONF=/dev/null OPENSSL_MODULES="$INST/lib/ossl-modules" \
    "$bin" version -a > "$LOGD/openssl_version_a.log" 2>&1 || return 1
  cli_version=$(env -i PATH=/usr/bin:/bin HOME="$LOGD/clean-home" \
    OPENSSL_CONF=/dev/null OPENSSL_MODULES="$INST/lib/ossl-modules" \
    "$bin" version) || return 1
  [[ "$cli_version" == "OpenSSL $VER "* ]] || return 1
  grep -Fqx "OPENSSLDIR: \"$INST/ssl\"" "$LOGD/openssl_version_a.log" || return 1
  env -i PATH=/usr/bin:/bin /usr/bin/ldd "$bin" \
    > "$LOGD/runtime_binding.ldd" 2>&1 || return 1
  /usr/bin/readelf -d "$bin" \
    > "$LOGD/runtime_binding.readelf" 2>&1 || return 1
  for soname in "libcrypto.so.$SHLIB_MAJOR" "libssl.so.$SHLIB_MAJOR"; do
    grep -Fq "Shared library: [$soname]" "$LOGD/runtime_binding.readelf" || return 1
    resolved=$(awk -v soname="$soname" '$1 == soname && $2 == "=>" { print $3; exit }' \
      "$LOGD/runtime_binding.ldd")
    [[ -n "$resolved" && "$resolved" != "not" ]] || return 1
    canonical=$(readlink -f -- "$resolved") || return 1
    case "$canonical" in
      "$INST/lib/"*) ;;
      *) printf '%s resolved outside selected lane: %s\n' "$soname" "$canonical" >&2; return 1 ;;
    esac
    expected=$(readlink -f -- "$INST/lib/$soname") || return 1
    [[ "$canonical" == "$expected" ]] || return 1
  done
  runpath=$(sed -n 's/.*Library runpath: \[\(.*\)\]/\1/p' \
    "$LOGD/runtime_binding.readelf") || return 1
  rpath=$(sed -n 's/.*Library rpath: \[\(.*\)\]/\1/p' \
    "$LOGD/runtime_binding.readelf") || return 1
  [[ -z "$runpath" || -z "$rpath" ]] || return 1
  if [[ -n "$runpath" ]]; then chosen=$runpath; else chosen=$rpath; fi
  [[ "$chosen" == "$INST/lib" ]] || return 1
  printf 'header_version=%s\ncli_version=%s\nrunpath_or_rpath=%s\n' \
    "$header_version" "$cli_version" "$chosen"
}

write_lane_identity() {
  {
    printf 'schema=ed301-openssl-lane-v1\nlane=%s\nsource_identity_rel=logs/%s/source_identity.tsv\nsource_kind=pinned-release-tarball\nrelease_name=%s\nsource_url=%s\n' \
      "$VER" "$VER" "$RELEASE_NAME" "$PUBLIC_URL"
    printf 'authenticated_git_tag=NOT_VERIFIED_FROM_RELEASE_TARBALL\n'
    printf 'source_commit=NOT_AVAILABLE_FROM_RELEASE_TARBALL\nsource_tree=NOT_AVAILABLE_FROM_RELEASE_TARBALL\nsource_manifest_rel=logs/%s/source_manifest_pristine.sha256\nsource_change_rel=logs/%s/source_change.tsv\n' \
      "$VER" "$VER"
    printf 'prefix_rel=inst/%s\nheaders_rel=inst/%s/include\nlibraries_rel=inst/%s/lib\ncli_rel=inst/%s/bin/openssl\nlinker_selection_rel=logs/%s/linker_selection.tsv\nartifact_hashes_rel=logs/%s/artifact_hashes.sha256\nopenssl_module_hashes_rel=logs/%s/openssl_modules_post.sha256\nruntime_binding_ldd_rel=logs/%s/runtime_binding.ldd\nruntime_binding_readelf_rel=logs/%s/runtime_binding.readelf\n' \
      "$VER" "$VER" "$VER" "$VER" "$VER" "$VER" "$VER" "$VER" "$VER"
  } > "$LOGD/lane_identity.seal.tmp" || return 1
  mv -f -- "$LOGD/lane_identity.seal.tmp" "$LOGD/lane_identity.seal"
}

write_evidence_manifest() {
  local out=$LOGD/evidence_manifest.sha256.tmp
  local rel
  # The manifest is created by this step, so its own log/exit and the final
  # lane status are deliberately outside this self-referential input set.
  local files=(
    "logs/$VER/builder_inputs.log"
    "logs/$VER/builder_inputs.exit"
    "logs/$VER/builder_inputs.sha256"
    "logs/$VER/builder_identity.tsv"
    "logs/$VER/toolchain_identity.log"
    "logs/$VER/toolchain_identity.exit"
    "logs/$VER/toolchain_identity.tsv"
    "logs/$VER/build_environment.tsv"
    "logs/$VER/tarball_hash.log"
    "logs/$VER/tarball_hash.exit"
    "logs/$VER/tarball_layout.log"
    "logs/$VER/tarball_layout.exit"
    "logs/$VER/tarball_checksum.refs"
    "logs/$VER/tarball.members"
    "logs/$VER/tarball.sha256"
    "logs/$VER/tarball_checksum.sha256"
    "logs/$VER/extract.log"
    "logs/$VER/extract.exit"
    "logs/$VER/source_version.log"
    "logs/$VER/source_version.exit"
    "logs/$VER/source_manifest_pristine.log"
    "logs/$VER/source_manifest_pristine.exit"
    "logs/$VER/source_manifest_pristine.sha256"
    "logs/$VER/source_manifest_pristine.sha256.seal"
    "logs/$VER/source_files_pre.lst"
    "logs/$VER/source_identity.log"
    "logs/$VER/source_identity.exit"
    "logs/$VER/source_identity.tsv"
    "logs/$VER/linker_selection.log"
    "logs/$VER/linker_selection.exit"
    "logs/$VER/linker_selection.tsv"
    "logs/$VER/configure.log"
    "logs/$VER/configure.exit"
    "logs/$VER/make.log"
    "logs/$VER/make.exit"
    "logs/$VER/install.log"
    "logs/$VER/install.exit"
    "logs/$VER/source_manifest_post.log"
    "logs/$VER/source_manifest_post.exit"
    "logs/$VER/source_manifest_post.sha256"
    "logs/$VER/source_manifest_post.sha256.seal"
    "logs/$VER/source_files_post.lst"
    "logs/$VER/source_pristine_check.log"
    "logs/$VER/source_pristine_check.exit"
    "logs/$VER/source_files_added.lst"
    "logs/$VER/source_files_removed.lst"
    "logs/$VER/source_change.tsv"
    "logs/$VER/artifact_hashes.log"
    "logs/$VER/artifact_hashes.exit"
    "logs/$VER/artifact_hashes.sha256"
    "logs/$VER/artifact_hashes.seal"
    "logs/$VER/artifact_verify.log"
    "logs/$VER/artifact_verify.exit"
    "logs/$VER/library_symlinks.tsv"
    "logs/$VER/openssl_module_hashes.log"
    "logs/$VER/openssl_module_hashes.exit"
    "logs/$VER/openssl_modules_pre.tsv"
    "logs/$VER/openssl_modules_post.sha256"
    "logs/$VER/openssl_modules_post.seal"
    "logs/$VER/lane_identity.log"
    "logs/$VER/lane_identity.exit"
    "logs/$VER/openssl_version_a.log"
    "logs/$VER/runtime_binding.ldd"
    "logs/$VER/runtime_binding.readelf"
    "logs/$VER/lane_identity_seal.log"
    "logs/$VER/lane_identity_seal.exit"
    "logs/$VER/lane_identity.seal"
    "logs/$VER/builder_inputs_post.log"
    "logs/$VER/builder_inputs_post.exit"
  )
  : > "$out"
  for rel in "${files[@]}"; do
    [[ -f "$ROOT/$rel" ]] || {
      printf 'missing evidence input: %s\n' "$rel" >&2
      return 1
    }
    ( cd "$ROOT" && sha256sum -- "$rel" ) >> "$out" || return 1
  done
  mv -f -- "$out" "$LOGD/evidence_manifest.sha256" || return 1
  sha256sum -- "$LOGD/evidence_manifest.sha256" \
    > "$LOGD/evidence_manifest.seal"
}

verify_evidence_manifest() {
  sha256sum --strict --quiet -c "$LOGD/evidence_manifest.seal" || return 1
  ( cd "$ROOT" &&
    sha256sum --strict --quiet -c "logs/$VER/evidence_manifest.sha256" \
  )
}

run_step builder_inputs record_builder_inputs
run_step toolchain_identity record_toolchain_identity
run_step tarball_hash verify_tarball_hash
run_step tarball_layout verify_tarball_layout
run_step extract extract_source
run_step source_version verify_source_version
run_step source_manifest_pristine write_source_manifest_pre
run_step source_identity write_source_identity
run_step linker_selection write_linker_selection
cd "$SRC"
JOBS=${OPENSSL_BUILD_JOBS:-$(nproc)}
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]]
run_step configure ./Configure linux-x86_64 shared --prefix="$INST" --libdir=lib \
  --openssldir="$INST/ssl" -DPURIFY "-L$INST/lib" "-Wl,-rpath,$INST/lib"
run_step make make -j"$JOBS"
run_step install make install_sw install_ssldirs
run_step source_manifest_post write_source_manifest_post
run_step source_pristine_check check_source_pristine
run_step artifact_hashes hash_installed_artifacts
run_step openssl_module_hashes hash_installed_modules
run_step lane_identity check_runtime_identity
run_step artifact_verify verify_installed_artifacts
run_step lane_identity_seal write_lane_identity
run_step builder_inputs_post verify_builder_inputs
run_step evidence_manifest write_evidence_manifest
run_step evidence_manifest_verify verify_evidence_manifest

# The only success transition is last.  All earlier failures exit through
# fail_lane/on_err, so a failed check cannot be followed by LANE OK.
printf '0\n' > "$LOGD/lane_status.exit.tmp"
printf 'LANE %s OK\n' "$VER" > "$STATUS.tmp"
mv -f -- "$LOGD/lane_status.exit.tmp" "$LOGD/lane_status.exit"
mv -f -- "$STATUS.tmp" "$STATUS"
STATUS_WRITTEN=1
