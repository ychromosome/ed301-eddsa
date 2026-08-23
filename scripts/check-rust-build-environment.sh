#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

FORBIDDEN='^(RUST[^=]*|CARGO[^=]*|CC|CC_[^=]*|CXX|CXX_[^=]*|AR|AR_[^=]*|RANLIB|RANLIB_[^=]*|LD|LD_[^=]*|CFLAGS|CFLAGS_[^=]*|CPPFLAGS|CPPFLAGS_[^=]*|CXXFLAGS|CXXFLAGS_[^=]*|LDFLAGS|LDFLAGS_[^=]*|LIBRARY_PATH|CPATH|C_INCLUDE_PATH|CPLUS_INCLUDE_PATH|OBJC_INCLUDE_PATH|PKG_CONFIG[^=]*|BINDGEN[^=]*|CRATE_CC[^=]*|HOST_CC|TARGET_CC|MAKEFLAGS|MFLAGS|PYTHON[^=]*|OPENSSL_[^=]*|BASH_ENV|ENV|TMPDIR)='

if env -0 | grep -zEq "$FORBIDDEN"; then
    echo "inherited build, compiler, runner, Python or linker override is forbidden" >&2
    env -0 | awk -v RS='\0' -v pattern="$FORBIDDEN" '
        $0 ~ pattern {
            name = $0
            sub(/=.*/, "", name)
            print name "=<redacted>"
        }
    ' | sort >&2
    exit 1
fi

for tool in /usr/bin/cargo /usr/bin/rustc /usr/bin/rustfmt \
        /usr/bin/cargo-clippy /usr/bin/rustdoc /usr/bin/gcc /usr/bin/ar \
        /usr/bin/python3; do
    test -x "$tool" || {
        echo "missing canonical build tool: $tool" >&2
        exit 127
    }
done

printf 'rust_build_environment=PASS path=%s\n' "$PATH"
