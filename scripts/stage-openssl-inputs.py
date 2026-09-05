#!/usr/bin/python3
import os
import stat
import sys


def copy_regular(source, destination):
    read_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        read_flags |= os.O_NOFOLLOW
        write_flags |= os.O_NOFOLLOW

    source_fd = os.open(source, read_flags)
    try:
        if not stat.S_ISREG(os.fstat(source_fd).st_mode):
            raise SystemExit(f"staged input is not a regular file: {source}")
        destination_fd = os.open(destination, write_flags, 0o400)
        try:
            while True:
                block = os.read(source_fd, 1024 * 1024)
                if not block:
                    break
                offset = 0
                while offset != len(block):
                    offset += os.write(destination_fd, block[offset:])
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)


if len(sys.argv) != 5:
    raise SystemExit(
        "usage: stage-openssl-inputs.py <tar-source> <tar-copy> "
        "<sidecar-source> <sidecar-copy>"
    )

copy_regular(sys.argv[1], sys.argv[2])
copy_regular(sys.argv[3], sys.argv[4])
