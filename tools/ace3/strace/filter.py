"""Installs a seccomp filter on itself and execs argv, to see which tools run under it.

Default: a thread (clone with CLONE_THREAD) is allowed, and a new process (clone without it, fork,
vfork) or io_uring_setup kills the process; clone3 fails with ENOSYS, since seccomp can't read its
flags, so glibc falls back to clone. With --no-threads every clone kills, as ace4's parser filter
does. execve stays allowed: it's the next call. Standard library only.
"""
import ctypes
import os
import platform
import struct
import sys

ARCHES = {
    "aarch64": dict(arch=0xC00000B7, clone=220, clone3=435, io_uring_setup=425, fork=None, vfork=None),
    "x86_64": dict(arch=0xC000003E, clone=56, clone3=435, io_uring_setup=425, fork=57, vfork=58),
}
LD_ABS, JEQ, JSET, RET = 0x20, 0x15, 0x45, 0x06
ALLOW, KILL, ENOSYS = 0x7FFF0000, 0x80000000, 0x00050000 | 38
CLONE_THREAD = 0x00010000


def program(a, no_threads):
    # the tail: index of ALLOW, KILL, ENOSYS, filled in at the end
    body = []  # (code, jt_label, jf_label, k)
    body.append((LD_ABS, None, None, 4))
    body.append((JEQ, "next", "kill", a["arch"]))
    body.append((LD_ABS, None, None, 0))
    body.append((JEQ, "enosys" if not no_threads else "kill", "next", a["clone3"]))
    body.append((JEQ, "kill", "next", a["io_uring_setup"]))
    for nr in (a["fork"], a["vfork"]):
        if nr is not None:
            body.append((JEQ, "kill", "next", nr))
    if no_threads:
        body.append((JEQ, "kill", "allow", a["clone"]))
    else:
        body.append((JEQ, "next", "allow", a["clone"]))
        body.append((LD_ABS, None, None, 16))  # args[0], low 32 bits on little endian
        body.append((JSET, "allow", "kill", CLONE_THREAD))
    tail = {"allow": len(body), "kill": len(body) + 1, "enosys": len(body) + 2}
    out = []
    for i, (code, jt, jf, k) in enumerate(body):
        def off(label):
            return 0 if label in (None, "next") else tail[label] - (i + 1)
        out.append(struct.pack("HBBI", code, off(jt), off(jf), k))
    for k in (ALLOW, KILL, ENOSYS):
        out.append(struct.pack("HBBI", RET, 0, 0, k))
    return b"".join(out), len(out)


def main():
    args = sys.argv[1:]
    no_threads = args[:1] == ["--no-threads"]
    if no_threads:
        args = args[1:]
    code, count = program(ARCHES[platform.machine()], no_threads)
    buf = ctypes.create_string_buffer(code, len(code))

    class Prog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    prog = Prog(count, ctypes.addressof(buf))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        sys.exit(f"no_new_privs: {os.strerror(ctypes.get_errno())}")
    if libc.prctl(22, 2, ctypes.addressof(prog), 0, 0) != 0:  # PR_SET_SECCOMP, FILTER
        sys.exit(f"seccomp: {os.strerror(ctypes.get_errno())}")
    os.execv(args[0], args)


main()
