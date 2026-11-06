"""Samples the private memory of a Compose stack's containers (PLAN.md 3.5).

tools/memory/measure runs this in a helper container with the VM's PID namespace and cgroup tree,
because a process in one container can't read another's smaps_rollup. It reads three things:

- each process's /proc/PID/smaps_rollup: the parser pool's task processes as fast as this loop
  can go, everything else every SLOW seconds;
- each container's cgroup: memory.stat every SLOW seconds, and memory.peak, memory.max and
  memory.events when a phase ends;
- the kernel's taskstats exit records, in a process of its own. Sampling can miss a task process
  or its peak. These can't: the kernel sends one when each process exits, with its peak RSS and
  its lifetime.

A phase is whatever name is in the file PHASE_FILE. Writing `stop` there ends the run.

Usage: sample.py OUT_DIR PHASE_FILE SERVICE=CONTAINER_ID...
Writes to OUT_DIR: samples.tsv, cgroup.tsv, tasks.tsv, taskstats.tsv, peaks.tsv and meta.json.
"""

import json
import multiprocessing
import os
import socket
import statistics
import struct
import sys
import time

CGROUP_ROOT = "/sys/fs/cgroup/docker"
PARSERS = "parsers"
TASK_ARG = "task"
TASK_UID = 10001  # ace4-task, docker/ace4/Dockerfile
SLOW = 0.25

FIELDS = {
    b"Rss:": "rss",
    b"Pss:": "pss",
    b"Private_Clean:": "private_clean",
    b"Private_Dirty:": "private_dirty",
    b"Anonymous:": "anon",
}


def rollup(pid):
    """The kB figures of a process's smaps_rollup, or None if it has gone or has no memory."""
    try:
        with open(f"/proc/{pid}/smaps_rollup", "rb") as f:
            text = f.read()
    except OSError:
        return None
    figures = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] in FIELDS:
            figures[FIELDS[parts[0]]] = int(parts[1])
    if "rss" not in figures:
        return None
    figures["private"] = figures["private_clean"] + figures["private_dirty"]
    return figures


def peak_rss_so_far(pid):
    try:
        with open(f"/proc/{pid}/status", "rb") as f:
            for line in f:
                if line.startswith(b"VmHWM:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0


def cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().decode(errors="replace").split("\0")
    except OSError:
        return []


def procs(cgroup):
    try:
        with open(f"{cgroup}/cgroup.procs") as f:
            return [int(line) for line in f]
    except OSError:
        return []


def memory_stat(cgroup):
    wanted = {"anon", "file", "kernel", "shmem"}
    stat = {}
    with open(f"{cgroup}/memory.stat") as f:
        for line in f:
            name, value = line.split()
            if name in wanted:
                stat[name] = int(value) // 1024
    with open(f"{cgroup}/memory.current") as f:
        stat["current"] = int(f.read()) // 1024
    return stat


def read_events(cgroup):
    with open(f"{cgroup}/memory.events") as f:
        return {line.split()[0]: int(line.split()[1]) for line in f}


class Peaks:
    """memory.peak per phase. Since Linux 6.12, writing to memory.peak restarts the count for
    whoever holds that file descriptor, without touching the container's own."""

    def __init__(self, cgroups):
        self.cgroups = cgroups
        self.fds = {}
        self.restart()

    def restart(self):
        for fd in self.fds.values():
            os.close(fd)
        self.fds = {}
        for service, cgroup in self.cgroups.items():
            fd = os.open(f"{cgroup}/memory.peak", os.O_RDWR)
            os.write(fd, b"reset\n")
            self.fds[service] = fd

    def read(self):
        return {
            service: int(os.pread(fd, 64, 0)) // 1024 for service, fd in self.fds.items()
        }


def taskstats_listener(path, ready, cpus):
    """Writes one line per exit of a task process, from the kernel's taskstats exit records."""
    # generic netlink: find the TASKSTATS family, then register for exits on every CPU
    genl, ctrl_getfamily, ctrl_family_name, ctrl_family_id = 16, 3, 2, 1
    cmd_get, attr_register_cpumask = 1, 3
    aggr_pid, type_stats = 4, 3

    def attr(kind, value):
        length = 4 + len(value)
        return struct.pack("HH", length, kind) + value + b"\0" * (-length % 4)

    def message(family, command, body, seq):
        return (
            struct.pack("IHHII", 20 + len(body), family, 1, seq, 0)
            + struct.pack("BBH", command, 1, 0)
            + body
        )

    def attrs(data):
        at = 0
        while at + 4 <= len(data):
            length, kind = struct.unpack_from("HH", data, at)
            if length < 4:
                return
            yield kind & 0x3FFF, data[at + 4 : at + length]
            at += (length + 3) & ~3

    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, genl)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind((0, 0))
    sock.send(message(0x10, ctrl_getfamily, attr(ctrl_family_name, b"TASKSTATS\0"), 1))
    answer = sock.recv(65536)
    family = None
    for kind, value in attrs(answer[20:]):
        if kind == ctrl_family_id:
            family = struct.unpack("H", value[:2])[0]
    if family is None:
        raise SystemExit("the kernel has no taskstats")
    sock.send(
        message(family, cmd_get, attr(attr_register_cpumask, f"0-{cpus - 1}\0".encode()), 2)
    )
    ready.set()
    dropped = 0
    with open(path, "w", buffering=1) as out:
        print("# monotonic\tpid\tppid\texit_code\tlifetime_ms\tcpu_ms\tpeak_rss_kb\tpeak_vm_kb", file=out)
        while True:
            try:
                data = sock.recv(1 << 20)
            except OSError:
                dropped += 1
                print(f"# dropped after {time.monotonic()}: total {dropped}", file=out)
                continue
            now = time.monotonic()
            at = 0
            while at + 20 <= len(data):
                length = struct.unpack_from("I", data, at)[0]
                if length < 20:
                    break
                for kind, value in attrs(data[at + 20 : at + length]):
                    if kind != aggr_pid:
                        continue
                    for inner, stats in attrs(value):
                        if inner != type_stats or len(stats) < 216:
                            continue
                        # struct taskstats, include/uapi/linux/taskstats.h
                        comm = stats[80:112].split(b"\0")[0]
                        uid, _gid, pid, ppid = struct.unpack_from("IIII", stats, 120)
                        if comm != b"ace-parsers" or uid != TASK_UID:
                            continue
                        exit_code = struct.unpack_from("I", stats, 4)[0]
                        etime, utime, stime = struct.unpack_from("QQQ", stats, 144)
                        hiwater_rss, hiwater_vm = struct.unpack_from("QQ", stats, 200)
                        print(
                            f"{now:.3f}\t{pid}\t{ppid}\t{exit_code}\t{etime / 1000:.1f}\t"
                            f"{(utime + stime) / 1000:.1f}\t{hiwater_rss}\t{hiwater_vm}",
                            file=out,
                        )
                at += (length + 3) & ~3


def main(out_dir, phase_file, services):
    cgroups = {service: f"{CGROUP_ROOT}/{cid}" for service, cid in services.items()}
    for service, cgroup in cgroups.items():
        if not os.path.isdir(cgroup):
            raise SystemExit(f"no cgroup for {service}: {cgroup}")

    ready = multiprocessing.Event()
    listener = multiprocessing.Process(
        target=taskstats_listener,
        args=(f"{out_dir}/taskstats.tsv", ready, os.cpu_count()),
        daemon=True,
    )
    listener.start()
    if not ready.wait(10):
        raise SystemExit("taskstats didn't start")

    parsers = cgroups[PARSERS]
    limits = {}
    for service, cgroup in cgroups.items():
        with open(f"{cgroup}/memory.max") as f:
            limits[service] = f.read().strip()

    peaks = Peaks(cgroups)
    samples = open(f"{out_dir}/samples.tsv", "w")
    print("monotonic\tphase\tservice\trole\tprocs\tprivate_kb\tprivate_dirty_kb\tpss_kb\trss_kb\tanon_kb", file=samples)
    cgroup_rows = open(f"{out_dir}/cgroup.tsv", "w")
    print("monotonic\tphase\tservice\tcurrent_kb\tanon_kb\tfile_kb\tkernel_kb\tshmem_kb", file=cgroup_rows)
    peak_rows = open(f"{out_dir}/peaks.tsv", "w")
    print("phase\tservice\tpeak_kb\tlimit\tevents_max\tevents_oom\tevents_oom_kill", file=peak_rows)

    def role_of(service, pid):
        line = cmdline(pid)
        if not line or not line[0]:
            return None
        if "docker-init" in line[0]:
            return "init"
        if service != PARSERS:
            return "main"
        return "task" if line[1:2] == [TASK_ARG] else "supervisor"

    # the supervisor is the one running before any task; a task process between fork and exec
    # still has the supervisor's command line and memory, so anything else with that command
    # line isn't counted
    supervisor = None
    for pid in procs(parsers):
        if role_of(PARSERS, pid) == "supervisor":
            supervisor = pid
    if supervisor is None:
        raise SystemExit("no parser supervisor is running")

    tasks = {}
    tick_times = []
    pass_times = []
    pool_peak = {}
    latest_supervisor = rollup(supervisor) or {"private": 0, "private_dirty": 0, "pss": 0}
    concurrent = {}
    phase = "idle-before"
    phases = [[phase, time.monotonic()]]
    supervisor_hwm = {}
    next_slow = 0.0
    next_phase_check = 0.0

    def finish_phase(name):
        read = peaks.read()
        for service, peak in read.items():
            events = read_events(cgroups[service])
            print(
                f"{name}\t{service}\t{peak}\t{limits[service]}\t{events.get('max', 0)}\t"
                f"{events.get('oom', 0)}\t{events.get('oom_kill', 0)}",
                file=peak_rows,
            )

    while True:
        started = time.monotonic()
        if started >= next_phase_check:
            next_phase_check = started + 0.1
            try:
                with open(phase_file) as f:
                    wanted = f.read().strip()
            except OSError:
                wanted = phase
            if wanted and wanted != phase:
                finish_phase(phase)
                if wanted == "stop":
                    break
                phase = wanted
                phases.append([phase, started])
                peaks.restart()

        # the task processes, as fast as this loop goes
        pool_private = latest_supervisor["private"]
        pool_dirty = latest_supervisor["private_dirty"]
        pool_pss = latest_supervisor["pss"]
        running = 0
        for pid in procs(parsers):
            if pid == supervisor:
                continue
            task = tasks.get(pid)
            if task is None:
                if role_of(PARSERS, pid) != "task":
                    continue
                task = tasks[pid] = {
                    "first": started,
                    "last": started,
                    "phase": phase,
                    "samples": 0,
                    "private": 0,
                    "private_dirty": 0,
                    "pss": 0,
                    "rss": 0,
                    "anon": 0,
                    "hwm": 0,
                }
            figures = rollup(pid)
            if figures is None:
                continue
            hwm = peak_rss_so_far(pid)
            task["last"] = time.monotonic()
            task["samples"] += 1
            task["hwm"] = max(task["hwm"], hwm)
            for name in ("private", "private_dirty", "pss", "rss", "anon"):
                task[name] = max(task[name], figures[name])
            pool_private += figures["private"]
            pool_dirty += figures["private_dirty"]
            pool_pss += figures["pss"]
            running += 1
        current = pool_peak.setdefault(phase, {"private": 0, "private_dirty": 0, "pss": 0})
        current["private"] = max(current["private"], pool_private)
        current["private_dirty"] = max(current["private_dirty"], pool_dirty)
        current["pss"] = max(current["pss"], pool_pss)
        concurrent[phase] = max(concurrent.get(phase, 0), running)

        now = time.monotonic()
        tick_times.append(now - started)
        if now >= next_slow:
            next_slow = now + SLOW
            for service, cgroup in cgroups.items():
                totals = {}
                for pid in procs(cgroup):
                    role = role_of(service, pid)
                    if role is None or role == "task":
                        continue
                    if service == PARSERS and role == "supervisor" and pid != supervisor:
                        continue
                    figures = rollup(pid)
                    if figures is None:
                        continue
                    row = totals.setdefault(
                        role,
                        {"procs": 0, "private": 0, "private_dirty": 0, "pss": 0, "rss": 0, "anon": 0},
                    )
                    row["procs"] += 1
                    for name in ("private", "private_dirty", "pss", "rss", "anon"):
                        row[name] += figures[name]
                    if pid == supervisor:
                        latest_supervisor = figures
                        supervisor_hwm[phase] = peak_rss_so_far(pid)
                for role, row in totals.items():
                    print(
                        f"{now:.3f}\t{phase}\t{service}\t{role}\t{row['procs']}\t{row['private']}\t"
                        f"{row['private_dirty']}\t{row['pss']}\t{row['rss']}\t{row['anon']}",
                        file=samples,
                    )
                stat = memory_stat(cgroup)
                print(
                    f"{now:.3f}\t{phase}\t{service}\t{stat['current']}\t{stat['anon']}\t"
                    f"{stat['file']}\t{stat['kernel']}\t{stat['shmem']}",
                    file=cgroup_rows,
                )
            pass_times.append(time.monotonic() - now)

    # memory.peak read without a reset: since the container started
    for service, cgroup in cgroups.items():
        with open(f"{cgroup}/memory.peak") as f:
            peak = int(f.read()) // 1024
        events = read_events(cgroup)
        print(
            f"container-life\t{service}\t{peak}\t{limits[service]}\t{events.get('max', 0)}\t"
            f"{events.get('oom', 0)}\t{events.get('oom_kill', 0)}",
            file=peak_rows,
        )

    with open(f"{out_dir}/tasks.tsv", "w") as out:
        print("pid\tphase\tfirst\tlast\tsamples\tprivate_kb\tprivate_dirty_kb\tpss_kb\trss_kb\tanon_kb\thwm_kb", file=out)
        for pid, task in tasks.items():
            print(
                f"{pid}\t{task['phase']}\t{task['first']:.3f}\t{task['last']:.3f}\t{task['samples']}\t"
                f"{task['private']}\t{task['private_dirty']}\t{task['pss']}\t{task['rss']}\t{task['anon']}\t{task['hwm']}",
                file=out,
            )
    meta = {
        "phases": phases,
        "ticks": len(tick_times),
        "tick_ms_median": round(statistics.median(tick_times) * 1000, 3),
        "tick_ms_p99": round(sorted(tick_times)[int(len(tick_times) * 0.99)] * 1000, 3),
        "slow_pass_ms_median": round(statistics.median(pass_times) * 1000, 3) if pass_times else None,
        "parsers_pool_peak_kb": pool_peak,
        "parsers_concurrent_tasks": concurrent,
        "supervisor_pid": supervisor,
        "supervisor_vmhwm_kb": supervisor_hwm,
    }
    with open(f"{out_dir}/meta.json", "w") as f:
        json.dump(meta, f, indent=2)
    for file in (samples, cgroup_rows, peak_rows):
        file.close()
    listener.terminate()


if __name__ == "__main__":
    pairs = dict(arg.split("=", 1) for arg in sys.argv[3:])
    main(sys.argv[1], sys.argv[2], pairs)
