#!/usr/bin/env python3
"""Probe battery run *inside* the sandboxed transient unit spawned by
cli.py (via `systemd-run --pipe ... python3 -`, fed on stdin).

Talks back to the host only through stdout (one JSON object per line) and
reads its config from the HARDEN_CONFIG / HOST_* environment variables set
by cli.py via --setenv. Every probe is self-contained and chosen to never
affect host state even if a restriction turns out not to be enforced
(no reboot/mount/settimeofday/module-load syscalls -- those are only checked
indirectly via capability bitmasks).
"""
import ctypes
import json
import mmap
import os
import socket
import stat
import tempfile

PASS, FAIL, WARN, INFO = "PASS", "FAIL", "WARN", "INFO"
CFG = json.loads(os.environ.get("HARDEN_CONFIG", "{}"))
CAP_BIT = {
    "CAP_SETGID": 6, "CAP_SETUID": 7, "CAP_NET_BIND_SERVICE": 10,
    "CAP_NET_ADMIN": 12, "CAP_NET_RAW": 13, "CAP_SYS_MODULE": 16,
    "CAP_SYS_PTRACE": 19, "CAP_SYS_ADMIN": 21, "CAP_SYS_BOOT": 22,
    "CAP_SYS_TIME": 25, "CAP_WAKE_ALARM": 35,
}
libc = ctypes.CDLL("libc.so.6", use_errno=True)


def emit(check, directive, status, detail):
    print(json.dumps({"check": check, "directive": directive, "status": status, "detail": detail}), flush=True)


def cfg(name):
    return CFG.get(name)


def cap_bitmask(field):
    for line in open("/proc/self/status"):
        if line.startswith(field + ":"):
            return int(line.split()[1], 16)
    return 0


def cap_present(name, field="CapBnd"):
    return bool(cap_bitmask(field) & (1 << CAP_BIT[name]))


def try_create_and_remove(path):
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        os.remove(path)
        return True, None
    except OSError as exc:
        return False, str(exc)


def try_open_existing(path, flags):
    try:
        fd = os.open(path, flags)
        os.close(fd)
        return True, None
    except OSError as exc:
        return False, str(exc)


def blocked_result(directive, truthy_values, observed_blocked, check, detail_ok, detail_bad):
    val = cfg(directive)
    if val is None:
        return INFO, f"{directive} not set in unit; observed: {'blocked' if observed_blocked else 'allowed'}"
    if val.lower() in truthy_values:
        return (PASS, detail_ok) if observed_blocked else (FAIL, detail_bad)
    return INFO, f"{directive}={val}; observed: {'blocked' if observed_blocked else 'allowed'}"


# 1. NoNewPrivileges
nnp = "0"
for line in open("/proc/self/status"):
    if line.startswith("NoNewPrivs:"):
        nnp = line.split()[1]
status, detail = blocked_result("NoNewPrivileges", ("true",), nnp == "1", "no_new_privileges",
                                 "NoNewPrivs flag is set", "NoNewPrivs flag NOT set despite NoNewPrivileges=true")
emit("no_new_privileges", "NoNewPrivileges", status, detail)

# 2. ProtectSystem: /usr must not be writable
ok, err = try_create_and_remove(f"/usr/.minicms-harden-{os.getpid()}")
status, detail = blocked_result("ProtectSystem", ("strict", "full", "true"), not ok,
                                 "protect_system", "/usr is not writable", f"/usr IS writable ({err or 'no error'})")
emit("protect_system_usr_rw", "ProtectSystem", status, detail)

# 3. ReadWritePaths positive control
rwp = cfg("ReadWritePaths")
if rwp:
    target = rwp.split()[0]
    if os.path.isdir(target):
        ok, err = try_create_and_remove(os.path.join(target, f".minicms-harden-{os.getpid()}"))
        status = PASS if ok else FAIL
        detail = f"{target} writable as expected" if ok else f"{target} NOT writable ({err}) -- over-restrictive?"
        emit("readwritepaths_rw", "ReadWritePaths", status, detail)
    else:
        emit("readwritepaths_rw", "ReadWritePaths", WARN, f"{target} does not exist, skipped")

# 4. ProtectHome: /root must be inaccessible
try:
    os.listdir("/root")
    accessible = True
except OSError:
    accessible = False
status, detail = blocked_result("ProtectHome", ("true", "read-only", "tmpfs"), not accessible,
                                 "protect_home", "/root is inaccessible", "/root IS accessible")
emit("protect_home", "ProtectHome", status, detail)

# 5. PrivateTmp: /tmp mount should come from a systemd-private-* source
private_tmp = False
try:
    for line in open("/proc/self/mountinfo"):
        parts = line.split()
        if len(parts) > 4 and parts[4] == "/tmp" and "systemd-private" in line:
            private_tmp = True
            break
except OSError:
    pass
status, detail = blocked_result("PrivateTmp", ("true",), private_tmp,
                                 "private_tmp", "/tmp is a private systemd-private mount",
                                 "/tmp does NOT look like a private mount (heuristic)")
emit("private_tmp", "PrivateTmp", status, detail)

# 6. PrivateDevices: /dev/sda should not exist; /dev/null must still work
sda_exists = os.path.exists("/dev/sda")
status, detail = blocked_result("PrivateDevices", ("true",), not sda_exists,
                                 "private_devices", "/dev/sda not visible", "/dev/sda IS visible")
emit("private_devices", "PrivateDevices", status, detail)
null_ok, _ = try_open_existing("/dev/null", os.O_RDONLY)
emit("private_devices_null_control", "PrivateDevices", PASS if null_ok else WARN,
     "/dev/null accessible" if null_ok else "/dev/null NOT accessible -- likely over-restrictive")

# 7. ProtectKernelTunables: /proc/sys/vm/swappiness must not be writable
ok, err = try_open_existing("/proc/sys/vm/swappiness", os.O_RDWR)
status, detail = blocked_result("ProtectKernelTunables", ("true",), not ok,
                                 "protect_kernel_tunables", "/proc/sys/vm/swappiness not writable",
                                 f"/proc/sys/vm/swappiness IS writable ({err or 'no error'})")
emit("protect_kernel_tunables", "ProtectKernelTunables", status, detail)

# 8. ProtectKernelModules: CAP_SYS_MODULE must be gone from the bounding set
has_cap = cap_present("CAP_SYS_MODULE")
status, detail = blocked_result("ProtectKernelModules", ("true",), not has_cap,
                                 "protect_kernel_modules", "CAP_SYS_MODULE absent from CapBnd",
                                 "CAP_SYS_MODULE still present in CapBnd")
emit("protect_kernel_modules", "ProtectKernelModules", status, detail)

# 9. ProtectKernelLogs: /dev/kmsg must not be openable
ok, err = try_open_existing("/dev/kmsg", os.O_RDONLY)
status, detail = blocked_result("ProtectKernelLogs", ("true",), not ok,
                                 "protect_kernel_logs", "/dev/kmsg not accessible",
                                 f"/dev/kmsg IS accessible ({err or 'no error'})")
emit("protect_kernel_logs", "ProtectKernelLogs", status, detail)

# 10. ProtectControlGroups: /sys/fs/cgroup must not be writable
ok, err = try_create_and_remove(f"/sys/fs/cgroup/.minicms-harden-{os.getpid()}")
status, detail = blocked_result("ProtectControlGroups", ("true",), not ok,
                                 "protect_control_groups", "/sys/fs/cgroup not writable",
                                 f"/sys/fs/cgroup IS writable ({err or 'no error'})")
emit("protect_control_groups", "ProtectControlGroups", status, detail)

# 11. ProtectClock: CAP_SYS_TIME / CAP_WAKE_ALARM must be gone
has_time_cap = cap_present("CAP_SYS_TIME") or cap_present("CAP_WAKE_ALARM")
status, detail = blocked_result("ProtectClock", ("true",), not has_time_cap,
                                 "protect_clock", "CAP_SYS_TIME/CAP_WAKE_ALARM absent",
                                 "CAP_SYS_TIME or CAP_WAKE_ALARM still present")
emit("protect_clock", "ProtectClock", status, detail)

# 12. ProtectHostname: private UTS namespace (inode differs from host baseline)
host_uts_ino = os.environ.get("HOST_NS_UTS_INO")
try:
    self_uts_ino = str(os.stat("/proc/self/ns/uts").st_ino)
    private_uts = host_uts_ino is not None and self_uts_ino != host_uts_ino
except OSError:
    private_uts = False
status, detail = blocked_result("ProtectHostname", ("true",), private_uts,
                                 "protect_hostname", "private UTS namespace (differs from host)",
                                 "UTS namespace matches host -- hostname changes would propagate")
emit("protect_hostname", "ProtectHostname", status, detail)

# 13. ProtectProc: /proc/1 must not be visible
try:
    os.listdir("/proc/1")
    pid1_visible = True
except OSError:
    pid1_visible = False
status, detail = blocked_result("ProtectProc", ("invisible", "noaccess", "restricted"), not pid1_visible,
                                 "protect_proc", "/proc/1 not visible", "/proc/1 IS visible")
emit("protect_proc", "ProtectProc", status, detail)

# 14. RestrictNamespaces: unshare(CLONE_NEWNS) must fail (self-contained, no host effect)
CLONE_NEWNS = 0x00020000
rc = libc.unshare(ctypes.c_int(CLONE_NEWNS))
status, detail = blocked_result("RestrictNamespaces", ("true", "yes"), rc != 0,
                                 "restrict_namespaces", "unshare(CLONE_NEWNS) blocked",
                                 "unshare(CLONE_NEWNS) SUCCEEDED")
emit("restrict_namespaces", "RestrictNamespaces", status, detail)

# 15. RestrictRealtime: SCHED_FIFO must be refused (affects only this dying process)
try:
    os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(1))
    rt_blocked = False
except (PermissionError, OSError):
    rt_blocked = True
status, detail = blocked_result("RestrictRealtime", ("true",), rt_blocked,
                                 "restrict_realtime", "SCHED_FIFO refused", "SCHED_FIFO was granted")
emit("restrict_realtime", "RestrictRealtime", status, detail)

# 16. RestrictSUIDSGID: chmod +s on our own temp file must fail
with tempfile.NamedTemporaryFile(delete=False) as tf:
    tmp_path = tf.name
try:
    os.chmod(tmp_path, 0o4755)
    suid_blocked = False
except (PermissionError, OSError):
    suid_blocked = True
finally:
    os.remove(tmp_path)
status, detail = blocked_result("RestrictSUIDSGID", ("true",), suid_blocked,
                                 "restrict_suidsgid", "chmod +s refused", "chmod +s SUCCEEDED")
emit("restrict_suidsgid", "RestrictSUIDSGID", status, detail)

# 17. RestrictAddressFamilies: AF_NETLINK must fail, AF_INET must still work
raf = cfg("RestrictAddressFamilies")
try:
    socket.socket(socket.AF_NETLINK, socket.SOCK_RAW).close()
    netlink_blocked = False
except OSError:
    netlink_blocked = True
if raf:
    status = PASS if netlink_blocked and "AF_NETLINK" not in raf.split() else \
        (INFO if "AF_NETLINK" in raf.split() and not netlink_blocked else FAIL)
    detail = "AF_NETLINK blocked as expected" if netlink_blocked else "AF_NETLINK socket creation SUCCEEDED"
else:
    status, detail = INFO, f"RestrictAddressFamilies not set; AF_NETLINK {'blocked' if netlink_blocked else 'allowed'}"
emit("restrict_af_netlink", "RestrictAddressFamilies", status, detail)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.close()
    inet_ok = True
except OSError:
    inet_ok = False
emit("restrict_af_inet_control", "RestrictAddressFamilies", PASS if inet_ok else WARN,
     "AF_INET still works" if inet_ok else "AF_INET socket creation FAILED -- over-restrictive")

# 18. LockPersonality: changing personality flags must fail
ADDR_NO_RANDOMIZE = 0x0040000
rc = libc.personality(ctypes.c_ulong(ADDR_NO_RANDOMIZE))
status, detail = blocked_result("LockPersonality", ("true",), rc == -1,
                                 "lock_personality", "personality() change refused", "personality() change SUCCEEDED")
emit("lock_personality", "LockPersonality", status, detail)

# 19. MemoryDenyWriteExecute: anonymous RWX mapping must fail
try:
    m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    m.close()
    mdwe_blocked = False
except PermissionError:
    mdwe_blocked = True
status, detail = blocked_result("MemoryDenyWriteExecute", ("true",), mdwe_blocked,
                                 "memory_deny_write_execute", "RWX mmap refused", "RWX mmap SUCCEEDED")
emit("memory_deny_write_execute", "MemoryDenyWriteExecute", status, detail)

# 20. CapabilityBoundingSet / AmbientCapabilities
cbs = cfg("CapabilityBoundingSet")
if cbs:
    expected = 0
    for name in cbs.split():
        expected |= (1 << CAP_BIT[name]) if name in CAP_BIT else 0
    observed = cap_bitmask("CapBnd")
    status = PASS if observed == expected else FAIL
    detail = f"CapBnd=0x{observed:x} expected=0x{expected:x} ({cbs})"
else:
    detail = f"CapabilityBoundingSet not set; CapBnd=0x{cap_bitmask('CapBnd'):x}"
    status = INFO
emit("capability_bounding_set", "CapabilityBoundingSet", status, detail)

# positive control: if AmbientCapabilities grants CAP_NET_BIND_SERVICE, binding
# a privileged port as non-root should succeed (or fail only with EADDRINUSE)
if cfg("AmbientCapabilities") and "CAP_NET_BIND_SERVICE" in cfg("AmbientCapabilities").split():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", 80))
        s.close()
        emit("ambient_cap_net_bind_service", "AmbientCapabilities", PASS, "bind(80) succeeded")
    except PermissionError:
        emit("ambient_cap_net_bind_service", "AmbientCapabilities", FAIL, "bind(80) DENIED despite AmbientCapabilities")
    except OSError as exc:
        emit("ambient_cap_net_bind_service", "AmbientCapabilities", PASS, f"bind(80) got past permission check ({exc})")

# 21. UMask
umask_cfg = cfg("UMask")
with tempfile.NamedTemporaryFile(delete=False) as tf:
    path = tf.name
mode = stat.S_IMODE(os.stat(path).st_mode)
os.remove(path)
if umask_cfg:
    expected_mask = int(umask_cfg, 8)
    expected_mode = 0o666 & ~expected_mask
    status = PASS if mode == expected_mode else WARN
    detail = f"file created with mode 0o{mode:o}, expected 0o{expected_mode:o} for UMask={umask_cfg}"
else:
    status, detail = INFO, f"UMask not set; file created with mode 0o{mode:o}"
emit("umask", "UMask", status, detail)

# 22. Seccomp -- intentionally not exercised live (see note in host script)
if cfg("SystemCallFilter"):
    emit("syscall_filter", "SystemCallFilter", INFO, "not dynamically probed for safety; see systemd-analyze security")
if cfg("SystemCallArchitectures"):
    emit("syscall_architectures", "SystemCallArchitectures", INFO, "not dynamically probed; see systemd-analyze security")
