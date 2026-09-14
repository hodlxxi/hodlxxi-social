"""Explicit isolated pinned integration runner; never imported by Node discovery."""
import argparse, ctypes, json, os, shutil, subprocess, tempfile, time, signal
from pathlib import Path
class ArgCmp(ctypes.Structure):
    _fields_ = [('arg', ctypes.c_uint), ('op', ctypes.c_int), ('a', ctypes.c_uint64), ('b', ctypes.c_uint64)]

SECCOMP = ctypes.CDLL('libseccomp.so.2', use_errno=True)
SECCOMP.seccomp_init.argtypes = [ctypes.c_uint32]
SECCOMP.seccomp_init.restype = ctypes.c_void_p
SECCOMP.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
SECCOMP.seccomp_syscall_resolve_name.restype = ctypes.c_int
SECCOMP.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint, ctypes.POINTER(ArgCmp)]
SECCOMP.seccomp_load.argtypes = [ctypes.c_void_p]
SECCOMP.seccomp_release.argtypes = [ctypes.c_void_p]

def deny_ip_sockets():
    ctx = SECCOMP.seccomp_init(0x7fff0000)
    if not ctx:
        raise RuntimeError('Cannot establish offline syscall guard')
    try:
        call = SECCOMP.seccomp_syscall_resolve_name(b'socket')
        assert call >= 0
        for family in (2, 10):
            comparison = ArgCmp(0, 4, family, 0)
            assert SECCOMP.seccomp_rule_add_array(ctx, 0x00050001, call, 1, ctypes.byref(comparison)) == 0
        assert SECCOMP.seccomp_load(ctx) == 0
    finally:
        SECCOMP.seccomp_release(ctx)


HERE = Path(__file__).resolve().parent
SOCIAL = HERE.parents[2]
PIN = "a8c409dbe4c900cc8f99c08346cd15bf83604336"
REFERENCE = Path("/srv/ubid-social-session-issuance-v1")
PYTHON = "/srv/ubid-staging/venv/bin/python"
PG = "/usr/lib/postgresql/16/bin/"
parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True)
parser.add_argument("--only-js", action="store_true")
args = parser.parse_args()
out = Path(args.output).absolute()
out.mkdir(mode=0o700)  # exclusive: preserve every prior attempt
scratch = Path(tempfile.mkdtemp(prefix="social-2b-synthetic-"))
archive = scratch / "reference"
archive.mkdir()
subprocess.run(["git", "-C", str(REFERENCE), "cat-file", "-e", PIN + "^{commit}"], check=True)
with (scratch / "reference.tar").open("wb") as f:
    subprocess.run(["git", "-C", str(REFERENCE), "archive", PIN], stdout=f, check=True)
subprocess.run(["tar", "-xf", str(scratch / "reference.tar"), "-C", str(archive)], check=True)
shutil.copyfile(HERE / "bridge_case.py", archive / "tests/integration/test_social_phase2b_consumer.py")
env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "PYTHON_DOTENV_DISABLED": "1"}
result = {"contract": PIN, "source_archive_owned": True}
started = False
pgroot = None
try:
    pgroot = Path(subprocess.check_output(["/usr/sbin/runuser", "-u", "postgres", "--", "mktemp", "-d", "/tmp/social-2b-pg-XXXXXXXX"], env=env, text=True).strip())
    assert pgroot.parent == Path("/tmp") and pgroot.name.startswith("social-2b-pg-")
    data, sock, port = pgroot / "data", pgroot / "socket", "56519"
    def pg_run(argv):
        with (out / "cluster-commands.log").open("a") as log:
            subprocess.run(["/usr/sbin/runuser", "-u", "postgres", "--", *argv], env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=40)
    pg_run(["mkdir", str(sock)])
    pg_run([PG + "initdb", "-D", str(data), "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=reject"])
    pg_run([PG + "pg_ctl", "-D", str(data), "-l", str(pgroot / "postgres.log"), "-o", f"-k {sock} -p {port} -c listen_addresses='' -c fsync=off", "-w", "start"])
    started = True
    postmaster = int((data / "postmaster.pid").read_text().splitlines()[0])
    pg_run([PG + "createdb", "-h", str(sock), "-p", port, "hodlxxi_social_binding_authorization_test"])
    result["target"] = {"data": str(data), "socket": str(sock), "port": port, "postmaster": postmaster, "listen_addresses": ""}
    subprocess.run(["/usr/bin/cc", "-shared", "-fPIC", "-o", str(scratch / "offline.so"), str(HERE / "offline.c"), "-ldl"], env=env, check=True)
    (out / "temp").mkdir()
    bridge_socket, social_socket = str(scratch / "ubid.sock"), str(scratch / "social.sock")
    testenv = {**env, "PATH": str(Path(PYTHON).parent) + ":/usr/bin:/bin", "TMPDIR": str(out / "temp"),
      "UBID_TEST_OUTPUT": str(out), "PYTHONPATH": str(HERE) + ":" + str(archive),
      "LD_PRELOAD": str(scratch / "offline.so"), "UBID_TEST_ALLOWED_SOCKET": "|".join([str(sock / (".s.PGSQL." + port)), bridge_socket, social_socket]),
      "GIT_DIR": subprocess.check_output(["git", "-C", str(REFERENCE), "rev-parse", "--absolute-git-dir"], text=True).strip(),
      "SOCIAL_SOURCE": str(SOCIAL), "SOCIAL_UBID_SOCKET": bridge_socket, "SOCIAL_TEST_SOCKET": social_socket,
      "TESTING": "1", "FLASK_ENV": "testing", "DATABASE_URL": "sqlite:///:memory:", "DISABLE_FORCE_HTTPS": "1", "RATE_LIMIT_ENABLED": "false", "REDIS_REQUIRED": "false",
      "HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_DSN": f"postgresql+psycopg2://postgres@/hodlxxi_social_binding_authorization_test?host={sock}&port={port}",
      "HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_ACK": "DISPOSABLE-SOCIAL-BINDING-AUTHORIZATION-POSTGRES-V1",
      "HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_DATA": str(data), "HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_SOCKET": str(sock), "HODLXXI_SOCIAL_BINDING_AUTHORIZATION_POSTGRES_PORT": port}
    subprocess.run([PYTHON, "-c", "import sitecustomize"], env=testenv, cwd=archive, check=True, preexec_fn=deny_ip_sockets, timeout=15)
    command = [PYTHON, str(HERE / "pytest-entry.py"), "-p", "no:cacheprovider", "-q", "-ra", "--tb=short", "--basetemp=" + str(out / "pytest-temp"), "tests/integration/test_social_phase2b_consumer.py"]
    if args.only_js: command += ["-k", "test_real_javascript_browser_bff_ubid"]
    result["command"] = command
    with (out / "pytest.log").open("w") as log:
        process = subprocess.Popen(command, cwd=archive, env=testenv, stdout=log, stderr=subprocess.STDOUT, preexec_fn=deny_ip_sockets)
        result["pid"] = process.pid
        start, completed = time.monotonic(), None
        while process.poll() is None:
            if (out / "pytest-exit.json").exists() and completed is None: completed = time.monotonic()
            if time.monotonic() - start > 180 or completed and time.monotonic() - completed > 20:
                result["timeout"] = "suite" if completed is None else "interpreter-shutdown"
                process.send_signal(signal.SIGUSR1)
                time.sleep(0.2)
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
                break
            time.sleep(0.2)
        result["process_exit_code"] = process.returncode
        result["normal_shutdown"] = "timeout" not in result
        marker = out / "pytest-exit.json"
        result["pytest_exit_code"] = json.loads(marker.read_text())["pytest_exit_code"] if marker.exists() else None
finally:
    if started:
        pg_run([PG + "pg_ctl", "-D", str(data), "-m", "fast", "-w", "stop"])
        result["postmaster_pid_absent"] = not Path("/proc", str(postmaster)).exists()
    if pgroot:
        shutil.rmtree(pgroot)
        result["cluster_removed"] = not pgroot.exists()
    shutil.rmtree(scratch)
    # Remove synthetic SQLite, generated test JWKS and pytest cache after shutdown.
    for name in ("temp", "pytest-temp"):
        if (out / name).exists(): shutil.rmtree(out / name)
    result["scratch_removed"] = not scratch.exists()
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
raise SystemExit(0 if result.get("pytest_exit_code") == 0 and result.get("process_exit_code") == 0 and result.get("normal_shutdown") else 1)
