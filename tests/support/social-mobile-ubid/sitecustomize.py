try:
    import json
    import os
    from pathlib import Path
    import sys

    output = Path(os.environ["UBID_TEST_OUTPUT"]).absolute()
    allowed = (output / "temp", output / "pytest-temp")

    def audit(event, arguments):
        if event != "sqlite3.connect":
            return
        target = arguments[0]
        if target == ":memory:":
            return
        raw = os.fspath(target)
        denied = not isinstance(raw, str) or ":" in raw or ".." in Path(raw).parts or not Path(raw).is_absolute()
        path = Path(raw).absolute() if isinstance(raw, str) else Path("/denied")
        if not any(path.is_relative_to(root) for root in allowed):
            denied = True
        if not denied and any(part.is_symlink() for part in (path, *path.parents)):
            denied = True
        if denied:
            with (output / "denied-sqlite-targets.jsonl").open("a") as log:
                log.write(json.dumps({"event": event, "target": str(path)}) + "\n")
            raise PermissionError("non-disposable SQLite target denied")

    sys.addaudithook(audit)

    # Exact Unix destination and SQLite policy also apply to Python subprocesses.
    def network_audit(event, arguments):
        if event == 'socket.connect':
            target = arguments[1]
            permitted = os.environ.get('UBID_TEST_ALLOWED_SOCKET', '')
            if not permitted or not isinstance(target, str) or target not in permitted.split('|'):
                raise PermissionError('non-disposable network target denied')
    sys.addaudithook(network_audit)

    # Preserve isolation even when a test deliberately constructs a fresh
    # child environment (the repository's standalone probe tests do this).
    guard_directory = str(Path(__file__).resolve().parent)
    def child_guard(event, arguments):
        if event == 'subprocess.Popen':
            environment = arguments[3]
        elif event == 'os.exec':
            environment = arguments[2]
        else:
            return
        if environment is not None:
            for name in ('LD_PRELOAD', 'UBID_TEST_OUTPUT', 'UBID_TEST_ALLOWED_SOCKET'):
                environment[name] = os.environ[name]
            environment['PYTHONDONTWRITEBYTECODE'] = '1'
            environment['PYTHON_DOTENV_DISABLED'] = '1'
            paths = environment.get('PYTHONPATH', '').split(os.pathsep)
            environment['PYTHONPATH'] = os.pathsep.join([guard_directory] + [p for p in paths if p and p != guard_directory])
    sys.addaudithook(child_guard)

    # Self-test the policy before any application/pytest/diagnostic import.
    import sqlite3
    import socket
    scratch = output / 'temp'
    scratch.mkdir(exist_ok=True)
    link = scratch / ('guard-link-' + str(os.getpid()))
    link.symlink_to('/srv/ubid')
    try:
        negative = ('/srv/ubid/ubid.db', 'file:/srv/ubid/ubid.db?mode=ro',
                    str(scratch / '..' / 'escape.db'), str(link / 'ubid.db'), 'ubid.db')
        for target in negative:
            try:
                sqlite3.connect(target)
            except PermissionError:
                pass
            else:
                raise RuntimeError('SQLite isolation self-test failed')
        with sqlite3.connect(':memory:') as db:
            assert db.execute('select 1').fetchone() == (1,)
        with sqlite3.connect(str(scratch / ('guard-' + str(os.getpid()) + '.db'))) as db:
            assert db.execute('select 1').fetchone() == (1,)
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                sock = socket.socket(family)
            except PermissionError:
                pass
            else:
                sock.close()
                raise RuntimeError('IP syscall isolation self-test failed')
        with socket.socket(socket.AF_UNIX) as sock:
            try:
                sock.connect('/tmp/forbidden-isolation-probe')
            except PermissionError:
                pass
            else:
                raise RuntimeError('Unix isolation self-test failed')
        with (output / 'pre-import-guard.jsonl').open('a') as log:
            log.write(json.dumps({'pid': os.getpid(), 'sqlite_negative': 5, 'ip_negative': 2, 'unix_negative': 1, 'before_app_import': 'app' not in sys.modules}) + '\n')
    finally:
        link.unlink()

    # Prove the libc/libpq connect interceptor itself, before diagnostic imports.
    import ctypes
    class Address(ctypes.Structure):
        _fields_ = [('family', ctypes.c_ushort), ('path', ctypes.c_char * 108)]
    libc = ctypes.CDLL(None, use_errno=True)
    address = Address(socket.AF_UNIX, b'/tmp/forbidden-native-isolation-probe')
    with socket.socket(socket.AF_UNIX) as sock:
        result = libc.connect(sock.fileno(), ctypes.byref(address), ctypes.sizeof(address))
        assert result == -1 and ctypes.get_errno() == 1, 'native connect guard missing'
except BaseException:
    import os
    os.write(2, b"ISOLATION_STARTUP_FAILED\n")
    os._exit(78)
