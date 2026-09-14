import atexit
import faulthandler
import signal
import json
import os
from pathlib import Path
import sqlite3
import sys

assert "sitecustomize" in sys.modules
out = Path(os.environ["UBID_TEST_OUTPUT"])
scratch = out / "temp"
link = scratch / "escape"
link.symlink_to("/srv/ubid")
for target in ("/srv/ubid/ubid.db", "file:/srv/ubid/ubid.db?mode=ro", str(scratch / ".." / "escape.db"), str(link / "ubid.db"), "ubid.db"):
    try:
        sqlite3.connect(target)
    except PermissionError:
        pass
    else:
        raise RuntimeError("SQLite guard failed before pytest import")
link.unlink()
with sqlite3.connect(":memory:") as db:
    assert db.execute("select 1").fetchone() == (1,)
with sqlite3.connect(str(scratch / "guard-self-test.db")) as db:
    assert db.execute("select 1").fetchone() == (1,)
(out / "guard-self-tests.json").write_text(json.dumps({"sqlite_before_pytest_import": True, "forbidden_paths_denied_before_open": 5, "memory_and_scratch_allowed": True}) + "\n")
stack_log = (out / "shutdown-stacks.log").open("w")
faulthandler.register(signal.SIGUSR1, file=stack_log, all_threads=True)
if os.environ.get('UBID_TRACE_EXCEPTIONS') == '1':
    def trace(frame, event, arg):
        filename = frame.f_code.co_filename
        if event == 'exception' and '/app/services/' in filename:
            with (out / 'exception-locations.log').open('a') as log:
                log.write(f'{Path(filename).name}:{frame.f_lineno} {frame.f_code.co_name} {arg[0].__name__}\n')
        return trace
    sys.settrace(trace)
import pytest

class Inventory:
    def __init__(self):
        self.reports = []
        self.deselected = []
    def pytest_runtest_logreport(self, report):
        self.reports.append({"nodeid":report.nodeid,"when":report.when,"outcome":report.outcome})
    def pytest_deselected(self, items):
        self.deselected.extend(item.nodeid for item in items)
    def pytest_sessionfinish(self, session, exitstatus):
        (out / "test-inventory.json").write_text(json.dumps({"collected":session.testscollected,
            "deselected":self.deselected,"reports":self.reports,"pytest_return":int(exitstatus)}, indent=2))
exit_code = int(pytest.main(sys.argv[1:], plugins=[Inventory()]))
sys.stdout.flush()
sys.stderr.flush()
atexit._run_exitfuncs()
(out / "pytest-exit.json").write_text(json.dumps({"pytest_exit_code": exit_code, "pytest_teardown_complete": True, "registered_cleanup_complete": True}) + "\n")
sys.stdout.flush()
sys.stderr.flush()
raise SystemExit(exit_code)
