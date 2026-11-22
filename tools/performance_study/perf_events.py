"""Count selected process I/O and scheduling events in a separate Linux diagnostic window."""
from contextlib import contextmanager
import signal
import subprocess
import time


@contextmanager
def count_events(folder, pid, executable="perf", completed_splices=False):
    calls = ("read", "readv", "write", "writev", "recvfrom", "recvmsg", "recvmmsg", "sendto",
             "sendmsg", "sendmmsg", "splice", "epoll_pwait", "epoll_pwait2", "ppoll", "pselect6")
    events = ["task-clock", "context-switches", *(f"syscalls:sys_enter_{call}" for call in calls)]
    select = ["-e", ",".join(events)]
    if completed_splices:
        select += ["-e", "syscalls:sys_exit_splice", "--filter", "ret > 0"]
    path = folder / "perf-stat.csv"
    with (folder / "perf-stat.log").open("w") as err:
        proc = subprocess.Popen([executable,"stat","--no-big-num","-x",",","-o",str(path),"-p",str(pid),
                                 *select],stderr=err)
        try:
            time.sleep(.15)
            if proc.poll() is not None:
                raise RuntimeError(f"perf stat failed to attach, see {err.name}")
            yield
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
