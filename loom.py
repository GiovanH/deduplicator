#!/bin/python3
"""Summary
"""

from time import sleep
import threading

necessary_threads = 1


def extraThreads():
    """Returns:
        int: Number of threads, not including main.
    """
    return threading.active_count() - necessary_threads


def threadWait(threshhold=0, interval=1, quiet=True, use_pbar=True):
    """Wait for threads to complete.

    Args:
        threshhold (int): Wait until at most X extra threads exist.
        interval (int, optional): Seconds between checking thread status
        quiet (bool, optional): Print detailed thread status
        use_pbar (bool, optional): Show progressbar
    """
    if threshhold < 0:
        # Short circuit
        return

    pbar = None
    if use_pbar and (extraThreads() > threshhold):
        import progressbar
        _max = extraThreads() - threshhold
        print("Finishing {} background jobs.".format(_max))
        pbar = progressbar.ProgressBar(max_value=_max, redirect_stdout=True)

    while (extraThreads() > threshhold):
        c = extraThreads() - threshhold

        if pbar:
            pbar.update(_max - c)

        if not quiet:
            print("Waiting for {} job{} to finish:".format(c, "s" if c > 1 else ""))
            print(threading.enumerate())

        sleep(interval)

    if pbar:
        pbar.finish()


def thread(target, *args, **kwargs):
    """Initialize and start a thread

    Args:
        target (function): Task to complete
        *args: Passthrough to threading.Thread
        **kwargs: threading.Thread
    """
    t = threading.Thread(target=target, *args, **kwargs)
    t.start()


class Spool(object):

    """A spool is a queue of threads.
    This is a simple way of making sure you aren't running too many threads at one time.
    At intervals, determined by `delay`, the spooler (if on) will start threads from the queue.
    The spooler can start multiple threads at once.

    Attributes:
        delay (num): How long to wait between waves
        start (bool): Start spooling when created, y/n.
        cverbose (bool): If called as a context manager, verbose finish.
        cverbose (bool): If called as a context manager, finish with progress bar.
    """

    def __init__(self, quota, delay=1, start=False, cverbose=False, cpbar=False):
        super(Spool, self).__init__()
        self.queue = []
        self.running_threads = []
        self.quota = quota
        self.delay = delay
        self.background_spool = False
        self.flushlock = False

        self.cverbose = cverbose
        self.cpbar = cpbar

        if start:
            self.start()

    def start(self):
        """Begin spooling threads, if not already doing so. 
        """
        if not self.background_spool:
            self.background_spool = True
            self.spoolThread = threading.Thread(target=self.spool, name="Spooler")
            self.spoolThread.start()

    def __str__(self):
        return "<{} at {}: {} threads queued, {}/{} currently running>".format(type(self), hex(id(self)), len(self.queue), self.getNoRunningThreads(), self.quota)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, type, value, traceback):
        self.finish(resume=False, verbose=self.cverbose, use_pbar=self.cpbar)

    def spool(self, verbose=False, use_pbar=False, delay=None):
        """Periodically start additional threads, if we have the resources to do so.
        This function is intended to be run as a thread.
        If run as a blocking call, self.background_spool should be False, in order to allow peaceful termination. 

        Args:
            verbose (bool, optional): Report progress towards queue completion.
            use_pbar (bool, optional): Graphically display progress towards queue completion.
            delay (num): Optionally override the normal delay.
        """
        if delay is None:
            delay = self.delay

        pbar = None
        if use_pbar and len(self.queue) > 0:
            import progressbar
            _max = len(self.queue)
            pbar = progressbar.ProgressBar(max_value=_max, redirect_stdout=True)

        while self.background_spool or len(self.queue) > 0:
            if self.flushlock and self.getNoRunningThreads() == 0:
                self.flushlock = False
            if not self.flushlock:
                while len(self.queue) > 0 and (self.getNoRunningThreads() < self.quota):
                    newThread = self.queue.pop(0)
                    self.running_threads.append(newThread)
                    newThread.start()
            if verbose:
                print(self.running_threads)
                print("{} threads queued, {}/{} currently running.".format(len(self.queue), self.getNoRunningThreads(), self.quota))
            if pbar and use_pbar:
                pbar.update(_max - len(self.queue))
            sleep(delay)

        if pbar and use_pbar:
            pbar.finish()
        self.background_spool = False

    def flush(self):
        self.flushlock = True

    def enqueue(self, target, *args, **kwargs):
        """Add a thread to the back of the queue.

        Args:
            Passthrough to threading.Thread. 
            target (function)
            name (str)
            args (tuple)
            kwargs (dict)
            group
        """
        self.queue.append(threading.Thread(target=target, *args, **kwargs))

    def enqueueSeries(self, targets):
        def closure():
            for target in targets:
                target()
        self.queue.append(threading.Thread(target=closure))

    def finish(self, resume=False, **kwargs):
        """Block and complete all threads in queue.

        Args:
            resume (bool, optional): If true, spooling resumes after. Otherwise, spooling stops.

        Args, spool:
            verbose (bool, optional): Report progress towards queue completion.
            use_pbar (bool, optional): Graphically display progress towards queue completion.
            delay (num): Optionally override the normal delay.
        """
        self.background_spool = False

        self.spool(**kwargs)

        if resume:
            self.start()

    def setDelay(self, newDelay):
        self.delay = newDelay

    def prune(self):
        """Accurately count number of "our" running threads.
        This removes references to non-alive threads."""
        self.running_threads = [
            thread
            for thread in self.running_threads
            if thread.is_alive()
        ]

    def getNoRunningThreads(self):
        """Accurately count number of "our" running threads.
        This prunes dead threads and returns a count of live threads."""
        self.prune()
        return len(self.running_threads)


def test():
    """Test threading functionality
    """
    from time import sleep

    work = []

    def dillydally(i, wait):
        sleep(wait)
        work.append(i)
        print("Job", i, "done.")

    # with Spool(8, start=True, cpbar=True) as s:
    s = Spool(2, start=True)
    
    s.enqueue(target=dillydally, args=(1, 1))
    s.enqueue(target=dillydally, args=(2, 2))
    s.enqueue(target=dillydally, args=(3, 3))
    s.enqueue(target=dillydally, args=(4, 2.5))
    s.enqueue(target=dillydally, args=(5, 1.5))
    s.flush()
    s.enqueue(target=dillydally, args=(10, 5))
    s.enqueue(target=dillydally, args=(20, 4))
    s.enqueue(target=dillydally, args=(30, 3))
    s.enqueue(target=dillydally, args=(40, 2))
    s.enqueue(target=dillydally, args=(50, 1))

    sleep(5)
    print("Finish.")
    # s.finish(use_pbar=True)
    print(work)

    # threadWait(5, 0.8)
    # print("Finished", done, "jobs")


if __name__ == '__main__':
    test()
