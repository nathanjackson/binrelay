import copy
import logging

import angr

from .utils import pthread_exit

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.INFO)

READ = "read"
WRITE = "write"

class Shadow(object):
    """
    A shadow memory for tracking memory accesses during symbolic execution.

    Address -> { (tid, ip, lockset) } 
    """
    def __init__(self):
        self._data = {}

    def add_access(self, start_address, size, tid, ip, rw, lockset,
                   active_threads):
        for i in range(size):
            address  = start_address + i
            if address not in self._data:
                self._data[address] =  set()

            self._data[address].add((tid, ip, rw, lockset, active_threads))

    def find_races(self, ranges):
        for address in self._data.keys():
            if True == min([address < rng[0] or rng[0]+rng[1]-1 < address for rng in
                            ranges]):
                continue

            accesses0 = list(self._data[address])
            accesses1 = accesses0[1:]

            for acc0 in accesses0:
                for acc1 in accesses1:
                    if acc0[0] == acc1[0]:
                        continue
                    if READ == acc0[2] and READ == acc1[2]:
                        continue
                    if 0 < len(acc0[3].intersection(acc1[3])):
                        continue
                    if not ((acc0[0] in acc1[4]) and (acc1[0] in acc0[4])):
                        continue
                    logger.info("Possible Race on 0x%X (%s <-> %s)" % (address,
                                                                      acc0,
                                                                       acc1))
shad = Shadow()

class ThreadInfoPlugin(angr.SimStatePlugin):
    """
    A state plugin for keeping track of simulated threads.
    """
    def __init__(self):
        super(ThreadInfoPlugin, self).__init__()
        self.current_thread_id = 0
        self.next_thread_id = 1
        self.prev_thread_id = None

        self.locks_held = set()

        self.active_threads = set([0])

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        result = ThreadInfoPlugin()
        result.current_thread_id = self.current_thread_id
        result.next_thread_id = self.next_thread_id
        result.prev_thread_id = self.prev_thread_id
        result.locks_held = copy.deepcopy(self.locks_held)
        # Notice that we don't perform a deep copy of the active threads. This
        # is because the symbolic execution is executing the "threads"
        # sequentially. We allow some states to share the same active thread
        # set. When a thread join occurs, we then make a copy. The idea is that
        # threads that could possibly execute simultaneously share an active
        # thread set.
        result.active_threads = self.active_threads
        return result

class _pthread_create(angr.procedures.posix.pthread.pthread_create):
    """
    A subclassed pthread_create sim procedure that updates the
    ThreadInfoPlugin.
    """
    def run(self, newthread, attr, start_routine, arg):
        thread = self.state.solver.eval(newthread)
        
        self.state.thread_info.prev_thread_id = self.state.thread_info.current_thread_id
        self.state.thread_info.current_thread_id = self.state.thread_info.next_thread_id
        self.state.thread_info.next_thread_id += 1

        self.state.thread_info.active_threads.add(self.state.thread_info.current_thread_id)

        logger.debug("Thread 0x%X = ID %d", thread,
                     self.state.thread_info.current_thread_id)
        self.state.mem[thread].uint64_t = self.state.thread_info.current_thread_id

        logger.debug("Thread %d -> %d" %
                     (self.state.thread_info.prev_thread_id,
                      self.state.thread_info.current_thread_id))
        super(_pthread_create, self).run(newthread, attr, start_routine, arg)

        prev = self.state.thread_info.current_thread_id
        self.state.thread_info.current_thread_id = self.state.thread_info.prev_thread_id
        self.state.thread_info.prev_thread_id = prev

class _pthread_join(angr.SimProcedure):
    def run(self, thread, retval):
        logger.debug("Join %s", thread)
        # Perform a deep copy of the active thread set and then remove the
        # provided thread from it.
        self.state.thread_info.active_threads = copy.deepcopy(self.state.thread_info.active_threads)
        self.state.thread_info.active_threads.remove(self.state.solver.eval(thread.to_claripy()))

class _pthread_mutex_lock(angr.SimProcedure):
    """
    A simprocedure that is executed when a lock (mutex) is taken.
    """
    def run(self, mutex):
        logger.debug("Thread %d is locking mutex @ %s" %
                    (self.state.thread_info.current_thread_id, mutex))
        mutex_address = self.state.solver.eval(mutex.to_claripy())
        self.state.thread_info.locks_held.add(mutex_address)

class _pthread_mutex_unlock(angr.SimProcedure):
    """
    A simprocedure that is executed when a lock (mutex) is released.
    """
    def run(self, mutex):
        logger.debug("Thread %d is releasing mutex @ %s" %
                    (self.state.thread_info.current_thread_id, mutex))
        mutex_address = self.state.solver.eval(mutex.to_claripy())
        self.state.thread_info.locks_held.remove(mutex_address)

def _mem_read_callback(state):
    ip = state.ip
    from_addr = state.inspect.mem_read_address
    length = state.inspect.mem_read_length
    logger.debug("Thread %d is reading from %s at %s" %
                (state.thread_info.current_thread_id, from_addr, state.ip))
    logger.debug("Thread %d Locks held = %s" %
                 (state.thread_info.current_thread_id, state.thread_info.locks_held))
    logger.debug("Active Threads = %s" % (state.thread_info.active_threads))

    if int != type(from_addr):
        from_addr = state.solver.eval(from_addr)
    if int != type(length):
        length = state.solver.eval(length)
    if int != type(ip):
        ip = state.solver.eval(ip)

    shad.add_access(from_addr, length, state.thread_info.current_thread_id, ip,
                    READ, frozenset(state.thread_info.locks_held),
                    frozenset(state.thread_info.active_threads))

def _mem_write_callback(state):
    ip = state.ip
    to_addr = state.inspect.mem_write_address
    length = state.inspect.mem_write_length
    logger.debug("Thread %d is writing from %s at %s" %
                (state.thread_info.current_thread_id, to_addr, state.ip))
    logger.debug("Thread %d Locks held = %s" %
                 (state.thread_info.current_thread_id, state.thread_info.locks_held))
    logger.debug("Active Threads = %s" % (state.thread_info.active_threads))

    if int != type(to_addr):
        to_addr = state.solver.eval(to_addr)
    if int != type(length):
        length = state.solver.eval(length)
    if int != type(ip):
        ip = state.solver.eval(ip)

    shad.add_access(to_addr, length, state.thread_info.current_thread_id, ip,
                    WRITE, frozenset(state.thread_info.locks_held),
                    frozenset(state.thread_info.active_threads))

class RaceFinder(angr.Analysis):
    """
    RaceFinder is the point of this entire project!
    """

    def __init__(self):
        # Save off the SimProcedures so they can be restored post-analysis.
        orig_hooks = copy.deepcopy(self.project._sim_procedures)

        # Setup BINRELAY's SimProcedures.
        # XXX: Need to do this in a cross-platform way, right now we assume
        # Linux binaries.
        self.project.hook_symbol("pthread_create", _pthread_create())
        self.project.hook_symbol("pthread_mutex_lock", _pthread_mutex_lock())
        self.project.hook_symbol("pthread_mutex_unlock",
                                 _pthread_mutex_unlock())
        self.project.hook_symbol("pthread_exit", pthread_exit())
        self.project.hook_symbol("pthread_join", _pthread_join())

        # Setup the symbolic execution.
        checked_ranges = set()
        for section in self.project.loader.main_object.sections:
            if section.name == ".data" or section.name == ".bss":
                checked_ranges.add((section.vaddr, section.memsize))
        state = self.project.factory.entry_state()
        state.register_plugin("thread_info", ThreadInfoPlugin())

        # Setup breakpoints for memory accesses
        state.inspect.b("mem_read", when=angr.BP_AFTER,
                        action=_mem_read_callback)
        state.inspect.b("mem_write", when=angr.BP_AFTER,
                        action=_mem_write_callback)

        simmgr = self.project.factory.simulation_manager(state)
        # XXX: We probably don't want to use LoopSeer because we need to be
        # able to execute the loop bodies to see their reads and writes.
        simmgr.use_technique(angr.exploration_techniques.Spiller())
        simmgr.run()

        shad.find_races(checked_ranges)

        # Restore sim procedures
        self.project._sim_procedures = orig_hooks

# Register the RaceFinder with angr.
angr.AnalysesHub.register_default("RaceFinder", RaceFinder)
