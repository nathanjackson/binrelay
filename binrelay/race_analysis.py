import copy
import logging

import angr

from .utils import pthread_exit

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.DEBUG)

# (PC, Thread ID) -> { (address, size, rw, locks) }
meta = { }

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

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        result = ThreadInfoPlugin()
        result.current_thread_id = self.current_thread_id
        result.next_thread_id = self.next_thread_id
        result.prev_thread_id = self.prev_thread_id
        result.locks_held = copy.deepcopy(self.locks_held)
        return result

class _pthread_create(angr.procedures.posix.pthread.pthread_create):
    """
    A subclassed pthread_create sim procedure that updates the
    ThreadInfoPlugin.
    """
    def run(self, newthread, attr, start_routine, arg):
        self.state.thread_info.prev_thread_id = self.state.thread_info.current_thread_id
        self.state.thread_info.current_thread_id = self.state.thread_info.next_thread_id
        self.state.thread_info.next_thread_id += 1

        logger.debug("Thread %d -> %d" %
                     (self.state.thread_info.prev_thread_id,
                      self.state.thread_info.current_thread_id))
        super(_pthread_create, self).run(newthread, attr, start_routine, arg)

        prev = self.state.thread_info.current_thread_id
        self.state.thread_info.current_thread_id = self.state.thread_info.prev_thread_id
        self.state.thread_info.prev_thread_id = prev

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
    from_addr = state.inspect.mem_read_address
    logger.debug("Thread %d is reading from %s at %s" %
                (state.thread_info.current_thread_id, from_addr, state.ip))
    logger.debug("Thread %d Locks held = %s" % (state.thread_info.current_thread_id, state.thread_info.locks_held))

    pc = state.solver.eval(state.ip)
    tid = state.thread_info.current_thread_id
    key = (pc, tid)

    length = state.inspect.mem_read_length
    rw = "read"
    locks = copy.deepcopy(state.thread_info.locks_held)
    value = (state.solver.eval(from_addr), length, rw, locks)

    if key not in meta:
        meta[key] = []
    meta[key].append(value)

def _mem_write_callback(state):
    to_addr = state.inspect.mem_write_address
    logger.debug("Thread %d is writing from %s at %s" %
                (state.thread_info.current_thread_id, to_addr, state.ip))
    logger.debug("Thread %d Locks held = %s" % (state.thread_info.current_thread_id, state.thread_info.locks_held))

    pc = state.solver.eval(state.ip)
    tid = state.thread_info.current_thread_id
    key = (pc, tid)

    length = state.inspect.mem_write_length
    rw = "write"
    locks = copy.deepcopy(state.thread_info.locks_held)
    value = (state.solver.eval(to_addr), length, rw, locks)

    if key not in meta:
        meta[key] = []
    meta[key].append(value)

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

        # Setup the symbolic execution.
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
        simmgr.use_technique(angr.exploration_techniques.LoopSeer(bound=1))
        simmgr.run()

        for key in meta.keys():
            print("%s: %s" % (key, meta[key]))

        # Restore sim procedures
        self.project._sim_procedures = orig_hooks


# Register the RaceFinder with angr.
angr.AnalysesHub.register_default("RaceFinder", RaceFinder)
