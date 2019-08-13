import copy
import logging

import angr

from .utils import pthread_exit

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.DEBUG)

class ThreadInfoPlugin(angr.SimStatePlugin):
    """
    A state plugin for keeping track of simulated threads.
    """
    def __init__(self):
        super(ThreadInfoPlugin, self).__init__()
        self.sim_thread_id = 0

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        result = ThreadInfoPlugin()
        result.sim_thread_id = self.sim_thread_id
        return result

class _pthread_create(angr.procedures.posix.pthread.pthread_create):
    """
    A subclassed pthread_create sim procedure that updates the
    ThreadInfoPlugin.
    """
    def run(self, newthread, attr, start_routine, arg):
        from_thread = self.state.thread_info.sim_thread_id
        to_thread = self.state.thread_info.sim_thread_id + 1
        logger.debug("Thread %d -> %d" % (from_thread, to_thread))
        logger.debug(self.state.callstack)
        self.state.thread_info.sim_thread_id = to_thread
        super(_pthread_create, self).run(newthread, attr, start_routine, arg)
        self.state.thread_info.sim_thread_id = from_thread

class _pthread_mutex_lock(angr.SimProcedure):
    """
    A simprocedure that is executed when a lock (mutex) is taken.
    """
    def run(self, mutex):
        logger.debug("Thread %d is locking mutex @ %s" %
                    (self.state.thread_info.sim_thread_id, mutex))

class _pthread_mutex_unlock(angr.SimProcedure):
    """
    A simprocedure that is executed when a lock (mutex) is released.
    """
    def run(self, mutex):
        logger.debug("Thread %d is releasing mutex @ %s" %
                    (self.state.thread_info.sim_thread_id, mutex))

def _mem_read_callback(state):
    from_addr = state.inspect.mem_read_address
    logger.debug("Thread %d is reading from %s at %s" %
                (state.thread_info.sim_thread_id, from_addr, state.ip))

def _mem_write_callback(state):
    to_addr = state.inspect.mem_write_address
    logger.debug("Thread %d is writing to %s at %s" %
                (state.thread_info.sim_thread_id, to_addr, state.ip))

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

        # Restore sim procedures
        self.project._sim_procedures = orig_hooks


# Register the RaceFinder with angr.
angr.AnalysesHub.register_default("RaceFinder", RaceFinder)
