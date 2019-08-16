import copy
import logging

import angr

from .utils import pthread_exit

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.DEBUG)

class ProgramPoint(object):
    def __init__(self, pc, tid):
        self.pc = pc
        self.tid = tid

    def collides(self, other):
        return self.tid != other.tid

    def __repr__(self):
        return "<ProgramPoint {0x%X, %d}>" % (self.pc, self.tid)

    def __hash__(self):
        return hash(self.pc) ^ hash(self.tid)

    def __eq__(self, other ):
        return self.pc == other.pc and \
               self.tid == other.tid

class MemoryAccess(object):
    def __init__(self, address, size, rw):
        self.address = address
        self.size = size
        self.rw = rw

    def overlaps(other):
        x1 = self.address
        y1 = other.address
        x2 = self.address + self.size - 1
        y2 = other.address + other.size - 1
        return x1 <= y2 and y1 <= x2

    def __hash__(self):
        return hash(self.address) ^ hash(self.size) ^ hash(self.rw)

    def __eq__(self, other):
        return self.address == other.address and \
               self.size == other.size and \
               self.rw == other.rw

    def __repr__(self):
        return "<MemoryAccess {0x%X, %d, %s}>" % (self.address, self.size,
                                                  self.rw)

# (PC, Thread ID) -> { (address, size, rw) }
# mem_accesses = { }

# (address, size, rw) -> (PC, Thread ID)
mem_accesses = { }

# (PC, Thread ID) -> { locks }
locksets = { }

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

    pp = ProgramPoint(state.solver.eval(state.ip),
                      state.thread_info.current_thread_id)

    length = state.inspect.mem_read_length
    if type(length) != int:
        length = state.solver.eval(length)
    access = MemoryAccess(state.solver.eval(from_addr), length, "read")
    if access not in mem_accesses:
        mem_accesses[access] = set()
    mem_accesses[access].add(pp)

#    pc = state.solver.eval(state.ip)
#    tid = state.thread_info.current_thread_id
#    key = (pc, tid)
#
#    length = state.inspect.mem_read_length
#    rw = "read"
#    value = (state.solver.eval(from_addr), length, rw)
#
#    if key not in mem_accesses:
#        mem_accesses[key] = set()
#    mem_accesses[key].add(value)
#
#    if key not in locksets:
#        locksets[key] = set()
#    locksets[key] = locksets[key].union(state.thread_info.locks_held)

def _mem_write_callback(state):
    to_addr = state.inspect.mem_write_address
    logger.debug("Thread %d is writing from %s at %s" %
                (state.thread_info.current_thread_id, to_addr, state.ip))
    logger.debug("Thread %d Locks held = %s" % (state.thread_info.current_thread_id, state.thread_info.locks_held))

    pp = ProgramPoint(state.solver.eval(state.ip),
                      state.thread_info.current_thread_id)

    length = state.inspect.mem_write_length
    if type(length) != int:
        length = state.solver.eval(length)
    access = MemoryAccess(state.solver.eval(to_addr), length, "write")
    if access not in mem_accesses:
        mem_accesses[access] = set()
    mem_accesses[access].add(pp)

#    pc = state.solver.eval(state.ip)
#    tid = state.thread_info.current_thread_id
#    key = (pc, tid)
#
#    length = state.inspect.mem_write_length
#    rw = "write"
#    value = (state.solver.eval(to_addr), length, rw)
#
#    if key not in mem_accesses:
#        mem_accesses[key] = set()
#    mem_accesses[key].add(value)
#
#    if key not in locksets:
#        locksets[key] = set()
#    locksets[key] = locksets[key].union(state.thread_info.locks_held)

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

        for key in mem_accesses.keys():
            xs = list(mem_accesses[key])
            ys = xs[1:]
            for xpp in xs:
                for ypp in ys:
                    if xpp.collides(ypp):
                        logger.info("Possible Race on 0x%X: xpp = %s, ypp = %s" % (key.address, xpp, ypp))

#        for key in locksets.keys():
#            print("%s: %s" % (key, locksets[key]))

        # Restore sim procedures
        self.project._sim_procedures = orig_hooks


# Register the RaceFinder with angr.
angr.AnalysesHub.register_default("RaceFinder", RaceFinder)
