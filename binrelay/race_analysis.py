import copy
import itertools
import logging

import angr

import networkx as nx

from .utils import pthread_exit

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.INFO)

READ = "read"
WRITE = "write"


class ThreadInfoPlugin(angr.SimStatePlugin):
    def __init__(self):
        super(ThreadInfoPlugin, self).__init__()

        self.prev_thread_id = None
        self.current_thread_id = 0
        self.next_thread_id = 1

        self.TG = nx.DiGraph()
        self.cn = frozenset([0])
        self.TG.add_node(self.cn)

        self.locks_held = set()

        self.accesses = {}
        #self.accesses = set()

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        result = ThreadInfoPlugin()
        result.prev_thread_id = self.prev_thread_id
        result.current_thread_id = self.current_thread_id
        result.next_thread_id = self.next_thread_id

        result.TG = copy.deepcopy(self.TG)
        result.cn = copy.deepcopy(self.cn)

        result.locks_held = copy.deepcopy(self.locks_held)

        result.accesses = copy.deepcopy(self.accesses)
        return result


class _pthread_create(angr.SimProcedure):
    """
    A Sim Procedure for pthread_create
    """

    def run(self, nt, attr, start_routine, arg):
        thread = self.state.solver.eval(nt)

        self.state.thread_info.prev_thread_id = self.state.thread_info.current_thread_id
        self.state.thread_info.current_thread_id = self.state.thread_info.next_thread_id
        self.state.thread_info.next_thread_id += 1

        logger.debug("enter thread: %d -> %d",
                     self.state.thread_info.prev_thread_id,
                     self.state.thread_info.current_thread_id)

        src_node = self.state.thread_info.cn

        tmp = set(src_node)
        tmp.add(self.state.thread_info.current_thread_id)
        dest_node = frozenset(tmp)

        self.state.thread_info.TG.add_edge(src_node, dest_node,
                                           create=self.state.thread_info.current_thread_id)
        self.state.thread_info.cn = dest_node

        self.state.mem[thread].uint64_t = self.state.thread_info.current_thread_id
        self.call(start_routine, (arg,), 'on_return')

    def on_return(self, thread, attr, start_routine, arg):
        prev = self.state.thread_info.current_thread_id
        self.state.thread_info.current_thread_id = self.state.thread_info.prev_thread_id
        self.state.thread_info.prev_thread_id = prev

        logger.debug("leave thread: %d -> %d",
                     self.state.thread_info.prev_thread_id,
                     self.state.thread_info.current_thread_id)
        self.ret(self.state.solver.BVV(0, self.state.arch.bits))


class _pthread_join(angr.SimProcedure):
    def run(self, thread, retval):
        joined_id = self.state.solver.eval(thread.to_claripy())
        logger.debug("Join %d", joined_id)

        src_node = self.state.thread_info.cn
        tmp = set(src_node)
        tmp.remove(joined_id)
        dest_node = frozenset(tmp)

        self.state.thread_info.TG.add_edge(src_node, dest_node, join=joined_id)
        self.state.thread_info.cn = dest_node


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

    if int != type(from_addr):
        from_addr = state.solver.eval(from_addr)
    if int != type(length):
        length = state.solver.eval(length)
    if int != type(ip):
        ip = state.solver.eval(ip)

    for i in range(length):
        addr = from_addr + i
        access = (state.thread_info.current_thread_id, ip, addr, READ,
                  frozenset(state.thread_info.locks_held), state.thread_info.cn)
        if addr not in state.thread_info.accesses:
            state.thread_info.accesses[addr] = set()
        state.thread_info.accesses[addr].add(access)

    logger.debug("thread=%d pc=0x%X addr=0x%X rw=r locks=%s tsn=%s",
                 state.thread_info.current_thread_id, ip, from_addr,
                 state.thread_info.locks_held, state.thread_info.cn)


def _mem_write_callback(state):
    ip = state.ip
    to_addr = state.inspect.mem_write_address
    length = state.inspect.mem_write_length
    logger.debug("Thread %d is reading from %s at %s" %
                 (state.thread_info.current_thread_id, to_addr, state.ip))

    if int != type(to_addr):
        to_addr = state.solver.eval(to_addr)
    if int != type(length):
        length = state.solver.eval(length)
    if int != type(ip):
        ip = state.solver.eval(ip)

    for i in range(length):
        addr = to_addr + i
        access = (state.thread_info.current_thread_id, ip, addr, WRITE,
                  frozenset(state.thread_info.locks_held), state.thread_info.cn)
        if addr not in state.thread_info.accesses:
            state.thread_info.accesses[addr] = set()
        state.thread_info.accesses[addr].add(access)

    logger.debug("thread=%d pc=0x%X addr=0x%X rw=w locks=%s tsn=%s",
                 state.thread_info.current_thread_id, ip, to_addr,
                 state.thread_info.locks_held, state.thread_info.cn)


def find_create_edge_dest(G, t):
    for _, d, attrs in G.edges(data=True):
        if "create" in attrs and t == attrs["create"]:
            return d
    return None


def reachable(G, c, tid, a):
    if c == a[5]:
        return True
    path = nx.shortest_path(G, source=c, target=a[5])
    for s, t in zip(path, path[1:]):
        attrs = G.get_edge_data(s, t)
        if "join" in attrs and tid == attrs["join"]:
            return False
        if t == a[5]:
            return True
    return False


def check(G, a1, a2):
    c1 = None
    c2 = None
    if 0 != a1[0]:
        c1 = find_create_edge_dest(G, a1[0])
    if 0 != a2[0]:
        c2 = find_create_edge_dest(G, a2[0])

    if None != c2 and True == reachable(G, c2, a2[0], a1):
        return True
    if None != c1 and True == reachable(G, c1, a1[0], a2):
        return True
    return False


class RaceFinder(angr.Analysis):
    """
    RaceFinder is the point of this entire project!
    """

    def __init__(self, initial_state=None):
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

        if None == initial_state:
            initial_state = self.project.factory.entry_state()
        initial_state.register_plugin("thread_info", ThreadInfoPlugin())

        # Setup breakpoints for memory accesses
        initial_state.inspect.b("mem_read", when=angr.BP_AFTER,
                                action=_mem_read_callback)
        initial_state.inspect.b("mem_write", when=angr.BP_AFTER,
                                action=_mem_write_callback)

        simmgr = self.project.factory.simulation_manager(initial_state)
        # XXX: We probably don't want to use LoopSeer because we need to be
        # able to execute the loop bodies to see their reads and writes.
        simmgr.use_technique(angr.exploration_techniques.Spiller())
        logger.info("Starting symbolic execution")
        simmgr.run()
        logger.info("Symbolic execution terminated")

        checked_ranges = set()
        for section in self.project.loader.main_object.sections:
            if section.name == ".data" or section.name == ".bss":
                checked_ranges.add((section.vaddr, section.memsize))

        logger.info(simmgr)

        logger.info("Checking for race conditions")

        for st in simmgr.deadended:
            for addr in st.thread_info.accesses.keys():
                if True == min([addr < rng[0] or rng[0]+rng[1]-1 < addr for rng
                                in checked_ranges]):
                    continue

                combinations = itertools.combinations(
                    st.thread_info.accesses[addr], 2)

                for combo in combinations:
                    a0 = combo[0]
                    a1 = combo[1]

                    if a0[0] == a1[0]:
                        continue
                    if a0[3] == READ and a1[3] == READ:
                        continue
                    if len(a0[4].intersection(a1[4])) > 0:
                        continue

                    result = check(st.thread_info.TG, a0, a1)
                    if True == result:
                        logger.info("possible race on 0x%X", addr)
                        logger.info("thread=%d, pc=0x%X addr=0x%X rw=%s locks=%s tsn=%s",
                                    a0[0], a0[1], a0[2], a0[3], a0[4], a0[5])
                        logger.info("thread=%d, pc=0x%X addr=0x%X rw=%s locks=%s tsn=%s",
                                    a1[0], a1[1], a1[2], a1[3], a1[4], a1[5])

        logger.info("Race Analysis Complete")

        # Restore sim procedures
        self.project._sim_procedures = orig_hooks


# Register the RaceFinder with angr.
angr.AnalysesHub.register_default("RaceFinder", RaceFinder)
