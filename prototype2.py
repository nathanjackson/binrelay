#!/usr/bin/env python3

import copy
import itertools
import logging

import angr

import networkx as nx

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.INFO)

#class proto_pthread_create(angr.procedures.posix.pthread.pthread_create):
class proto_pthread_create(angr.SimProcedure):
    def run(self, nt, attr, start_routine, arg):
        thread = self.state.solver.eval(nt)

        self.state.thread_info.prev_thread_id = self.state.thread_info.current_thread_id
        self.state.thread_info.current_thread_id = self.state.thread_info.next_thread_id
        self.state.thread_info.next_thread_id += 1

        logger.info("enter thread: %d -> %d",
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
        self.call(start_routine, (arg,), 'dummy')
#        self.ret(self.state.solver.BVV(0, self.state.arch.bits))
#        super().run(nt, attr, start_routine, arg)

    def dummy(self, thread, attr, start_routine, arg):
        prev = self.state.thread_info.current_thread_id
        self.state.thread_info.current_thread_id = self.state.thread_info.prev_thread_id
        self.state.thread_info.prev_thread_id = prev

        logger.info("leave thread: %d -> %d",
                    self.state.thread_info.prev_thread_id,
                    self.state.thread_info.current_thread_id)
        self.ret(self.state.solver.BVV(0, self.state.arch.bits))

class proto_pthread_join(angr.SimProcedure):
    def run(self, thread, retval):
        joined_id = self.state.solver.eval(thread.to_claripy())
        logger.info("Join %d", joined_id)

        src_node = self.state.thread_info.cn
        tmp = set(src_node)
        tmp.remove(joined_id)
        dest_node = frozenset(tmp)

        self.state.thread_info.TG.add_edge(src_node, dest_node, join=joined_id)
        self.state.thread_info.cn = dest_node

        # Perform a deep copy of the active thread set and then remove the
        # provided thread from it.
        #self.state.thread_info.active_threads = copy.deepcopy(self.state.thread_info.active_threads)
        #self.state.thread_info.active_threads.remove(self.state.solver.eval(thread.to_claripy()))

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

def mem_read_callback(state):
    ip = state.ip
    from_addr = state.inspect.mem_read_address
    length = state.inspect.mem_read_length
    logger.debug("Thread %d is reading from %s at %s" %
                (state.thread_info.current_thread_id, from_addr, state.ip))
    #logger.debug("Thread %d Locks held = %s" %
    #             (state.thread_info.current_thread_id, state.thread_info.locks_held))
    #logger.debug("Active Threads = %s" % (state.thread_info.active_threads))

    if int != type(from_addr):
        from_addr = state.solver.eval(from_addr)
    if int != type(length):
        length = state.solver.eval(length)
    if int != type(ip):
        ip = state.solver.eval(ip)

    access = (state.thread_info.current_thread_id, ip, from_addr, "read",
              frozenset(state.thread_info.locks_held), state.thread_info.cn)
    if from_addr not in state.thread_info.accesses:
        state.thread_info.accesses[from_addr] = set()
    state.thread_info.accesses[from_addr].add(access)
    #state.thread_info.accesses.add(access)

    logger.info("thread=%d pc=0x%X addr=0x%X rw=r locks=%s tsn=%s",
                state.thread_info.current_thread_id, ip, from_addr,
                state.thread_info.locks_held, state.thread_info.cn)

def mem_write_callback(state):
    ip = state.ip
    to_addr = state.inspect.mem_write_address
    length = state.inspect.mem_write_length
    logger.debug("Thread %d is reading from %s at %s" %
                (state.thread_info.current_thread_id, to_addr, state.ip))
    #logger.debug("Thread %d Locks held = %s" %
    #             (state.thread_info.current_thread_id, state.thread_info.locks_held))
    #logger.debug("Active Threads = %s" % (state.thread_info.active_threads))

    if int != type(to_addr):
        to_addr = state.solver.eval(to_addr)
    if int != type(length):
        length = state.solver.eval(length)
    if int != type(ip):
        ip = state.solver.eval(ip)

    access = (state.thread_info.current_thread_id, ip, to_addr, "write",
              frozenset(state.thread_info.locks_held), state.thread_info.cn)
    if to_addr not in state.thread_info.accesses:
        state.thread_info.accesses[to_addr] = set()
    state.thread_info.accesses[to_addr].add(access)
#    state.thread_info.accesses.add(access)

    logger.info("thread=%d pc=0x%X addr=0x%X rw=w locks=%s tsn=%s",
                state.thread_info.current_thread_id, ip, to_addr,
                state.thread_info.locks_held, state.thread_info.cn)

p = angr.Project("samples/sample03", auto_load_libs=False)
p.hook_symbol("pthread_create", proto_pthread_create())
p.hook_symbol("pthread_join", proto_pthread_join())
p.hook_symbol("pthread_mutex_lock", _pthread_mutex_lock())
p.hook_symbol("_pthread_mutex_unlock", _pthread_mutex_unlock())

state = p.factory.entry_state()
state.register_plugin("thread_info", ThreadInfoPlugin())
state.inspect.b("mem_read", when=angr.BP_AFTER, action=mem_read_callback)
state.inspect.b("mem_write", when=angr.BP_AFTER, action=mem_write_callback)

simgr = p.factory.simulation_manager(state)
simgr.use_technique(angr.exploration_techniques.Spiller())
simgr.run()

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

checked_ranges = set()
for section in p.loader.main_object.sections:
    if section.name == ".data" or section.name == ".bss":
        checked_ranges.add((section.vaddr, section.memsize))

for st in simgr.deadended:
    for addr in st.thread_info.accesses.keys():
        if True == min([addr < rng[0] or rng[0]+rng[1]-1 < addr for rng
                        in checked_ranges]):
            continue

        #logger.info("Accesses for Address 0x%X", addr)
        tmp = st.thread_info.accesses[addr]
        combinations = itertools.combinations(st.thread_info.accesses[addr], 2)

        for combo in combinations:
            a0 = combo[0]
            a1 = combo[1]

            if a0[0] == a1[0]:
                continue
            if a0[3] == "read" and a1[3] == "read":
                continue

#                logger.info("thread=%d, pc=0x%X addr=0x%X rw=%s locks=%s tsn=%s",
#                           a0[0], a0[1], a0[2], a0[3], a0[4], a0[5])
#                logger.info("thread=%d, pc=0x%X addr=0x%X rw=%s locks=%s tsn=%s",
#                           a1[0], a1[1], a1[2], a1[3], a1[4], a1[5])
            result = check(st.thread_info.TG, a0, a1)
            if True == result:
                logger.info("possible race on 0x%X", addr)
                logger.info("thread=%d, pc=0x%X addr=0x%X rw=%s locks=%s tsn=%s",
                    a0[0], a0[1], a0[2], a0[3], a0[4], a0[5])
                logger.info("thread=%d, pc=0x%X addr=0x%X rw=%s locks=%s tsn=%s",
                    a1[0], a1[1], a1[2], a1[3], a1[4], a1[5])
#                logger.info(result)

#        for acc in st.thread_info.accesses[addr]:
#            logger.info("thread=%d, pc=0x%X addr=0x%X rw=%s locks=%s tsn=%s",
#                        acc[0], acc[1], acc[2], acc[3], acc[4], acc[5])


    #for acc0 in list(st.thread_info.accesses):
    #    for acc1 in list(st.thread_info.accesses)[1:]:
    #        logger.info("acc0: thread=%d, pc=0x%X addr=0x%X rw=%s locks=%s tsn=%s",
    #                    acc0[0], acc0[1], acc0[2], acc0[3], acc0[4], acc0[5])
    #        logger.info("acc1: thread=%d, pc=0x%X addr=0x%X rw=%s locks=%s tsn=%s",
    #                    acc1[0], acc1[1], acc1[2], acc1[3], acc1[4], acc0[5])

    #print(st.thread_info.TG.edges(data=True))
