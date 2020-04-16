import logging

import angr

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.DEBUG)


class pthread_exit(angr.SimProcedure):
    """
    Simulates pthread_exit by performing a no-op.
    """

    def run(self, exit_code):
        self.ret()


class loop_hook(object):
    def __init__(self, dest_addr):
        self.hit_count_for_tid = {}
        self.dest_addr = dest_addr

    def __call__(self, state):
        if state.thread_info.current_thread_id not in self.hit_count_for_tid:
            self.hit_count_for_tid[state.thread_info.current_thread_id] = 0

        if self.hit_count_for_tid[state.thread_info.current_thread_id] >= 10:
            state.ip = self.dest_addr
            logger.debug("tid = %d jumping out of loop, ip = %s" %
                         (state.thread_info.current_thread_id, state.ip))

        self.hit_count_for_tid[state.thread_info.current_thread_id] += 1


def hook_loops(proj, max_iters=10):
    proj.analyses.CFGFast()

    loop_finder_result = proj.analyses.LoopFinder()

    for loop in loop_finder_result.loops:
        edge = loop.break_edges[0]
        logger.debug(edge)
        src_block = proj.factory.block(edge[0].addr)
        jmp_out_addr = src_block.instruction_addrs[-1]
        logger.debug("jump out addr = 0x%X" % (jmp_out_addr))
        proj.hook(jmp_out_addr, hook=loop_hook(edge[1].addr))


def pthread_exit_hook(state):
    state.callstack.ret()
    state.ip = state.callstack.current_return_target


def hook_pthread_exit(proj):
    cfg = proj.analyses.CFGFast()
    for func in cfg.functions:
        f = cfg.kb.functions.function(func)
        for callsite in f.get_call_sites():
            target = f.get_call_target(callsite)
            target_func = cfg.kb.functions.function(target)
            if "pthread_exit" == target_func.name:
                bb = proj.factory.block(callsite)
                proj.hook(bb.instruction_addrs[-1], hook=pthread_exit_hook)
                print("pthread_exit call @ 0x%X" % (bb.instruction_addrs[-1]))
