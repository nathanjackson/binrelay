import logging

import angr

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.DEBUG)

class pthread_exit(angr.SimProcedure):
    """
    Simulates pthread_exit by never returning.
    """
    NO_RET = True
    def run(self, exit_code):
        pass

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

#    def mk_hook(dest_addr):
#        hit_count = 0
#        def loop_hook(state):
#            nonlocal hit_count
#            if hit_count >= max_iters:
#                state.ip = dest_addr
#                logger.debug("tid = %d jumping out of loop, ip = %s" %
#                             (state.thread_info.current_thread_id, state.ip))
#            hit_count += 1
#        return loop_hook

    cfg = proj.analyses.CFGFast()

    loop_finder_result = proj.analyses.LoopFinder()

    for loop in loop_finder_result.loops:
        edge = loop.break_edges[0]
        logger.debug(edge)
        src_block = proj.factory.block(edge[0].addr)
        jmp_out_addr = src_block.instruction_addrs[-1]
        logger.debug("jump out addr = 0x%X" % (jmp_out_addr))
        #proj.hook(jmp_out_addr, hook=mk_hook(edge[1].addr))
        proj.hook(jmp_out_addr, hook=loop_hook(edge[1].addr))
