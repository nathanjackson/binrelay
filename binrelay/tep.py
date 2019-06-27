import copy
import logging

import angr

l = logging.getLogger(name=__name__)
l.setLevel(logging.INFO)

class _PthreadCreate(angr.procedures.posix.pthread.pthread_create):
    symbol = "pthread_create"

    def __init__(self, kb):
        super(_PthreadCreate, self).__init__()
        self._kb = kb

    def run(self, newthread, attr, start_routine, arg):
        addr = self.state.solver.eval(start_routine.to_claripy())
        if addr not in self._kb.thread_entry_points:
            l.info("Found new thread entry point at 0x%x" % addr)
        self._kb.thread_entry_points.add(addr)
        super(_PthreadCreate, self).run(newthread, attr, start_routine, arg)

class ThreadEntryPoints(angr.knowledge_plugins.KnowledgeBasePlugin):
    _teps = set()

    def __iter__(self):
        return self._teps.__iter__()

    def __getitem__(self, idx):
        return self._teps[idx]

    def __len__(self):
        return len(self._teps)

    def __contains__(self, v):
        return (v in self._teps)

    def add(self, tep):
        self._teps.add(tep)

class TEPAnalysis(angr.Analysis):
    """
    Thread entry point analysis.

    Finds functions that are used as the start of new threads.
    """
    def __init__(self):
        # Save sim procedures so we can restore them after the analysis.
        orig_hooks = copy.deepcopy(self.project._sim_procedures)

        self.kb.register_plugin("thread_entry_points", ThreadEntryPoints())

        # Hook our custom sim procedures that keep track of where threads start
        # up.
        simproc = _PthreadCreate(self.kb)
        self.project.hook_symbol(simproc.symbol, simproc)

        # Run a simulation to find the thread entry points.
        simmgr = self.project.factory.simulation_manager()
        simmgr.use_technique(angr.exploration_techniques.LoopSeer(bound=1))
        simmgr.run()

        # Restore original sim procedures
        self.project._sim_procedures = orig_hooks
angr.AnalysesHub.register_default("TEPAnalysis", TEPAnalysis)
