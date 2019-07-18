import angr

class pthread_exit(angr.SimProcedure):
    """
    Simulates pthread_exit by never returning.
    """
    NO_RET = True
    def run(self, exit_code):
        pass
