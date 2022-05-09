from pyboy import PyBoy, WindowEvent
from pyboy.core.mb import Motherboard

def run_gb_testcases(program, testcase_list):
    '''
    runs given test cases (list of tuples for inputs to a,b)
    returns list of outputs (register e)
    '''

    filename = "gb_programs/" + program + "/prog.gb"

    # should run without video; a lot faster than with it (and we don't need it for this project)
    quiet = True

    results = []

    for test in testcase_list:
        # initialize emulator
        pyboy = PyBoy(filename, window_type="headless" if quiet else "SDL2", window_scale=3, debug=not quiet, game_wrapper=True)

        try:
            # sets to as fast as possible
            pyboy.set_emulation_speed(0)

            # let program run until before the call of the function we want to evaluate;
            # starts at 0x0200
            pyboy.add_breakpoint(0, 0x0200)
            # we're getting function results in E, nops until 0x0216
            pyboy.add_breakpoint(0, 0x0216)

            # let program run until before the call of the function we want to evaluate
            while not pyboy.paused:
                pyboy.tick()
                #print(F"PC: 0x{pyboy.read_PC():04X}")

            # write inputs
            pyboy.write_A(test[0])
            pyboy.write_B(test[1])
            #print(F"Input in A: 0x{pyboy.read_A():02X}")
            #print(F"Input in B: 0x{pyboy.read_B():02X}")

            pyboy._unpause()

            # we're getting function results in E, nops until 0x0216
            while not pyboy.paused:
                pyboy.tick()
                #print(F"PC: 0x{pyboy.read_PC():04X}")

            # read output
            #print(F"Output in E: 0x{pyboy.read_E():02X}")
            results.append(pyboy.read_E())

        finally:
            # shut down emulator
            pyboy.stop(save=False)

    return results
