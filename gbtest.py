from pyboy import PyBoy, WindowEvent
from pyboy.core.mb import Motherboard

program = "inc"

filename = "gb_programs/" + program + "/prog.gb"

# should run without video; a lot faster than with it (and we don't need it for this project)
quiet = True

pyboy = PyBoy(filename, window_type="headless" if quiet else "SDL2", window_scale=3, debug=not quiet, game_wrapper=True)

try:
    # sets to as fast as possible
    pyboy.set_emulation_speed(0)

    # normal execution:
    '''
    for i in range(100000):
        # compute one frame (as many CPU cycles as fit in one LCD cycle)
        pyboy.tick()
    '''

    # let program run until before the call of the function we want to evaluate;
    # starts at 0x0200
    pyboy.add_breakpoint(0, 0x0200)
    # we're getting function results in E, nops until 0x0216
    pyboy.add_breakpoint(0, 0x0216)

    # let program run until before the call of the function we want to evaluate
    while not pyboy.paused:
        pyboy.tick()
        print(F"PC: 0x{pyboy.read_PC():04X}")

    # write inputs
    pyboy.write_A(0x01)
    pyboy.write_B(0x02)
    print(F"Input in A: 0x{pyboy.read_A():02X}")
    print(F"Input in B: 0x{pyboy.read_B():02X}")

    pyboy._unpause()

    # we're getting function results in E, nops until 0x0216
    while not pyboy.paused:
        pyboy.tick()
        print(F"PC: 0x{pyboy.read_PC():04X}")

    # read output
    print(F"Output in E: 0x{pyboy.read_E():02X}")

finally:
    # shut down emulator
    pyboy.stop(save=False)
