from pyboy import PyBoy, WindowEvent
from pyboy.core.mb import Motherboard

filename = "sternstein.gb"

# should run without video; a lot faster than with it (and we don't need it for this project)
quiet = True

pyboy = PyBoy(filename, window_type="headless" if quiet else "SDL2", window_scale=3, debug=not quiet, game_wrapper=True)

try:
    # sets to as fast as possible
    pyboy.set_emulation_speed(0)

    # get title
    print("Current ROM: " + pyboy.cartridge_title())

    print(PyBoy.__dict__)

    # normal execution:
    '''
    for i in range(100000):
        # compute one frame (as many CPU cycles as fit in one LCD cycle)
        pyboy.tick()
    '''
    # instruction-by-instruction CPU execution:
    for i in range(100):
        # compute one instruction (warning: sound, LCD not being updates; possibly other things?)
        pyboy.cpu_tick()
        print(F"PC: {pyboy.read_PC():04X}")

    # read/write registers
    print(F"A: {pyboy.read_A():02X}")
    pyboy.write_A(255)
    print(F"A: {pyboy.read_A():02X}")

finally:
    # shut down emulator
    pyboy.stop(save=False)
