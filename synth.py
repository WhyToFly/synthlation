# to emulate x86 code
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_SECOND_SCALE
# to access relevant registers
from unicorn.x86_const import UC_X86_REG_AL, UC_X86_REG_BL, UC_X86_REG_CL, \
                                UC_X86_REG_DL, UC_X86_REG_ESI
# to assemble x86 code
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

import sys
import time
import random
import math
import argparse

from multiprocessing import Queue, Process, Value
from queue import Empty
import signal

from gbtest import run_gb_testcases


# maximum program length
MAX_LEN = 10
# number of test cases to generate
TEST_NUM = 32
# allow jumps?
ALLOW_JMP = True
# probability for actually using jumps even if they're allowed
JUMP_PROB = 0.5

# timeout for emulation; vital when using jumps as they can produce infinite loops that slow the search down a lot
EMU_TIMEOUT = int(UC_SECOND_SCALE * 0.01)

# timeout for synthesis
TIME_LIMIT = 30 * 60 * 60
# number of processes to start
CPU_NUM = 8


# memory address where emulation starts
ADDRESS = 0x1000000

# constants from STOKE
p_u = 0.16
beta = 0.1
p_o = 0.5
p_c = 0.16
p_s = 0.16
p_i = 0.16

# changed w_m; in the paper this was 3 but there 64 bit registers were used
w_m = 1

p_o_thresh = p_o
p_c_thresh = p_o_thresh + p_c
p_s_thresh = p_c_thresh + p_s
p_i_thresh = 1.0

# defining types of instructions (which operands they take)
INST_UNUSED = -1
INST_LBL = 0
INST_REG = 1
INST_REG_REG = 2
INST_REG_CONST = 3

# list of instructions based on type
INST_LISTS = [
    ["jmp", "je", "jne", "jz", "jg", "jge", "jl", "jle"], # instructions taking one label
    ["inc", "dec", "not", "neg", "mul", "imul"],# "div", "idiv"], # instructions taking one register
    ["mov", "add", "sub", "and", "or", "xor", "cmp"], # instructions taking two registers
    ["mov", "add", "sub", "and", "or", "xor", "cmp", "shl", "shr"] # instructions taking one register and one constant
]

# list of labels
LBL_LIST = [".L" + str(i) for i in range(MAX_LEN)]
# list of registers
REG_LIST = ["al", "bl", "cl", "dl"]
# list of constants
CONST_LIST = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "16", "32", "64", "128", "255"]

# types of operands
LBL_OP = 0
REG_OP = 1
CONST_OP = 2

# types of operands based on instruction type
OP_TYPES = [[LBL_OP, None], [REG_OP, None], [REG_OP, REG_OP], [REG_OP, CONST_OP]]

# list to index types of operands
OPERAND_LISTS = [LBL_LIST, REG_LIST, CONST_LIST]

# class to define instructions
class Instruction:
    def __init__(self, inst_type, opcode, op1, op2=None):
        self.opcode = opcode
        self.inst_type = inst_type
        self.op1 = op1
        self.op2 = op2

        # get operand types
        self.op1_type = OP_TYPES[inst_type][0]
        self.op2_type = OP_TYPES[inst_type][1]

        # cache string version
        self.text = self.inst_str()

    def new_opcode(self, opcode):
        self.opcode = opcode
        # cache string version
        self.text = self.inst_str()

    def new_op1(self, op1):
        self.op1 = op1
        # cache string version
        self.text = self.inst_str()

    def new_op2(self, op2):
        self.op2 = op2
        # cache string version
        self.text = self.inst_str()

    def inst_str(self):
        '''
        returns string for instruction
        '''

        # find out # of operands
        if self.inst_type < 2:
            return self.opcode + "\t" + self.op1
        return self.opcode + "\t" + self.op1 + ", " + self.op2

    def __str__(self):
        return self.text

class UNUSED(Instruction):
    def __init__(self):
        self.opcode = None
        self.inst_type = INST_UNUSED
        self.op1 = None
        self.op2 = None

        # get operand types
        self.op1_type = None
        self.op2_type = None

        # cache string version
        self.text = self.inst_str()

    def inst_str(self):
        '''
        returns string for instruction
        '''

        return ""


# function to construct code from list of instructions
def code_text_from_inst(inst_list, add_timeout_check=True):
    '''
    Add label for each line, instruction str
    '''
    code_str = ""
    for i in range(len(inst_list)):
        # add label
        code_str += ".L" + str(i) + ":\n"
        # add instruction
        code_str += inst_list[i].text + "\n"

    # in the end: add line that lets us find out if the code timed out or not
    # since unicorn doesn't tell us...
    if add_timeout_check:
        code_str += "mov    esi, 3141"

    return code_str

def assemble_code(ks, code_str):
    try:
        # Assemble the code
        asm, _ = ks.asm(code_str)
        # convert the array of integers into bytes
        asm_bytes = bytes(asm)

        return asm_bytes
    except Exception as e:
        print(e)
        print(code_str)

def run_x86_test(emu, prog_len, test):
    '''
    runs given test case (tuple for inputs to al,bl)
    returns output (register dl)
    '''

    # Write testcase inputs to al,bl
    emu.reg_write(UC_X86_REG_AL, test[0])
    emu.reg_write(UC_X86_REG_BL, test[1])
    # emulate code; set timeout since we might run into infinite loops
    try:
        emu.emu_start(ADDRESS, ADDRESS + prog_len, timeout=EMU_TIMEOUT)
    except:
        # tell caller that we ran into CPU exception (probably because of div instruction)
        return False, None, None, None, None

    # whether execution terminated is in ESI
    done = (emu.reg_read(UC_X86_REG_ESI) == 3141)


    # result is in dl; but read all registers to
    # check if one of the others contains correct answer
    al = emu.reg_read(UC_X86_REG_AL)
    bl = emu.reg_read(UC_X86_REG_BL)
    cl = emu.reg_read(UC_X86_REG_CL)
    dl = emu.reg_read(UC_X86_REG_DL)
    #print(">>> DL = %u" % dl)

    return done, al, bl, cl, dl


def switch_operand(inst_list):
    '''
    switch out one of the operands of a random operation at random
    for a random operand of the same type
    '''

    inst_index = random.randrange(MAX_LEN)

    # let's make this actually do something even if we randomly hit UNUSED token;
    # find next instruction if it exists
    while inst_list[inst_index].inst_type == INST_UNUSED:
        inst_index += 1
        if inst_index >= MAX_LEN:
            return

    # instruction could hold one or two operands; choose one
    if (random.randrange(2) == 1) and (inst_list[inst_index].op2_type):
        inst_list[inst_index].new_op2(random.choice(OPERAND_LISTS[inst_list[inst_index].op2_type]))
    else:
        inst_list[inst_index].new_op1(random.choice(OPERAND_LISTS[inst_list[inst_index].op1_type]))

def switch_opcode(inst_list):
    '''
    switch out the opcode of a random operation at random
    for one with operands of the same type
    '''

    inst_index = random.randrange(MAX_LEN)

    # let's make this actually do something even if we randomly hit UNUSED token;
    # find next instruction if it exists
    while inst_list[inst_index].inst_type == INST_UNUSED:
        inst_index += 1
        if inst_index >= MAX_LEN:
            return

    inst_list[inst_index].new_opcode(random.choice(INST_LISTS[inst_list[inst_index].inst_type]))

def swap_lines(inst_list):
    '''
    swap two random lines; could be either code or "UNUSED" token
    '''

    inst_index1 = random.randrange(MAX_LEN)
    inst_index2 = random.randrange(MAX_LEN)

    inst_list[inst_index1], inst_list[inst_index2] = inst_list[inst_index2], inst_list[inst_index1]

def random_inst(allow_jmp):
    '''
    returns random instruction; used for initialization and instruction replacing
    '''

    # with prob p_u we generate UNUSED token
    if random.random() < p_u:
        return UNUSED()

    # generate new instruction type; check whether we are allowed to use jumps;
    # even then don't use them that often
    if allow_jmp and (random.random() < JUMP_PROB):
        new_inst_type = random.randint(0,3)
    else:
        new_inst_type = random.randint(1,3)

    # check if we need one or two operands
    if new_inst_type > 1:
        return Instruction(new_inst_type, \
                                random.choice(INST_LISTS[new_inst_type]), \
                                random.choice(OPERAND_LISTS[OP_TYPES[new_inst_type][0]]), \
                                random.choice(OPERAND_LISTS[OP_TYPES[new_inst_type][1]]))
    else:
        return Instruction(new_inst_type, \
                                random.choice(INST_LISTS[new_inst_type]), \
                                random.choice(OPERAND_LISTS[OP_TYPES[new_inst_type][0]]))

def switch_inst(inst_list):
    '''
    select one instruction at random and replace it with random new instruction
    could be either code or "UNUSED" token
    "UNUSED" token is created with a probability of p_u
    '''

    inst_index = random.randrange(MAX_LEN)

    inst_list[inst_index] = random_inst(ALLOW_JMP)

def hamming_dist(v1, v2):
    '''
    calculate how many bits differ in two 8-bit values
    by xor'ing, shifting and adding up values
    there is probably a better way?
    '''

    xor = v1 ^ v2
    dist = 0
    for i in range(8):
        dist += (xor >> i) & 1

    return dist

def gen_test_cases(test_num):
    '''
    generate test cases to run on GB, x86
    contain two 8-bit values (for a,b/al,bl)
    '''
    return [(random.randint(0,255), random.randint(0,255)) for i in range(test_num)]


def translate(test_cases, test_results, done, ret_queue):
    '''
    use STOKE-inspired synthesis algorithm to find x86 program that is equivalent to GB one

    '''
    global EMU_TIMEOUT

    # initialize keystone assembler
    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    # Initialize emulator in x86_64 mode
    emu = Uc(UC_ARCH_X86, UC_MODE_64)
    # map 2MB memory for this emulation
    emu.mem_map(ADDRESS, 2 * 1024 * 1024)


    solved = False
    steps = 0

    # create initial proposal consisting of random instructions;
    # don't include jumps so we can be sure that initial code won't time out
    current = [random_inst(allow_jmp=False) for i in range(MAX_LEN)]
    current_cost = 10000000

    # test runtime of initial program to set limit for timeout

    prog_text = code_text_from_inst(current)
    asm_bytes = assemble_code(ks, prog_text)
    emu.mem_write(ADDRESS, asm_bytes)

    start_time = time.time()

    emu.emu_start(ADDRESS, ADDRESS + len(asm_bytes))

    EMU_TIMEOUT = int(UC_SECOND_SCALE * (time.time() - start_time) * 20)


    while not solved:
        proposed = current.copy()

        steps += 1
        if done.value == 1:
            ret_queue.put((False, proposed, steps))
            return

        # sample move on current program
        rand_num = random.random()

        if rand_num < p_o_thresh:
            switch_operand(proposed)
        elif rand_num < p_c_thresh:
            switch_opcode(proposed)
        elif rand_num < p_s_thresh:
            swap_lines(proposed)
        else:
            switch_inst(proposed)

        prog_text = code_text_from_inst(proposed)

        #print("\n\nProgram:")
        #print(prog_text)

        # assemble code
        asm_bytes = assemble_code(ks, prog_text)

        # write to emulator memory
        emu.mem_write(ADDRESS, asm_bytes)

        # sample random variable and run test cases;
        # if we exceed cost threshold we can stop and discard this program
        p = random.random()
        thresh = current_cost - math.log(p)/beta

        # keep running sums for costs
        # we also want to get costs if result is in wrong register
        # (with w_m penalty at every step)
        proposed_costs = [0,0,0,0]
        i = 0
        cancelled = False

        # go through test cases, calculate cost sum
        for i in range(len(test_cases)):
            success, al, bl, cl, dl = run_x86_test(emu, len(asm_bytes), test_cases[i])

            # if the execution timed out, discard program
            if not success:
                cancelled = True
                break

            # calculate hamming distances between test results; add to costs
            proposed_costs[0] += hamming_dist(al, test_results[i]) + w_m
            proposed_costs[1] += hamming_dist(bl, test_results[i]) + w_m
            proposed_costs[2] += hamming_dist(cl, test_results[i]) + w_m
            proposed_costs[3] += hamming_dist(dl, test_results[i])

            if min(proposed_costs) > thresh:
                cancelled = True
                break

        # check if we managed to stay below threshold
        if not cancelled:
            # did we find a solution?
            if min(proposed_costs) == 0:
                solved = True
            # otherwise, take this proposal as new current program
            else:
                current = proposed
                current_cost = min(proposed_costs)

    # we found an equivalent program -> end this and all other processes
    done.value = 1

    ret_queue.put((True, proposed, steps))
    return

def cleanup(test_cases, test_results, prog):
    '''
    clean up code by removing a line, testing if the code still works and repeating
    '''
    # initialize keystone assembler
    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    # Initialize emulator in x86_64 mode
    emu = Uc(UC_ARCH_X86, UC_MODE_64)
    # map 2MB memory for this emulation
    emu.mem_map(ADDRESS, 2 * 1024 * 1024)

    i = 0
    while i < len(prog):
        # remove UNUSED tokens
        if prog[i].inst_type == INST_UNUSED:
            prog.pop(i)
        else:
            # test if tests still work after removing this line
            proposed = prog.copy()
            proposed.pop(i)


            prog_text = code_text_from_inst(proposed)

            # assemble code
            asm_bytes = assemble_code(ks, prog_text)

            # write to emulator memory
            emu.mem_write(ADDRESS, asm_bytes)

            cancelled = False

            # go through test cases, calculate cost sum
            for j in range(len(test_cases)):
                success, al, bl, cl, dl = run_x86_test(emu, len(asm_bytes), test_cases[j])

                # test if we get correct result; otherwise discard this program
                if (not success) or (dl != test_results[j]):
                    cancelled = True
                    break

            # if all tests passed, accept as new program
            if not cancelled:
                prog = proposed
            else:
                i += 1

    return prog



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('program', metavar='P', \
                help='the GB program (in the gb_programs directory) to translate to x86')

    args = parser.parse_args()

    PROG_NAME = args.program


    print("\n---------------------------------")

    print("\nTranslating Game Boy Program '" + PROG_NAME + "'.")

    # generate test cases
    test_cases = gen_test_cases(TEST_NUM)

    # run test cases on GB, get results
    test_results = run_gb_testcases(PROG_NAME, test_cases)

    # shared value that indicates if an equivalent program was found;
    # terminates parallel processes if 1
    done = Value('i', 0)

    # start threads to find equivalent program
    ret_queue = Queue()
    rets = []

    start_time = time.time()

    try:
        processes =  []

        # disable SIGINT so child processes don't catch ctrl+c
        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)

        for i in range(CPU_NUM):
            p = Process(target=translate, args=(test_cases, test_results, done, ret_queue))
            processes.append(p)

        # restore SIGINT so parent process catches ctrl+c
        signal.signal(signal.SIGINT, original_sigint_handler)

        for p in processes:
            p.start()

        for p in processes:
            ret = ret_queue.get(timeout=TIME_LIMIT)
            rets.append(ret)

        for p in processes:
            p.join()

    except KeyboardInterrupt:
        print("\nCaught KeyboardInterrupt, terminating workers")
        for p in processes:
            p.terminate()
            p.join()
        sys.exit()
    except Empty:
        print("\nTimed out without finding a program :(")
        for p in processes:
            p.terminate()
            p.join()
        sys.exit()

    # retrieve results
    steps = 0
    prog = None
    for ret in rets:
        steps += ret[2]
        if ret[0]:
            prog = ret[1]


    print("\nSUCCESS AFTER " + str(steps) + " STEPS (%.2f seconds)!" % (time.time() - start_time))

    print("BEFORE CLEANUP:")
    print(code_text_from_inst(prog, add_timeout_check=False))

    prog = cleanup(test_cases, test_results, prog)

    print("\nFINAL PROGRAM:")
    print(code_text_from_inst(prog, add_timeout_check=False))
