# to emulate x86 code
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_SECOND_SCALE
# to access relevant registers
from unicorn.x86_const import UC_X86_REG_AL, UC_X86_REG_BL, UC_X86_REG_DL, UC_X86_REG_ESI
# to assemble x86 code
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

import random

# initialize keystone assembler
KS = Ks(KS_ARCH_X86, KS_MODE_64)

# memory address where emulation starts
ADDRESS = 0
# Initialize emulator in x86_64 mode
EMU = Uc(UC_ARCH_X86, UC_MODE_64)
# map 2MB memory for this emulation
EMU.mem_map(ADDRESS, 2 * 1024 * 1024)

# maximum program length
MAX_LEN = 8
# allow jumps? Probably makes things a lot more complicated
ALLOW_JMP = False

# constants from STOKE
p_u = 0.16
beta = 0.1
p_o = 0.5
p_c = 0.16
p_s = 0.16
p_i = 0.16

# defining types of instructions (which operands they take)
INST_UNUSED = -1
INST_LBL = 0
INST_REG = 1
INST_REG_REG = 2
INST_REG_CONST = 3

# list of instructions based on type
INST_LISTS = [
    ["jmp", "je", "jne", "jz", "jg", "jge", "jl", "jle"], # instructions taking one label
    ["inc", "dec", "not", "neg", "mul", "div"], # instructions taking one register
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

    def inst_str(self):
        '''
        returns string for instruction
        '''

        # find out # of operands
        if self.inst_type < 2:
            return self.opcode + "\t" + self.op1
        return self.opcode + "\t" + self.op1 + ", " + self.op2

    def __str__(self):
        return self.inst_str()

class UNUSED(Instruction):
    def __init__(self):
        self.opcode = None
        self.inst_type = INST_UNUSED
        self.op1 = None
        self.op2 = None

        # get operand types
        self.op1_type = None
        self.op2_type = None

    def inst_str(self):
        '''
        returns string for instruction
        '''

        return ""


# function to construct code from list of instructions
def code_text_from_inst(inst_list):
    '''
    Add label for each line, instruction str
    '''
    code_str = ""
    for i in range(len(inst_list)):
        # add label
        code_str += ".L" + str(i) + ":\n"
        # add instruction
        code_str += inst_list[i].inst_str() + "\n"

    # in the end: add line that lets us find out if the code timed out or not
    # since unicorn doesn't tell us...
    code_str += "mov    esi, 3141"

    return code_str

def assemble_code(code_str):
    # Assemble the code
    asm, _ = KS.asm(code_str)
    # convert the array of integers into bytes
    asm_bytes = bytes(asm)

    return asm_bytes

def run_x86_test(prog_len, test):
    '''
    runs given test case (tuple for inputs to al,bl)
    returns output (register dl)
    '''

    # Write testcase inputs to al,bl
    EMU.reg_write(UC_X86_REG_AL, test[0])
    EMU.reg_write(UC_X86_REG_BL, test[1])
    # emulate code; time out after a quarter of a second
    EMU.emu_start(ADDRESS, ADDRESS + prog_len, timeout=int(UC_SECOND_SCALE * 0.25))

    # whether execution terminated is in ESI
    done = (EMU.reg_read(UC_X86_REG_ESI) == 3141)

    # result is in dl
    dl = EMU.reg_read(UC_X86_REG_DL)
    #print(">>> DL = %u" % dl)

    return done, dl


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
        inst_list[inst_index].op2 = random.choice(OPERAND_LISTS[inst_list[inst_index].op2_type])
    else:
        inst_list[inst_index].op1 = random.choice(OPERAND_LISTS[inst_list[inst_index].op1_type])

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

    inst_list[inst_index].opcode = random.choice(INST_LISTS[inst_list[inst_index].inst_type])

def swap_lines(inst_list):
    '''
    swap two random lines; could be either code or "UNUSED" token
    '''

    inst_index1 = random.randrange(MAX_LEN)
    inst_index2 = random.randrange(MAX_LEN)

    inst_list[inst_index1], inst_list[inst_index2] = inst_list[inst_index2], inst_list[inst_index1]

def switch_inst(inst_list):
    '''
    select one instruction at random and replace it with random new instruction
    could be either code or "UNUSED" token
    "UNUSED" token is created with a probability of p_u
    '''

    inst_index = random.randrange(MAX_LEN)

    # with prob p_u we generate UNUSED token
    if random.random() < p_u:
        inst_list[inst_index] = UNUSED()
        return

    # generate new instruction type; check whether we are allowed to use jumps
    if ALLOW_JMP:
        new_inst_type = random.randint(0,3)
    else:
        new_inst_type = random.randint(1,3)

    # check if we need one or two operands
    if new_inst_type > 1:
        inst_list[inst_index] = Instruction(new_inst_type, \
                                random.choice(INST_LISTS[new_inst_type]), \
                                random.choice(OPERAND_LISTS[OP_TYPES[new_inst_type][0]]), \
                                random.choice(OPERAND_LISTS[OP_TYPES[new_inst_type][1]]))
    else:
        inst_list[inst_index] = Instruction(new_inst_type, \
                                random.choice(INST_LISTS[new_inst_type]), \
                                random.choice(OPERAND_LISTS[OP_TYPES[new_inst_type][0]]))


proposed = [Instruction(INST_REG_REG, "add", "al", "bl"),
    Instruction(INST_REG_REG, "mov", "dl", "al"),
    UNUSED(),
    UNUSED(),
    UNUSED(),
    UNUSED(),
    UNUSED(),
    UNUSED(),]

code_str = code_text_from_inst(proposed)

print(code_str)

# assemble x86
asm_bytes = assemble_code(code_str)

# write machine code to be emulated to memory
EMU.mem_write(ADDRESS, asm_bytes)

for test in [(0,0),(1,2),(128,127)]:
    print(run_x86_test(len(asm_bytes), test))
