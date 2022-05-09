# to emulate x86 code
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_SECOND_SCALE
# to access relevant registers
from unicorn.x86_const import UC_X86_REG_AL, UC_X86_REG_BL, UC_X86_REG_DL
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

# defining types of instructions (which operands they take)
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
    def __init__(self, name, inst_type, op1, op2):
        self.name = name
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
            return self.name + "\t" + self.op1
        return self.name + "\t" + self.op1 + ", " + self.op2

    def __str__(self):
        return self.inst_str()

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
    # emulate code; time out after a second
    EMU.emu_start(ADDRESS, ADDRESS + prog_len, timeout=UC_SECOND_SCALE)

    # result is in dl
    # now print out the DL register
    dl = EMU.reg_read(UC_X86_REG_DL)
    print(">>> DL = %u" % dl)

    return dl


def switch_operand(inst):
    '''
    switch out one of the operands of this operation at random
    for a random operand of the same type
    '''

    ini


proposed = [Instruction("add", INST_REG_REG, "al", "bl"),
    Instruction("mov", INST_REG_REG, "dl", "al")]

code_str = code_text_from_inst(proposed)

print(code_str)

# assemble x86
asm_bytes = assemble_code(code_str)

# write machine code to be emulated to memory
EMU.mem_write(ADDRESS, asm_bytes)

for test in [(0,0),(1,2),(128,127)]:
    print(run_x86_test(len(asm_bytes), test))
