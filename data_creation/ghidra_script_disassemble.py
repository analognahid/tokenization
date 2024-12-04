from __future__ import print_function

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
# actually you don't need to import by yourself, but it makes much "explicit"
import __main__ as ghidra_app


import json , collections
from collections import OrderedDict



def unoverflow(x):
    return (abs(x) ^ 0xff) + 1


def to_hex(integer):
    return '{:02x}'.format(integer)

import re

def replace_hex_with_decimal(input_string):
    # Regular expression to find hexadecimal numbers prefixed with "0x" or "0X"
    hex_pattern = r'0[xX][0-9a-fA-F]+'
    
    # Function to convert each found hex number to decimal
    def hex_to_decimal(match):
        hex_value = match.group(0)  # Extract the matched hex number
        decimal_value = str(int(hex_value, 16))  # Convert hex to decimal
        return decimal_value
    
    # Substitute all hex numbers in the string with their decimal equivalents
    result_string = re.sub(hex_pattern, hex_to_decimal, input_string)
    
    return result_string




def _get_instructions(func):
    
    baseAddress = ghidra_app.currentProgram.getImageBase()
    
    instructions = []

    # Get instructions in function
    func_addr = func.getEntryPoint()
    insts = ghidra_app.currentProgram.getListing().getInstructions(func_addr, True)

    

    # Process each instruction
    for inst in insts:
        
        if ghidra_app.getFunctionContaining(inst.getAddress()) != func:
            break

        instructions.append([ (int( inst.getAddress().subtract(0).toString(),16)) , inst.toString()]) 

    if len(instructions)<5:
        return None
    instructions = sorted(instructions, key=lambda x: x[0], reverse=False) 

    fun_str = ""
    for addr,inst_str in instructions:
        fun_str+=  str(addr)+"|" + replace_hex_with_decimal(inst_str) +"\n"#replace_hex_with_decimal

    return fun_str



def getAddress(program, offset):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)



def disassemble(program):
    '''disassemble given program.
    Args:
        program (ghidra.program.model.listing.Program): program to be disassembled
    Returns:
        string: all disassembled functions 
    '''


    disasm_result = []

    funcs = program.getListing().getFunctions(True)
    for func in funcs:
        
        disassembled_function = _get_instructions(func)
        if disassembled_function != None:
            disasm_result.append(disassembled_function)
        else:
            continue 

    return disasm_result

from ghidra.program.model.address import Address
def run():


    output_path = str(getScriptArgs()[0])

    start_file_offset = 0  
    ghidra_app.currentProgram.setImageBase(ghidra_app.getCurrentProgram().getAddressFactory().getDefaultAddressSpace().getAddress(start_file_offset), True)

    function_disassembly_list = disassemble(ghidra_app.currentProgram)
    # disassembled = sorted(disassembled, key=lambda x: x[0], reverse=False)


    exeName = ghidra_app.currentProgram.getName()
    exeLocation = ghidra_app.currentProgram.getExecutablePath()


    
    print("DBG base: " , ghidra_app.currentProgram.getImageBase())
    
    # disassembled_dict = OrderedDict()
    # for key, value in disassembled:

        
    #     inst_file_offset = ghidra_app.currentProgram.getMemory().getAddressSourceInfo(value.getAddress()).getFileOffset() 

    #     if int(key)!= int(inst_file_offset):
    #         print("FILE offset ERROR !" , hex(key) , hex(inst_file_offset))
    #         return
    #     disassembled_dict[ hex(key)  ] = value.toString()

    # print("DBG:  disassembled_dict", disassembled_dict)
    output = output_path + '.disassembly.json'
    with open(output, 'w') as fw:
        json.dump(function_disassembly_list, fw, indent=2)
        print('[*] success. save to -> {}'.format(output ))
    
# Starts execution here
if __name__ == '__main__':
    run()
    

