from __future__ import print_function

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
# actually you don't need to import by yourself, but it makes much "explicit"
import __main__ as ghidra_app


import json , collections
from collections import OrderedDict

from ghidra.program.model.data import Pointer, StructureDataType
import re

import hashlib
# from ghidra.program.model.listing import OperandType
from ghidra.program.model.lang import OperandType


def unoverflow(x):
    return (abs(x) ^ 0xff) + 1


def to_hex(integer):
    return '{:02x}'.format(integer)

import re



def convert(typename):

    if 'undefined' in typename:
        return "None"
    
    valids = [ 'uint','ulong','uchar','ushort','ulonglong','longlong','schar','int' , 'char', 'float', 'long', 'double', 'short', 'bool', 'void']
    for tk in valids:
        if tk in typename:

            if len(typename)< len(tk)+3:#structs can have tk in their name.
            
                if '[' in typename:
                    return "array "+tk
                elif '*' in typename:
                    return '*'+tk
                elif typename == tk:
                        return tk
            
    if "*" in typename:
        return "*struct"

    
    return "None"





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

        # print('\n')
        # print(inst)

        op_addr = None
        op_scalar = None
        for opi in range(inst.numOperands):
            operandType = inst.getOperandType(opi)
            address = inst.getAddress(opi)
            if address and str(address) in inst.toString():
                op_addr =str(address)
                # print("address >" ,address)
            
            scalar = inst.getScalar(opi)
            if scalar  and str(scalar) in inst.toString():
                op_scalar = str(scalar)
                # print("scalar: >" , scalar)


            # if operandType & OperandType.IMMEDIATE:
            #     scalar = inst.getScalar(opi)
            #     print(scalar)


        instructions.append([ (int( inst.getAddress().subtract(0).toString(),16)) , inst.toString(),op_addr ,op_scalar ]) 

    if len(instructions)<10:
        return None
    
    instructions = sorted(instructions, key=lambda x: x[0], reverse=False) 

    fun_str = ""
    fun_opaddr = []
    fun_scalar = []
    for addr,inst_str, opaddr, opscalar in instructions:
        fun_str+=  (inst_str) +"\n"
        fun_opaddr.append(opaddr)
        fun_scalar.append(opscalar)

    return fun_str , fun_opaddr , fun_scalar



def getAddress(program, offset):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)





def extract_function_parameters(func):
    parameters = func.getParameters()
    param_list = []


    # return
    for param in parameters:

        param_type = convert(param.getDataType().getName())
        param_list.append(param_type)


    return param_list


def disassemble(program):
    '''disassemble given program.
    Args:
        program (ghidra.program.model.listing.Program): program to be disassembled
    Returns:
        string: all disassembled functions 
    '''


    disasm_result = []
    param_list = []
    signature_list = []
    return_type_list = []
    opadd_list = []
    opscalar_list = []

    
    funcs = program.getListing().getFunctions(True)
    for func in funcs:

        
        return_type = func.getReturnType().getName()
        return_type_list.append(return_type)

        rdata = _get_instructions(func)
        if rdata:
            disassembled_function, fun_opaddr , fun_scalar  = rdata


            if disassembled_function != None:
                disasm_result.append(disassembled_function)
                param_list.append(extract_function_parameters(func))
                signature_list.append(func.getSignature())

                opadd_list.append(fun_opaddr)
                opscalar_list.append(fun_scalar)


                
            else:
                continue 

    return disasm_result, param_list , return_type_list , signature_list ,opadd_list , opscalar_list

from ghidra.program.model.address import Address
def run():


    output_path = str(getScriptArgs()[0])

    start_file_offset = 0  
    ghidra_app.currentProgram.setImageBase(ghidra_app.getCurrentProgram().getAddressFactory().getDefaultAddressSpace().getAddress(start_file_offset), True)

    function_disassembly_list, params_list ,returns_list , signature_list ,opadd_list , opscalar_list= disassemble(ghidra_app.currentProgram)
    # disassembled = sorted(disassembled, key=lambda x: x[0], reverse=False)
    # print(signature_list , '\n', params_list , returns_list)


        


    exeName = ghidra_app.currentProgram.getName()
    exeLocation = ghidra_app.currentProgram.getExecutablePath()
    print("DBG base: " , ghidra_app.currentProgram.getImageBase())

    data_arr = []
    for x in range(len(function_disassembly_list)):
        #signature_list[x].arguments.tolist()
        # print( params_list[x] , convert(signature_list[x].getReturnType().getName() ), "  > " ) # dir(signature_list[x] )
        
        data_arr.append( [function_disassembly_list[x], params_list[x]  , convert(signature_list[x].getReturnType().getName() ) ,  signature_list[x].toString() ,opadd_list[x] , opscalar_list[x]])
        # hash = Simhash(function_disassembly_list[x])
        # print(hash)

    output = output_path + '.disassembly.json'
    with open(output, 'w') as fw:
        json.dump(data_arr, fw, indent=2)
        print('[*] success. save to -> {}'.format(output ))
    
# Starts execution here
if __name__ == '__main__':
    run()
    

