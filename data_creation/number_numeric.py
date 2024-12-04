import torch

torch.cuda.is_available()
#!/usr/bin/env python3

import sys,os
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
from capstone import *
from capstone.x86 import *
from num2words import num2words
import os
import json 

import sys,os,re






DATA_PATH = "/home/raisul/ANALYSED_DATA/mlm_x86_O2_d4"

json_files = [os.path.join(DATA_PATH, f) for f in os.listdir(DATA_PATH) ]



def get_training_corpus():

    all = []

    for k, j_file in enumerate(json_files):
        if k==5:
            break
        try:
            with open(j_file, 'r') as file:
                j_data = json.load(file)
                print(len(j_data))
                for function_data in j_data:
                    print(function_data)
                    break
                    all.append(function_data)
            print("- - - - -"*10)
        except :
            pass
    # all.sort(key=len)
    return all
    
  

text = get_training_corpus()
text = text[0:20]
print("Functions Count: ",len(text), '\n')

# for program in text:

#     print(program)
