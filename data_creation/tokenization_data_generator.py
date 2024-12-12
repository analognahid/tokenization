import os
import json 
import os.path

import hashlib
from simhash import Simhash



DATA_PATH = "/home/raisul/ANALYSED_DATA/tokenization_data/"
NEW_DATA_PATH = "/home/raisul/ANALYSED_DATA/tokenization_data_single_functions/"

json_files = [os.path.join(DATA_PATH, f) for f in os.listdir(DATA_PATH) ] 

json_files =json_files [0:10]



all_data = []

for i,j_file in enumerate( json_files):

    if i%1000==0:
        print(len(all_data))
    
    with open(j_file, 'r') as file:
        j_data = json.load(file)
        

        for function_data in j_data:

            
            disassembly, paramTypes  , returnType ,  signature = function_data

            print(disassembly)

            instruction_count = len(disassembly.split('\n'))

            if  instruction_count>20 and instruction_count<50 :

            
                # print(instruction_count)

                all_data.append(function_data)


                # print(disassembly, paramTypes  , returnType ,  signature)
                
                # try:
                #     # hash=  str(int(hashlib.sha1(function_data.encode("utf-8")).hexdigest(), 16) % (10 ** 8))
                #     hash = str(Simhash(disassembly).value)


                #     if os.path.isfile(NEW_DATA_PATH + hash) is False:
                #         with open(NEW_DATA_PATH + hash+'.json', 'w') as output:
                #             output.write(function_data)
                #     else:
                #         print("DUPLICAETe|\n")

                # except:
                #     pass



print(len(all_data))