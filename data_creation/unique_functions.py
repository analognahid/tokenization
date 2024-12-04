import os
import json 
import os.path

import hashlib
from simhash import Simhash



DATA_PATH = "/home/raisul/ANALYSED_DATA/mlm_x86_O2_d4"
NEW_DATA_PATH = "/home/raisul/ANALYSED_DATA/mlm_x86_O2_d4_single_functions/"

json_files = [os.path.join(DATA_PATH, f) for f in os.listdir(DATA_PATH) ]

# json_files =json_files [0:5]


all_data = []





for j_file in json_files:

    
    with open(j_file, 'r') as file:
        j_data = json.load(file)
        

        for function_data in j_data:
            
            try:
                # hash=  str(int(hashlib.sha1(function_data.encode("utf-8")).hexdigest(), 16) % (10 ** 8))
                hash = str(Simhash(function_data).value)


                if os.path.isfile(NEW_DATA_PATH + hash) is False:
                    with open(NEW_DATA_PATH + hash, 'w') as output:
                        output.write(function_data)
                else:
                    print("DUPLICAETe|\n")

            except:
                pass



