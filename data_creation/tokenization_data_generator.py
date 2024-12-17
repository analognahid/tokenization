import os,re
import json 
import os.path

import hashlib, random
from simhash import Simhash

from num2words import num2words
from transformers import AutoTokenizer
import matplotlib.pyplot as plt
import difflib, pickle



# tokenizer = AutoTokenizer.from_pretrained("./../models/bert_pretokenizer_trained")
# special_tokens = {"additional_special_tokens": ["\n" , ' ']}
# tokenizer.add_special_tokens(special_tokens)


# def replace_random_tokens(insructions):
#     lst = insructions.copy()
#     # Calculate the number of items to replace
#     num_to_replace = int(len(lst) * 0.15)
    
#     # Get random indices to replace
#     indices_to_replace = random.sample(range(len(lst)), num_to_replace)
    
#     # Replace items at the selected indices
#     for idx in indices_to_replace:
#         lst[idx] = '[mask]'
    
#     return lst



def replace_num_with_word(input_string , replace_dict):
    def num_to_word(match):
        number = int( match.group(0))
        return num2words(replace_dict[number]).replace(' ','').replace('-',"")
    result_string = re.sub(r'\b\d+\b', num_to_word, input_string)
    return result_string



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




DATA_PATH = "/home/raisul/ANALYSED_DATA/tokenization_data/"
NEW_DATA_PATH = "/home/raisul/ANALYSED_DATA/tokenization_data_single_functions/"
SUB_FOLDER = ''
json_files = sorted( [os.path.join(DATA_PATH, f) for f in os.listdir(DATA_PATH) ] )

# json_files =json_files [0:100]



counter = 0
instruction_count_list=[]

for i,j_file in enumerate( json_files):

    if i%1000==0:
        print(counter)
    
    with open(j_file, 'r') as file:
        j_data = json.load(file)
        

        for function_data in j_data:
            
            if counter<80000:
                SUB_FOLDER = 'train/'
            else:
                SUB_FOLDER = "test/"


            if counter>=100000:

                with open("instruction_count_list.pkl", "wb") as file:  # 'wb' means write in binary mode
                    pickle.dump(instruction_count_list, file)

                
                exit()
            
            output = {}
            
            disassembly, paramTypes  , returnType ,  signature, opadd_list , opscalar_list = function_data


            instruction_count = len(disassembly.split('\n'))

            if  instruction_count>=30 and instruction_count<=100 :
                instruction_count_list.append(instruction_count)
                disassembly_decimal = replace_hex_with_decimal(disassembly)

                #num to words all

                numbers = [int(s) for s in re.findall(r'\b\d+\b', disassembly_decimal)]
                numbers = sorted(set(numbers) , reverse=True)
                number_word_dict={}
                
                for ix,n in enumerate(numbers):
                    number_word_dict[n] = len(numbers)-1 -ix

                disassembly_num_to_words = replace_num_with_word(disassembly_decimal , number_word_dict)


                #adddr to words

                # print(disassembly)
                all_addr_list = [  '0x'+addr for addr in opadd_list if addr]
                all_addr_list = list(set(all_addr_list))
                all_addr_list = sorted(all_addr_list, key=lambda x: int(x, 16))
                all_addr_list_as_int = [int(x, 16) for x in all_addr_list]
                # print(disassembly_decimal)
                # print(all_addr_list_as_int)

                disassembly_addr_to_num = disassembly_decimal
                for idx,addr in  enumerate(all_addr_list_as_int):
                    disassembly_addr_to_num = disassembly_addr_to_num.replace( str(addr) , 'addr'+str(idx) )

                # print(disassembly_addr_to_decimal)
                # break
                # disassembly_decimal_tokens,disassembly_num_to_words_tokens, disassembly_addr_to_num_tokens =  tokenizer.tokenize([disassembly_decimal , disassembly_num_to_words, disassembly_addr_to_num ])
                # disassembly_decimal_tokens = tokenizer.tokenize(disassembly_decimal)
                # masked_disassembly_decimal_tokens = replace_random_tokens(disassembly_decimal_tokens)

                # disassembly_num_to_words_tokens = tokenizer.tokenize(disassembly_num_to_words)
                # masked_disassembly_num_to_words_tokens  = replace_random_tokens(disassembly_num_to_words_tokens)

                # disassembly_addr_to_num_tokens =   tokenizer.tokenize(disassembly_addr_to_num)
                # masked_disassembly_addr_to_num_tokens =replace_random_tokens(disassembly_addr_to_num_tokens)


                # if tokenizer.convert_tokens_to_string(disassembly_decimal_tokens) != disassembly_decimal :

                #     print("\n\nNOT EQUAL")
                    
                #     print(disassembly_decimal )
                #     print(tokenizer.convert_tokens_to_string(disassembly_decimal_tokens))

                output = {
                    'disassembly_original': disassembly,
                    'disassembly_decimal':{
                        'input':disassembly_decimal,
                                           },
                    'disassembly_all_number_to_words':{
                        'input':disassembly_num_to_words,
                        },
                    'disassembly_addresses_to_words' : {
                        'input':disassembly_addr_to_num,
                        },

                    'signature':{
                        'string':signature,
                        'paramTypes': paramTypes,
                        'returnType':returnType
                    },


                    'meta_data':{
                        'addresses':opadd_list,
                        'scalar':opscalar_list
                    }


                }
            
                # print(instruction_count)
                # hash = str(Simhash(disassembly).value)

                try:
                    # hash=  str(int(hashlib.sha1(function_data.encode("utf-8")).hexdigest(), 16) % (10 ** 8))
                    hash = str(Simhash(disassembly).value)

                    newfilepath = NEW_DATA_PATH + SUB_FOLDER+ hash+'.json'

                    if os.path.isfile(newfilepath) is False:
                        with open(newfilepath, 'w') as fw:
                            json.dump(output, fw, indent=2)
                            counter = counter + 1 

                    else:
                        print("DUPLICAETe|\n")

                except Exception as e:
                    print(e)    


