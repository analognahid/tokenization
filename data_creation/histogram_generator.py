import pickle
import os,re
import json 
import os.path

import hashlib, random
from simhash import Simhash

from num2words import num2words
from transformers import AutoTokenizer
import matplotlib.pyplot as plt
import difflib, pickle



def plotHoistogram(numbers):
    plt.figure(figsize=(6, 6))
    plt.hist(numbers, bins=14, edgecolor='black', color='skyblue')

    # Add titles and labels
    # plt.title('Frequency Distribution of Input Sizes', fontsize=16)
    plt.xlabel('Instruction Count', fontsize=13)
    plt.ylabel('Frequency', fontsize=14)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.xticks(range(min(numbers), max(numbers) + 1,5) )  # Show every integer length on x-axis



    # Save the plot as a PDF
    plt.tight_layout()
    plt.savefig("histogram.pdf", format="pdf")
    plt.show()


# File path of the saved list
file_path = "instruction_count_list.pkl"

# Load the list from the .pkl file
with open(file_path, "rb") as file:  # 'rb' means read in binary mode
    loaded_list = pickle.load(file)
    plotHoistogram(loaded_list)

