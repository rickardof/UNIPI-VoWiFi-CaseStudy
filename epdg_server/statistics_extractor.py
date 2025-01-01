#!/usr/bin/env python3

import glob


# function to read files based on a pattern
def read_files(pattern):
    file_list = glob.glob(pattern)  # find files matching the pattern
    lines = []
    for file_path in file_list:
        with open(file_path, "r") as file:
            lines.extend([line.strip() for line in file])  # read lines from the files
    return lines


# read files corresponding to different dh groups
list_768 = read_files("results/SUPPORT_ENC_NULL_DH_768MODP_*.txt")
list_1024 = read_files("results/SUPPORT_ENC_NULL_DH_1024MODP_*.txt")
list_2048 = read_files("results/SUPPORT_ENC_NULL_DH_2048MODP_*.txt")


# overall count (all elements)
unique_elements_overall = set()
count_overall = 0

for item in list_768:
    if item not in unique_elements_overall:
        unique_elements_overall.add(item)
        count_overall += 1
for item in list_1024:
    if item not in unique_elements_overall:
        unique_elements_overall.add(item)
        count_overall += 1
for item in list_2048:
    if item not in unique_elements_overall:
        unique_elements_overall.add(item)
        count_overall += 1


# italian count (only mcc 222)
unique_elements_italian = set()
count_italian = 0

for item in list_768:
    if "mcc222" in item and item not in unique_elements_italian:
        unique_elements_italian.add(item)
        count_italian += 1
for item in list_1024:
    if "mcc222" in item and item not in unique_elements_italian:
        unique_elements_italian.add(item)
        count_italian += 1
for item in list_2048:
    if "mcc222" in item and item not in unique_elements_italian:
        unique_elements_italian.add(item)
        count_italian += 1

print(f"> The total number of unique elements (overall) is: {count_overall}")
print(f"> The total number of unique elements with Italian MCC is: {count_italian}")
