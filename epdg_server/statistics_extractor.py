import glob

# Funzione per leggere file basati su un pattern
def read_files(pattern):
    file_list = glob.glob(pattern)  # Trova i file corrispondenti al pattern
    lines = []
    for file_path in file_list:
        with open(file_path, "r") as file:
            lines.extend([line.strip() for line in file])  # Legge le righe dai file
    return lines

# Leggi i file corrispondenti ai diversi gruppi DH
list_768 = read_files("results/SUPPORT_ENC_NULL_DH_768MODP_*.txt")
list_1024 = read_files("results/SUPPORT_ENC_NULL_DH_1024MODP_*.txt")
list_2048 = read_files("results/SUPPORT_ENC_NULL_DH_2048MODP_*.txt")


# Conteggio complessivo (tutti gli elementi)
unique_elements_overall = set()
count_overall = 0

# Aggiungi elementi dalla lista 2048
for item in list_768:
    if item not in unique_elements_overall:
        unique_elements_overall.add(item)
        count_overall += 1

# Aggiungi elementi dalla lista 3072
for item in list_1024:
    if item not in unique_elements_overall:
        unique_elements_overall.add(item)
        count_overall += 1

# Aggiungi elementi dalla lista 4096
for item in list_2048:
    if item not in unique_elements_overall:
        unique_elements_overall.add(item)
        count_overall += 1


# Conteggio italiano (solo MCC 222)
unique_elements_italian = set()
count_italian = 0

# Aggiungi elementi italiani dalla lista 768
for item in list_768:
    if "mcc222" in item and item not in unique_elements_italian:
        unique_elements_italian.add(item)
        count_italian += 1

# Aggiungi elementi italiani dalla lista 1024
for item in list_1024:
    if "mcc222" in item and item not in unique_elements_italian:
        unique_elements_italian.add(item)
        count_italian += 1

# Aggiungi elementi italiani dalla lista 1536
for item in list_2048:
    if "mcc222" in item and item not in unique_elements_italian:
        unique_elements_italian.add(item)
        count_italian += 1

# Stampa i risultati
print(f"Il totale degli elementi unici (complessivo) è: {count_overall}")
print(f"Il totale degli elementi unici con MCC italiano è: {count_italian}")
