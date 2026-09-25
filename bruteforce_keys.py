import os
import gpv_decrypt


# These are just to remove non key-like values
UNIQUE_BYTES_IN_16 = 10 
UNIQUE_BYTES_IN_32 = 2 * UNIQUE_BYTES_IN_16

def getEntropy(data, numUnique):
    return len(set(list(data))) >= numUnique 


# Note that the AoE2DE_s.exe is packed and thus needs either extracting or decrypting (see: https://www.youtube.com/watch?v=Dp-IvqfCoL0 )
# Something like pe-sieve64 can easily dump the unpacked exe from a running game


exe_loc = ""

for exe_locs in os.listdir("."):
    if exe_locs.endswith("AoE2DE_s.exe"):
        exe_loc = exe_locs
if exe_loc == "":
    for exe_locs in os.listdir("exe"):
        if exe_locs.endswith("AoE2DE_s.exe"):
            exe_loc = os.path.join("exe", exe_locs)

with open(exe_loc, "rb") as binary_file:
    binary_data = binary_file.read()
binary_length = len(binary_data)

# gpv files have an AES key depending on the first 4 bytes of the header, encrypted through AES-CTR

# As of Update #185872, the "Viking Saga" DLC update, the key structure has changed:
# Instead of the AES keys being encrypted via TEA, they are instead directly in
# the binary. This makes it significantly easier to find and confirm them.

### Finding the keyblob
# The AES keys are all located together in a neat structure:
# 32 bytes of AES Key
# 64 bytes of 0
# 16 bytes of AES IV
# 32 bytes of 0
# Repeat for a total of 9 key-iv pairs - the key order is currently Base, Pomp, DLC4, Phil, Pap1, Peru, Prov, Pari, Port

potential_aes_keys = []

for i in range(binary_length-0x90):
    if (binary_data[i+32:i+96] == b"\x00"*64) and (binary_data[i+112:i+144] == b"\x00"*32) and (getEntropy(binary_data[i:i+32], UNIQUE_BYTES_IN_32)) and (getEntropy(binary_data[i+96:i+112], UNIQUE_BYTES_IN_16)):
        potential_aes_keys.append((binary_data[i:i+32], binary_data[i+96:i+112]))

# We could check that these are all together, but currently only the 9 key pairs are found

print(f"Found {len(potential_aes_keys)} potential AES key-iv pairs")


# Fetching the sbox is non-trivial. The sbox is not located in a single block, but spread across several opcodes and directly loaded into memory
# Further, an inconsistent amount is loaded in at a time, before jumping to another function to load more in - so we'd have to either
#   parse a lot of opcodes - which we're trying to avoid anyway -
#   or test every set of 4 bytes and seeing if it makes a possible s-box, and then compare such compositions to see if there exists an inverse
# The S-Box is, however, not considered a crucial element of AES security
test_sbox = "63 7C 69 90 66 32 9A 0E 64 41 CB A9 9F FA D5 AA 65 24 F7 77 37 1D 83 EB 98 1A 2A 7D BD 25 02 EE E5 E7 45 50 29 C4 EC A7 CC F0 5C 4D 13 96 A2 09 9E FF 5A A1 C7 6F E9 15 0C 1B C5 97 56 14 A5 B6 20 D6 21 11 70 0D 7F 4E 46 52 35 4B A4 C9 01 1E 31 0F 2F 17 FC DB 74 30 DE 48 1C 95 06 53 D3 67 18 FD 2D 1F 7A 8D 87 75 B4 26 E0 71 A3 82 58 07 D4 BA DA A8 B5 D9 9C CF F9 60 D8 12 00 79 89 04 C2 B8 3C 61 42 76 DF 6C EA 49 54 62 E8 B3 F5 0B F1 28 7E D2 CD 23 F2 8E 80 F8 36 E3 D7 22 DD F3 4A 2E 55 10 C0 B1 59 43 AC 68 3F BB 6D AF CA C6 38 B9 73 AE DC BC 9D C3 D1 4C FE A6 3B 92 E4 2B 5B FB 2C F6 C1 B2 5D 8F EF 78 91 5F 94 72 ED 40 88 B7 44 34 27 E1 6A 05 86 C8 93 8A 7B 84 51 E6 3D 99 0A 33 BF 39 03 8C 08 6B 3E 85 19 CE B0 8B AB A0 E2 47 BE 4F 5E 9B 57 AD 6E 81 16 3A D0 F4"

print("Gathering testing data")


# Get everything in the "in" folder, read the name and the first 16 bytes of data
#   - this should be "32 2E 30 30" plus either "06 00 00 00 02 00 00 00 03 00 00 00", "0B 00 00 00 02 00 00 00 03 00 00 00", "32 2E 30 30 01 00 00 00 0B 00 00 00 61 6F 65 63", or "32 2E 30 30 01 00 00 00 0B 00 00 00 70 63 61 6D"
# these should be 2.00, then dependency count, then each dependency. - whatever a dependency is, just going by what aoe2campaign parsers call them
test_data_lst = {}
for file in os.listdir("in"):
    with open(os.path.join("in", file), "rb") as in_file:
        in_file_name = in_file.read(4)[::-1]
        in_file.read(8) # discard length
        test_data = in_file.read(16)
        if in_file_name not in test_data_lst:
            test_data_lst[in_file_name] = [test_data]
        elif test_data not in test_data_lst[in_file_name]:
            test_data_lst[in_file_name].append(test_data)

print("Testing key-iv pairs against testing data")

# We can check if an AES-IV pair is correct by attempting to decrypt an aoe2campaign.gpv from that dlc.
# We know that the first 4 bytes probably matches "2.00" - this may change if new campaign file versions are introduced, or if non campaign gpvs introduced
# With enough keys there may be false positives, in which case we would need to check more data

# Thanks to the keys being in plaintext, we can just directly try each potential key.
# We can't validate a key without a gpv file to check it against

found_keys = {}

for key, iv in potential_aes_keys:
##    print(f"key: {key}, iv: {iv}")
    found_key = False
    for test_data_name in test_data_lst:
        for test_data in test_data_lst[test_data_name]:
            if gpv_decrypt.decryptTest(test_data, key, iv, test_sbox): # if the first 4 bytes of the decrypted test data are "2.00"...
                print(test_data_name, "keys found")
                found_key = True
                found_keys[test_data_name] = {"key":key, "iv":iv}
                break
        if found_key:
            break
    

# Finally, output the found keys to file

if len(found_keys) > 0:
    print("Outputting found keys to keys directory")
    if not os.path.exists("keys"):
        os.mkdir("keys")

    for f_key in found_keys:
        with open(os.path.join("keys",f_key.decode()+".key"), "wb") as key_f:
            key_f.write(found_keys[f_key]["key"])
        with open(os.path.join("keys",f_key.decode()+".iv"), "wb") as iv_f:
            iv_f.write(found_keys[f_key]["iv"])
    with open("aoe2de.sbox", "wb") as sbox_f:
        sbox_f.write(bytes.fromhex(test_sbox))

