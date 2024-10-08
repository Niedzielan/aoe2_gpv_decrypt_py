import os
from collections import Counter, defaultdict
import gpv_decrypt, tea_gen_keys


# Constants
# If bruteforcing finds nothing, you can try changing these - fewer unique bytes, more distance, more leniency with finding duplicates (i.e. 3 = triplicates allowed)
# These will cause some degree of slowdown!
# From 14, 2, 0xA0 taking 3-3.5 minutes, to 12, 3, 0x100 taking 60+

UNIQUE_BYTES_IN_16 = 14 # at 15 only DLC3, DLC4, Phil found, at 16 none found
UNIQUE_BYTES_IN_32 = 2 * UNIQUE_BYTES_IN_16

TEA_KEY_MAX_COUNT = 2 # min count is 2 as well,

# As of update #118476, DLC1 and DLC2 TEA distance needs increasing, doubled to 0x100.
TEA_IV_DIST_FROM_KEY_MAX = 0x100 # at 0x80, finds all in 2.5-3 minutes instead of 3-3.5


# gpv keys are specific for each DLC as determined via the first 4 bytes of the gpv header
# gpv files are encrypted through AES-CTR
# The AES keys are stored in the binary encrypted via TEA
# Each key and each DLC has a unique TEA key
# Note that the base AoE2DE_s.exe binary is packed, so either unpacking it manually (good luck)
# or dumping the exe after it is already unpacked (easy, with something like pe-sieve64)

# There are two keyblobs, one containing the TEA encrypted AES-keys (and AES-ivs), another containing the keys for TEA itself

### TEA-encrypted AES-key/iv pairs

# The TEA encrypted AES-keys keyblob is a simple format consisting of:

# AA
#
# BB BB BB BB
# BB BB BB BB
# BB BB BB BB
# BB BB BB BB
# BB BB BB BB
# BB BB BB BB
# BB BB BB BB
# BB BB BB BB
#
# CC * 61
#
# DD EE
#
# FF
#
# GG GG GG GG
# GG GG GG GG
# GG GG GG GG
# GG GG GG GG
#
# HH * 29
#
# II JJ
#
# AA_2 ... (next DLC)

# Where BBs are the 8 4-byte values of the TEA encrypted AES-key, and GGs are 4 4-byte values of the TEA encrypted AES-IV
#
# AA has the property of being 1 larger than DD. If AA < 0x80, then EE is the same as AA, otherwise EE is 0xFF
# Note that in every known case, AA is odd. Thus all bits except the least significant are identical to DD
# When retreiving the key, the following takes place:
# AA signed extend into 64bit register (so if AA < 0x80, register is 00000000000000AA, otherwise FFFFFFFFFFFFFFAA)
# AA << 8 (thus 00...00AA00 or FF...FFAA00)
# (AA << 8) || AA (thus, 00...00AAAA or FF...FFAAAA)
# EEDD ^ ((AA << 8) || AA)
#   If AA <0x80, then this means EE=AA and DD=AA-1, where AA is odd, thus this always results in 00...000001
#   Similarly, if AA >= 0x80, EE=0xFF, DD=AA-1, this is always FF...FF0001)
# Take the least significant 2 bytes, or 0001
# This is then compared to the key length (0x20), and proceeds if lower. Otherwise, jmps out (presumed jump out because invalid key?)
# In all testing, this has always been 1 < 20.
# Although it doesn't affect key generation for our purposes, it does give a handy check to see if a block is a potential key.
# The CCs have currently no known purpose.
#
# This repeats for the IV with FF through JJ, with a 0x10 length and 29 bytes of unknown data
# Thus, potential key blocks are found by checking (i[0] == i[0x60] + 1) && (i[0x60+1] == i[0x60+0x30] + 1) && iv...

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


def getEntropy(data, numUnique):
    return len(set(list(data))) >= numUnique

print("finding potential TEA-encrypted key-iv pair blocks")

potential_key_blocks = {}

for i in range(binary_length-0x90):
    if ((binary_data[i] == binary_data[i+0x60-2] + 1)
        and (binary_data[i+0x60] == binary_data[i+0x60+0x30-2] + 1)
        and ((binary_data[i] < 0x80 and binary_data[i] == binary_data[i+0x60-1])
             or (binary_data[i] >= 0x80 and binary_data[i+0x60-1] == 0xFF))
        and ((binary_data[i+0x60] < 0x80 and binary_data[i+0x60] == binary_data[i+0x60+0x30-1])
             or (binary_data[i+0x60] >= 0x80 and binary_data[i+0x60+0x30-1] == 0xFF))):
        if getEntropy(binary_data[i+1:i+0x21],UNIQUE_BYTES_IN_32) and getEntropy(binary_data[i+0x61:i+0x71],UNIQUE_BYTES_IN_16):
            potential_key_blocks[i] = binary_data[i:i+0x90]

# We know that there is no gap between these keys, so we can just group them together.

potential_keyblobs = {}
current_potential_keyblob_index = -1
running_index = -1

print("sorting potential TEA-encrypted key-iv pair blocks into potential keyblobs")

# We also assume that there are at least 2 key blocks in the keyblob.
for j in potential_key_blocks:
    if j == running_index + 0x90:
        running_index = j
        if current_potential_keyblob_index not in potential_keyblobs:
            potential_keyblobs[current_potential_keyblob_index] = [current_potential_keyblob_index, j]
        else:
            potential_keyblobs[current_potential_keyblob_index].append(j)
    else:
        current_potential_keyblob_index = j
        running_index = j

potential_keyblobs_lst = []
for k in potential_keyblobs:
    tmpblob = b''
    for l in potential_keyblobs[k]:
        tmpblob += potential_key_blocks[l]
    potential_keyblobs_lst.append(tmpblob)

# This leaves a single keyblob - though in case of future differences, we still store and loop through all possiblities. For now this is just a list of a single element

### TEA keys

# The TEA keys are trickier - although they have a keyblob, there seems to be irregular lengths of data between keys
# Generally this ranges from 33-40 bytes, but between the DLC1 key and DLC1 IV there are 105, or 0x69. It would probably be safe to assume 0x80, but we choose to be a bit safer at 0xA0
# The other hint is that each TEA key is also located somewhere else in the binary. In fact, those other locations are the ones actually used - the keyblob is only parsed after the game has launched, for unknown reason (it itself is decrypted into... something)
# We have to rely on those two findings, plus the facts that keys don't overlap and the assumption that the IV is soon after the Key, to narrow results down
# Of course, general methodologies of key bruteforcing can be used. Entropy can be assumed to be high (with 16 bytes, there should be at least 10 unique bytes - we assume 14 unique here for performance reasons)

# Thus, we are looking for a group of key-like bytes with another set of key-like bytes within reasonable distance (say, 0xA0) where both of these also occur elsewhere in the binary
# This isn't particularly fast, especially in python, but it's still reasonable when using collections (I assume there's some CPython speedup, where looping through twice is a lot slower)

print("finding potential TEA-keys")

potential_tea_keys = []
potential_tea_keys_dict = defaultdict(list)
# We create a list of potential keys, and a dict of keys and their locations in the binary data. Since we want to check locations against eachother, this is pretty handy

for q in range(binary_length-0x10):
    potential_q = binary_data[q:q+0x10]
    if not getEntropy(potential_q, UNIQUE_BYTES_IN_16):
        continue
    potential_tea_keys.append(potential_q)
    potential_tea_keys_dict[potential_q].append(q)


def get_duplicates(array):
    c = Counter(array)
    #return {k for k in c if c[k] == 2}
    return {k for k in c if c[k] >= 2 and c[k] <= TEA_KEY_MAX_COUNT}
potential_tea_keys_duplicates = get_duplicates(potential_tea_keys) # I tried just using potential_tea_keys_dict.keys() and it didn't work, so... extra memory usage it is

del potential_tea_keys

# We actually want the index to be the key
tmp2 = {indx:byts for byts in potential_tea_keys_duplicates for indx in potential_tea_keys_dict[byts]}

del potential_tea_keys_dict
del potential_tea_keys_duplicates

# And for the earlier indices to be first
tmp3 = {k:v for k,v in sorted(tmp2.items())}

del tmp2

# We can actually do those two steps at once
# potential_tea_keys_dict_rev[q] = potential_q instead of potential_tea_keys_dict[potential_q].append(q)
# tmp3 = {indx:byts for indx, byts in potential_tea_keys_dict_rev.items() if byts in potential_tea_keys_duplicates}
# but it's actually slightly slower - even after making get_duplicates return a set instead of a list (otherwise it's *significantly* slower)
# ~2s vs ~1.5s so the difference is minimal

potential_tea_keyblobs = []

running_index = -1
tmp_grp = [[],[]]

def getcount(tmpx):
    prev_ind = tmpx[0]
    running_ind = 0
    totalcount = 1
    for ind in tmpx[1:]:
        diffind = ind-prev_ind+running_ind
        if diffind <= 0x10:
            running_ind = diffind
        else:
            totalcount += 1
            running_ind = 0
        prev_ind = ind
    return totalcount

# We then want to group nearby potential TEA keys together - into pseudo-keyblobs
# Again we want the locations and the data - though we could just use lookups on binary_data and just store the locations

for r in tmp3:
    if r > running_index + TEA_IV_DIST_FROM_KEY_MAX:
        #append old group
        if len(tmp_grp[0]) >= 14: # we know there are at least 7 DLCs with a key and iv each
            if getcount(tmp_grp[0]) >= 14: # and these keys should not overlap
                potential_tea_keyblobs.append(tmp_grp)
        tmp_grp = [[r], [tmp3[r]]] # create new group
    else:
        tmp_grp[0].append(r)
        tmp_grp[1].append(tmp3[r])
    running_index = r

del tmp3
    
# the current known keyblob has length 60, sorting leaves the massive blobs until later (e.g. otherwise keyblob 7 is 1000+). Saves a lot of time, though not guaranteed
potential_tea_keyblobs.sort(key=lambda item: len(item[0]))
# There are 778 potential keyblobs at the time of writing

def arr_to_int(array):
    return int.from_bytes(bytes(array), "little")

def int_to_arr(int_in):
    return int.to_bytes(int_in, 4, "little")

def split_arr(array, count = 4):
    tmp_arr = []
    for i in range(len(array)//count):
        tmp_arr.append(arr_to_int(array[i*count:(i+1)*count]))
    return tmp_arr

def get_key_list_from_keyblob(kb):
    keys = []
    kb_ind = 1 # keyblob index
    kb_keydist = 0x60 # keyblob key distance, aka 0x60
    kb_ivdist = 0x30 # keyblob iv distance, aka 0x30
    while kb_ind < len(kb):
        keys.append([split_arr(kb[kb_ind : kb_ind + 0x20]), split_arr(kb[kb_ind + kb_keydist : kb_ind + kb_keydist + 0x10])])
        kb_ind += kb_keydist + kb_ivdist
    return keys

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

print("Testing key/iv / tea pairs against testing data")

# We can check if an AES-IV pair is correct by attempting to decrypt an aoe2campaign.gpv from that dlc.
# We know that the first 4 bytes probably matches "2.00" - this may change if new campaign file versions are introduced, or if non campaign gpvs introduced
# With enough keys there may be false positives, in which case we would need to check more data

# For every potential TEA-encrypted AES Key-IV pair keyblob (only 1 at the time of writing)
#   Process the keyblob and retreive the TEA-encrypted AES Key / IV pairs 
#   Then for each potential key/iv pair: (7 pairs at the time of writing)
#       For each potential TEA keyblob (778 at the time of writing) (or the one which contains the keys, if found)
#           For each potential TEA key in the keyblob
#               For each close TEA key (between 0x10 and 0xA0 distance after)
#                   Use these to decrypt the AES Key-IV pair
#                   For each test case
#                       Attempt to AES decrypt the test case
#                       If successful, remember the potential TEA keyblob, then break out to the next potential key/iv pair


found_keys = {}
found_key = False

for w in potential_keyblobs_lst:
    keylist = get_key_list_from_keyblob(w)
    #keydict = tea_gen_keys.setup_keys(w)
    for k in keylist:
        found_key_tmp = False
        key = k[0]
        iv = k[1]
        tmpy=0
        for ptk in potential_tea_keyblobs:
            if found_key: # once we know where the TEA keys are we can skip this loop from now
                ptk = found_tea_keyblob
            else:
                tmpy +=1
                t_len = len(ptk[0])
            for t in range(t_len-1):
                dec_key = tea_gen_keys.do_decipher_2(key, tea_gen_keys.split_arr(ptk[1][t])) # TEA decipher the key into a potential AES key
                nxt_ind = t+1
                while nxt_ind < t_len and ptk[0][nxt_ind] <= ptk[0][t] + TEA_IV_DIST_FROM_KEY_MAX:
                    if ptk[0][nxt_ind] < ptk[0][t] + 0x10:
                        nxt_ind += 1
                        continue
                    potential_iv = tea_gen_keys.do_decipher_2(iv, tea_gen_keys.split_arr(ptk[1][nxt_ind])) # TEA decipher the iv into a potential AES iv
                    nxt_ind += 1

                    dec_key_b = b""
                    for d in dec_key:
                        dec_key_b += int.to_bytes(d, 4, "little")
                    dec_iv_b = b""
                    for d in potential_iv:
                        dec_iv_b += int.to_bytes(d, 4, "little")
                    for test_data_name in test_data_lst:
                        for test_data in test_data_lst[test_data_name]:
                            if gpv_decrypt.decryptTest(test_data, dec_key_b, dec_iv_b, test_sbox): # if the first 4 bytes of the decrypted test data are "2.00"...
                                print(test_data_name, "keys found")
                                found_key = True # we don't need to check other potential keyblobs
                                found_key_tmp = True # We can skip the remaining loops for this key/iv
                                found_keys[test_data_name] = {"key":dec_key_b, "iv":dec_iv_b}
                                found_keyblob = w
                                found_tea_keyblob = ptk
                                break
                        if found_key_tmp:
                            break
                    if found_key_tmp:
                        break
                if found_key_tmp:
                    break
            if found_key:
                break
    if found_key:
        break


del potential_keyblobs_lst
del potential_tea_keyblobs

# Finally, output the found keys to file

if found_key:
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

