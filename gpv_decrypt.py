#! /usr/bin/env python3

## Algorithm: AES-256-CTR with custom substitution box (s-box)
## key and iv are stored in the binary via TEA encryption
## Each DLC has a unique key/iv determined via the first 4 bytes in the gpv header

## It is possible to reencrypt to gpv via running decrypt(...) on the aoe2campaign - encryption and decryption are the same thing in AES-256-CTR

def printl(list_of_bytes):
    print([f'{i:x}' for i in list_of_bytes])


## Init constants

rcon = "00 01 02 04 08 10 20 40 80 1B 36"
rcon = [x for x in bytes.fromhex(rcon)]

s_box = None # Specific to AoE2DE, please supply manually. By default, this script reads from aoe2de.sbox

def xor_bytes(a, b):
    for i in range(len(a)):
        a[i] = a[i] ^ b[i]
    return a

def sub_bytes(state):
    for i in range(len(state)):
        state[i] = s_box[state[i]]
    return state
    

def shift_rows(state):
    newstate = [
        state[0],
        state[1+4],
        state[2+8],
        state[3+12],

        state[4],
        state[5+4],
        state[6+8],
        state[(7+12) %len(state)],

        state[8],
        state[9+4],
        state[(10+8) %len(state)],
        state[(11+12) %len(state)],

        state[12],
        state[(13+4) %len(state)],
        state[(14+8) %len(state)],
        state[(15+12) %len(state)]
        ]
    for i in range(len(state)):
        state[i] = newstate[i]
    return state

def add_round_key(state, key):
    return xor_bytes(state, key)


xtime = lambda a: 0xff & (a << 1) ^ ( 0x1b * (a>>7) )

def inc_bytes(out):
    """ Returns a new byte array with the value increment by 1 """
    for i in reversed(range(len(out))):
        if out[i] == 0xFF:
            out[i] = 0
        else:
            out[i] += 1
            break
    return out

def dec_bytes(out):
    """ Returns a new byte array with the value decremented by 1 """
    for i in reversed(range(len(out))):
        if out[i] == 0x00:
            out[i] = 0xFF
        else:
            out[i] -= 1
            break
    return out

def mix_columns(state):
    for j in range(4):
        tmp = state[4*j] ^ state[4*j + 1] ^ state[4*j + 2] ^ state[4*j + 3]
        t0 = state[4*j]
        state[4*j] = state[4*j] ^ tmp  ^ xtime(state[4*j] ^ state[4*j + 1])
        state[4*j + 1] = state[4*j + 1] ^ tmp ^ xtime(state[4*j + 1] ^ state[4*j + 2])
        state[4*j + 2] = state[4*j + 2] ^ tmp ^ xtime(state[4*j + 2] ^ state[4*j + 3])
        state[4*j + 3] = state[4*j + 3] ^ tmp ^ xtime(state[4*j + 3] ^ t0)
    
    return state

def rotword(word_in):
    newword = word_in[1:] + word_in[:1]
    for i in range(len(word_in)):
        word_in[i] = newword[i]

def subword(word_in):
    for i in range(len(word_in)):
        word_in[i] = s_box[word_in[i]]

def key_expansion(master_key):
    # see https://en.wikipedia.org/wiki/AES_key_schedule
    
    N = 8 ## length of key in 32-bit = 4 byte words
    key_words = [master_key[i:i+4] for i in range(0, 32, 4)] # if i < N, W_i = K_i
    R = 15 ## number of round keys needed
    # total 4*15 - 1 = 59 expanded 32-bit words
    words = key_words

    for i in range(N, 4*R):
        prev_word = words[-1][:]
        prev_Nword = words[-N][:]
        word = prev_word[:]
        if i % N == 0:
            rotword(word)
            subword(word)
            word[0] ^= rcon[int(i/N)]
            xor_bytes(word, prev_Nword)
        elif i % N == 4: # if N > 6
            subword(word)
            xor_bytes(word, prev_Nword)
        else:
            xor_bytes(word, prev_Nword)
        words.append(word)
    return words

    #return round_keys


def decrypt(body, key, iv):
    length = len(body)
    expanded_key_words = key_expansion(key)
    round_keys = [j for i in expanded_key_words for j in i]
    message = [x for x in body]
    if length % 16 != 0:
        padding = 16 - (length % 16)
        message.extend([0]*padding)
    message_blocks = int(len(message) / 16)
    state = iv[:]
    iv_copy = iv[:]

    for k in range(message_blocks):
        message_block = message[k*16:(k+1)*16]

        round_key = round_keys[0:16]
        add_round_key(state, round_key)
        for i in range(1, 15):
            sub_bytes(state)
            shift_rows(state)
            if i != 14: ## last loop, skip mix columns
                mix_columns(state)
            round_key = round_keys[16*i:16*(i+1)]
            add_round_key(state, round_key)
            
        xor_bytes(message_block, state)

        for l in range(16):
            message[k*16 + l] = message_block[l]
            
        inc_bytes(iv_copy)
        for j in range(len(state)):
            state[j] = iv_copy[j]

    message = bytes(message[:length])

    return message


import os
import sys, getopt
import struct

def printHelp():
    print ('gpv_decrypt.py -i <input> -o <output> -k <keyfile> -v <ivfile> -s <sboxfile> [-a] [-m magicheader]')
    print ('gpv_decrypt.py -i <input> -o <output> -k <keydir> [-v <ivdir>] -s <sboxfile> [-a] [-m magicheader]')
    print ('default: gpv_decrypt.py -i in -o out -k keys -s aoe2de.sbox')
    print()
    print ('input, output, key, iv can be supplied as either files or dirs')
    print ('if supplying key, iv as dirs, file names must either match the magic header or the input filename')
    print ('\t Note that the magic header is reversed, e.g. in a gpv it may be "esaB", where they keyfile should be "Base.key"')
    print ('"-a" will force input directory to process all files, not just gpv. No effect if input is file')
    print ('\t if supplying key, iv as dirs, files must have extensions ".key" and ".iv" respectively')
    print ('"-m" can supply a header. This will assume you want to encrypt files')
    print ('\t Note that encrypted files have a 4-byte magic and 8-byte length')
    print ('\t Only the magic needs to be supplied')
    print ('\t The header will be reversed, so e.g. "-m Base" will create a b"esaB" header')
    print ('\t This also only supports a single header. If you want to encrypt with different headers, run the command multiple times')
    print()
    print("Keys, IVs, and S-Box should be binary files containing only the bytes of their respective data.")
    print("For example, the sbox file should have, when using a hex editor, '63 7c 77 7b ...' for 256 bytes total.")
    print("\t Note that the AoE2DE sbox has different values to the standard AES S-Box")
    print("The key should be 32 bytes and the IV 16 bytes.")

def decryptTest(body, key_in, iv_in, sbox_in):
    #key = [x for x in bytes.fromhex(key_in)]
    #iv = [x for x in bytes.fromhex(iv_in)]
    key = [x for x in key_in]
    iv = [x for x in iv_in]
    global s_box
    s_box = [x for x in bytes.fromhex(sbox_in)]
    #print(key)
    #print(iv)
    #print(body)
    #print(s_box)
    processed_body = decrypt(body, key, iv)
    if b"\x32\x2E\x30\x30" not in processed_body:
        return False
    else:
        return True
    

def main(argv):
    inputfile = 'in'
    outputfile = 'out'
    keyfile = 'keys'
    ivfile = ''
    sboxfile = "aoe2de.sbox"
    inputDir = True
    outputDir = True
    keyDir = True
    ivDir = True
    gpvOnly = True
    magicheader = ''
    encryption = False
    try:
        opts, args = getopt.getopt(argv,"hai:o:k:v:s:m:",["ifile=","ofile=","keyfile=","ivfile=","sbox=","magicheader="])
    except getopt.GetoptError:
        printHelp()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            printHelp()
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
            inputDir = os.path.isdir(inputfile) 
        elif opt in ("-o", "--ofile"):
            outputfile = arg
            if not os.path.exists(outputfile):
                print("output does not exist, assuming it is a directory")
                os.makedirs(outputfile)
                outputDir = True
            else:
                outputDir = os.path.isdir(outputfile)
        elif opt in ("-k", "--keyfile"):
            keyfile = arg
            keyDir = os.path.isdir(keyfile)
        elif opt in ("-v", "--ivfile"):
            ivfile = arg
            ivDir = os.path.isdir(ivfile)
        elif opt == "-a":
            gpvOnly = False
        elif opt in ("-m", "--magicheader"):
            magicheader = arg
            encryption = True
        elif opt in ("-s", "--sbox"):
            sboxfile = arg
            
    if keyDir and ivfile == '':
        print("keydir specified but ivdir not specified. Assuming ivdir is the same as keydir")
        ivfile = keyfile
    elif not keyDir and ivfile == '':
        print("keyfile specified but ivfile not specified. Assuming ivfile has the same name as keyfile")
        ivfile = os.path.split(keyfile)[0] + os.path.sep + ".".join(os.path.split(keyfile)[1].split(".")[:-1]) + ".iv"
        ivDir = False
        
    if inputDir and not outputDir:
        print("Can't output a directory to a file")
        sys.exit(2)
    elif inputDir and not keyDir:
        print("Warning: single keyfile specified for an entire directory.")
        print("Assuming all inputs use the same key")
        
    if inputDir:
        print ('Input dir is:', inputfile)
    else:
        print ('Input file is:', inputfile)
    if outputDir:
        print ('Output dir is:', outputfile)
        if not os.path.exists(outputfile):
            os.makedirs(outputfile)
    else:
        print ('Output file is:', outputfile)
    if keyDir:
        print ('Key dir is:', keyfile)
    else:
        print ('Key file is:', keyfile)
    if ivDir:
        print ('IV dir is:', ivfile)
    else:
        print ('IV file is:', ivfile)
    if not os.path.exists(sboxfile):
        print("Couldn't find sbox file in root, assuming in keys")
        sboxfile = os.path.join("./keys", sboxfile)
    print ("S-Box file is:", sboxfile)
    print()

    with open(sboxfile, "rb") as sbf:
        global s_box
        s_box = sbf.read()
        s_box = [x for x in s_box]
        global inv_s_box
        inv_s_box = [0] * len(s_box)
        for i in range(len(s_box)):
            inv_s_box[s_box[i]] = i

    infileList = []
    if inputDir:
        for file in os.listdir(inputfile):
            if file.endswith(".gpv") or not gpvOnly:
                infileList.append(os.path.join(inputfile, file))
    else:
        infileList.append(inputfile)

    keyfileList = []
    if keyDir:
        for file in os.listdir(keyfile):
            if file.endswith(".key"):
                keyfileList.append(os.path.join(keyfile, file))
    else:
        keyfileList.append(keyfile)

    ivfileList = []
    if ivDir:
        for file in os.listdir(ivfile):
            if file.endswith(".iv"):
                ivfileList.append(os.path.join(ivfile, file))
    else:
        ivfileList.append(ivfile)

    for inf in infileList:
        print("Processing file:", inf)
        inf_name = os.path.split(inf)[-1]
        inf_name_base = inf_name.split(".")[0]
        if encryption:
            with open(inf, "rb") as infi:
                body = infi.read()
                length = len(body)
                length_b = struct.pack('<Q', length)
                magic_b = magicheader[::-1].encode()
        else: # Decryption
            with open(inf, "rb") as infi:
                magic_b = infi.read(4)
                magicheader = magic_b.decode()[::-1]
                length_b = infi.read(8)
                length = int.from_bytes(length_b, "little")
                body = infi.read()
        if keyDir:
            for keyf in keyfileList:
                keyf_name = os.path.split(keyf)[-1]
                keyf_name_base = keyf_name.split(".")[0]
                if keyf_name_base == inf_name_base:
                    keyfi = keyf
                    break
                elif keyf_name_base == magicheader:
                    keyfi = keyf # specific names can override magic header names
            if "keyfi" not in locals():
                print("Key file not found! Make sure it has the same name as the gpv (e.g. eecam1.key) or as the magic header (e.g. DLC2.key)")
                sys.exit()
        else:
            keyfi = keyfileList[0]
        with open(keyfi, "rb") as keyfil:
            key = keyfil.read()
            key = [x for x in key]
            
        if ivDir:
            for ivf in ivfileList:
                ivf_name = os.path.split(ivf)[-1]
                ivf_name_base = ivf_name.split(".")[0]
                if ivf_name_base == inf_name_base:
                    ivfi = ivf
                    break
                elif ivf_name_base == magicheader:
                    ivfi = ivf # specific names can override magic header names
            if "ivfi" not in locals():
                print("IV file not found! Make sure it has the same name as the gpv (e.g. eecam1.iv) or as the magic header (e.g. DLC2.iv)")
                sys.exit()               
        else:
            ivfi = ivfileList[0]
        with open(ivfi, "rb") as ivfil:
            iv = ivfil.read()
            iv = [x for x in iv]

        processed_body = decrypt(body, key, iv) # AES-CTR encryption/decryption are the same

        if encryption:
            if outputDir:
                out_name = outputfile + os.path.sep + inf_name + ".gpv"
            else:
                out_name = outputfile
            print("Creating file:", out_name)
            with open(out_name, "wb") as outf:
                outf.write(magic_b)
                outf.write(length_b)
                outf.write(processed_body)
        else: # Decryption
            if b"aoe2scenario" not in processed_body:
                print("Warning: verification string \"aoe2scenario\" not found after decryption")
            if outputDir:
                out_name = inf_name
                if out_name.endswith(".gpv"):
                    out_name = out_name[:-4]
                out_name = outputfile + os.path.sep + out_name
            else:
                out_name = outputfile
            print("Creating file:", out_name)
            with open(out_name, "wb") as outf:
                outf.write(processed_body)
                
if __name__ == "__main__":
    main(sys.argv[1:])


