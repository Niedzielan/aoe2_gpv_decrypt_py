import struct

def arr_to_int(array):
    return int.from_bytes(bytes(array), "little")

def int_to_arr(int_in):
    return int.to_bytes(int_in, 4, "little")

def bytes_string_to_k(bs):
    tmp = [x for x in bytes.fromhex(bs)]
    return split_arr(tmp)

def split_arr(array, count = 4):
    tmp_arr = []
    for i in range(len(array)//count):
        tmp_arr.append(arr_to_int(array[i*count:(i+1)*count]))
    return tmp_arr

def print32(numb):
    print([hex(x)[2:] for x in struct.pack('<I', numb & 0xFFFFFFFF)])


def encipher(v_parts, k_parts):
    v_0 = v_parts[0]
    v_1 = v_parts[1]
    
    k_0 = k_parts[0]
    k_1 = k_parts[1]
    k_2 = k_parts[2]
    k_3 = k_parts[3]
    
    sum_d = 0
    delta = 0x9E3779B9
    for i in range(0x20):
        sum_d += delta
        v_0 += ((v_1 << 4) + k_0) ^ (v_1 + sum_d) ^ ((v_1 >> 5) + k_1)
        v_0 &= 0xFFFFFFFF        
        v_1 += ((v_0 << 4) + k_2) ^ (v_0 + sum_d) ^ ((v_0 >> 5) + k_3)
        v_1 &= 0xFFFFFFFF
    return v_0, v_1

def decipher(v_parts, k_parts):
    v_0 = v_parts[0]
    v_1 = v_parts[1]
    
    k_0 = k_parts[0]
    k_1 = k_parts[1]
    k_2 = k_parts[2]
    k_3 = k_parts[3]
    
    delta = 0x9E3779B9
    
    sum_d = delta << 5

    for i in range(0x20):
        v_1 -= ((v_0 << 4) + k_2) ^ (v_0 + sum_d) ^ ((v_0 >> 5) + k_3)
        v_1 &= 0xFFFFFFFF
        v_0 -= ((v_1 << 4) + k_0) ^ (v_1 + sum_d) ^ ((v_1 >> 5) + k_1)
        v_0 &= 0xFFFFFFFF
        sum_d -= delta
    return v_0, v_1

def do_decipher_2(valueslist, key):
    output = []
    for x in range(len(valueslist)//2):
        tmp1, tmp2 = decipher([valueslist[2*x], valueslist[2*x+1]], key)
        output.append(tmp1)
        output.append(tmp2)
    return output

