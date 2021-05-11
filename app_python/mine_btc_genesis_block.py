# Works on Python 3.
# Source: https://github.com/gtmadureira/bitcoin_address-generator/blob/main/app_python/mine_btc_genesis_block.py

import os
import sys
import struct
import codecs
import hashlib
from dateutil.tz import gettz
from dateutil.parser import parse
from datetime import datetime, timedelta, timezone


HEIGHT        = "0"
VERSION       = "00000001"
PREVIOUSBLOCK = "0000000000000000000000000000000000000000000000000000000000000000"
MERKLEROOT    = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
TIMESTAMP     = "2009-01-03 18:15:05" # Sat Jan 03 2009 18:15:05 GMT+0000.
BITS          = "1d00ffff"

TARGET        = "00000000ffff0000000000000000000000000000000000000000000000000000"


number_of_try = 0

if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
    def clear(): os.system('clear')
elif sys.platform == "win32":
    def clear(): os.system('cls')

clear()

def little(string):
    t = bytearray.fromhex(string)
    t.reverse()
    return ''.join(format(x,'02x') for x in t)

def block_hash_less_than_target(block_hash, given_target):
    return int(block_hash, 16) < int(given_target, 16)

def get_little_indian_from_decimal(nonce_decimal):
    return bytes.decode(codecs.encode(struct.pack('<I', nonce_decimal), 'hex'))

def get_random_nonce_decimal(initial_value):    
    return initial_value + number_of_try

def get_version():
    version = little(VERSION)
    return version

def get_prev_block():
    prev_block = little(PREVIOUSBLOCK)
    return prev_block    

def get_merkle_root():    
    merkle_root = little(MERKLEROOT)
    return merkle_root

def get_timestamp():
    tzinfos = {"BRST": 0, "CST": gettz("Greenwich")}
    epoch = datetime(1970, 1, 1, tzinfo = timezone.utc)    
    date = TIMESTAMP
    dt = parse(date + "BRST", tzinfos = tzinfos)
    ts = (dt - epoch) // timedelta(seconds = 1)
    timestamp = little(hex(ts)[2:]) 
    return timestamp

def get_size():    
    size_bits = little(BITS)
    return size_bits

def get_nonce():    
    nonce_decimal = get_random_nonce_decimal(2083200000) 
    nonce_little_indian = get_little_indian_from_decimal(nonce_decimal)
    return nonce_little_indian

def get_header_bin(version, prev_block, merkle_root, timestamp, size_bits, nonce):
    header_hex = version + prev_block + merkle_root + timestamp + size_bits + nonce
    header_bin = codecs.decode(header_hex, 'hex')
    return header_bin

def get_header_second_hash_big_endian_hex(header_bin):
    first_hash_bin = hashlib.sha256(header_bin).digest()      
    second_hash_bin = hashlib.sha256(first_hash_bin).digest() 
    second_hash_big_endian = second_hash_bin[::-1]            
    header_second_hash_big_endian_hex = bytes.decode(codecs.encode(second_hash_big_endian, 'hex'))
    return header_second_hash_big_endian_hex

def print_number_of_try():
    info_str = ('number_of_try: ' + str(number_of_try))
    sys.stdout.write('%s\r' % info_str)
    sys.stdout.flush()

def print_solution_found(header_second_hash_big_endian_hex, HEIGHT):
    print("\n\n\033[92m\033[05m\033[01mMined!\033[0m")
    print("\n    HEIGHT: "+ HEIGHT)
    print("   ####################################################################################")
    print("   #\033[92m\033[01m         " + header_second_hash_big_endian_hex + "         \033[0m#")
    print("##########################################################################################")

def print_header(version, prev_block, merkle_root, datetime, timestamp, size_bits, nonce):
    print('#          VERSION:  ' + version + '                                                            #')
    print("# -------------------------------------------------------------------------------------- #")
    print('#   PREVIOUS BLOCK:  ' + prev_block + '    #')
    print("# -------------------------------------------------------------------------------------- #")
    print('#      MERKLE ROOT:  ' + merkle_root + '    #')
    print("# -------------------------------------------------------------------------------------- #")
    print('#        TIMESTAMP:  ' + str(datetime) + " (" + str(timestamp) + ")" + '                              #')
    print("# -------------------------------------------------------------------------------------- #")
    print('#             BITS:  ' + size_bits + '                                                            #')
    print("# -------------------------------------------------------------------------------------- #")
    print('#            NONCE:  ' + nonce + " (" + str(int("0x" + nonce, 16)) + ")" + '                                               #')
    print("##########################################################################################")

is_solution_found = False

while not is_solution_found:    
    print_number_of_try()
    version = get_version()          
    prev_block = get_prev_block()    
    merkle_root = get_merkle_root()  
    timestamp = get_timestamp()      
    size_bits = get_size()           
    nonce = get_nonce()
    header_bin = get_header_bin(version, prev_block, merkle_root, timestamp, size_bits, nonce)
    header_second_hash_big_endian_hex = get_header_second_hash_big_endian_hex(header_bin)
    is_solution_found = block_hash_less_than_target(header_second_hash_big_endian_hex, TARGET)
    if not is_solution_found:
        number_of_try = number_of_try + 1
    else:
        print_solution_found(header_second_hash_big_endian_hex, HEIGHT)
        print_header(little(version), little(prev_block), little(merkle_root),
        datetime.fromtimestamp(int("0x" + little(timestamp), 16), timezone.utc), int("0x" + little(timestamp), 16), little(size_bits), little(nonce))
