# Works on Python 3.

import sys
import struct
import codecs
import hashlib
from dateutil.tz import gettz
from dateutil.parser import parse
from datetime import datetime, timedelta, timezone

tzinfos = {"BRST": -7200, "CST": gettz("America/Sao_Paulo")}
epoch = datetime(1970, 1, 1, tzinfo = timezone.utc)

TARGET = '00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff'

number_of_try = 0

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
    version = little("00000001")
    return version

def get_prev_block():
    prev_block = little("0000000000000000000000000000000000000000000000000000000000000000")
    return prev_block    

def get_merkle_root():
    
    merkle_root = little("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
    return merkle_root

def get_timestamp():
    
    date = "2009-01-03 16:15:05"
    dt = parse(date + "BRST", tzinfos = tzinfos)
    ts = (dt - epoch) // timedelta(seconds = 1)
    timestamp = little(hex(ts)[2:]) 
    return timestamp

def get_size():
    
    size_bits = little("1d00ffff")
    return size_bits

def get_nonce():
    
    nonce_decimal = get_random_nonce_decimal(2083230000) 
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

def print_solution_found(header_second_hash_big_endian_hex, TARGET):
    print('')
    print('!!! We found a perfect header combination !!!')
    print('because the hash of the header is:  ' + header_second_hash_big_endian_hex)
    print('   and is smaller than the target:  ' + TARGET)

def print_header(version, prev_block, merkle_root, datetime, timestamp, size_bits, nonce):
    print('[Base on the header]')
    print('       VERSION:  ' + version)
    print('PREVIOUS BLOCK:  ' + prev_block)
    print('   MERKLE ROOT:  ' + merkle_root)
    print('     TIMESTAMP:  ' + str(datetime) + " GMT+0000 (" + str(timestamp) + ")")
    print('          BITS:  ' + size_bits)
    print('         NONCE:  ' + nonce + " (" + str(int("0x" + nonce, 16)) + ")")

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
        print_solution_found(header_second_hash_big_endian_hex, TARGET)
        print_header(little(version), little(prev_block), little(merkle_root),
        datetime.fromtimestamp(int("0x" + little(timestamp), 16)), int("0x" + little(timestamp), 16), little(size_bits), little(nonce))
