
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "libdex/SysUtil.h"
#include "libdex/DexFile.h"
#include "libdex/DexClass.h"
#include "libdex/DexOpcodes.h"
#include "libdex/InstrUtils.h"


/**
 *  Register Encoding Rules:
 *  - int, float are 32bit, encoded in the higher part (N << 32)
 *  - double are 64bit, encoded into 2 regs, both only take the higher half
 *  - objects are 8 bytes aligned, use the lower bits to encode type
 */
size_t regs[65536] = {0};
size_t result_reg[2] = {0};

const u2 *execute_one(const u2 *insns, u4 insn_size) {
    Opcode op;
    DecodedInstruction inst;
    op = dexOpcodeFromCodeUnit(insns[0]);

    dexDecodeInstruction(insns, &inst);

    switch (inst.opcode) {
    case OP_MOVE:
    case OP_MOVE_FROM16:
    case OP_MOVE_16:
    case OP_MOVE_OBJECT:
    case OP_MOVE_OBJECT_FROM16:
    case OP_MOVE_OBJECT_16:
    {
        // Check Type
        regs[inst.vA] = regs[inst.vB];
        break;
    }
    case OP_MOVE_WIDE:
    case OP_MOVE_WIDE_FROM16:
    case OP_MOVE_WIDE_16:
    case OP_NOP:
    {
        // Handle overlapping move-wide v6, v7; && move-wide v7, v6;
        break;
    }
    default:
    {
        break;
    }
    }

    return &insns[dexGetWidthFromOpcode(op)];
}

// Entry for VM
void run(const u2 *insns, u4 insn_size) {

    // Expected to run a trace to deduce the number of loops unrolled
    if (insn_size > 0) {
        insn_size -= dexGetWidthFromInstruction(insns);
        insns = execute_one(insns, insn_size);
    }
}


int main(int argc, char** argv) {
    char *path;
    struct stat st;
    MemMapping pmap;
    int dexfd;
    DexFile *dexfile;
    u4 idx = 0;
    const DexClassDef *cls = NULL;
    const u1 *dat = NULL;
    DexClassData *class_data = NULL;
    DexMethod meth;
    const DexCode *code = NULL;
    const DexCode *maincode = NULL;
    u4 mit = 0;

    if (argc < 2) {
        dprintf(2, "Too Few Args\n");
        return -1;
    }
    path = argv[1];

    if (stat(path, &st) != 0) {
        dprintf(2, "File stat Error\n");
        return -1;
    }

    if (sysCreatePrivateMap(st.st_size, &pmap) != 0) {
        dprintf(2, "Create Mapping Failed\n");
        return -1;
    }

    dexfd = open(path, O_RDONLY);
    if (sysMapFileInShmemWritableReadOnly(dexfd, &pmap) != 0) {
        dprintf(2, "File Mapping Failed\n");
        return -1;
    }

    dexfile = dexFileParse((unsigned char *)pmap.addr, pmap.length, kDexParseVerifyChecksum);


    dprintf(2, "methodsz: %d\n", dexfile->pHeader->methodIdsSize);
    dprintf(2, "classsz: %d\n", dexfile->pHeader->classDefsSize);
    dprintf(2, "linksz: %d\n", dexfile->pHeader->linkSize);
    dprintf(2, "typesz: %d\n", dexfile->pHeader->typeIdsSize);
    dprintf(2, "protpsz: %d\n", dexfile->pHeader->protoIdsSize);
    for (idx = 0; idx < dexfile->pHeader->classDefsSize; idx++) {

        cls = dexGetClassDef(dexfile, idx);

        if (cls->accessFlags != ACC_PUBLIC)
            continue;

        dat = dexGetClassData(dexfile, cls);
        class_data = dexReadAndVerifyClassData(&dat, NULL);

        dprintf(2, "staticfieldsz: %d\n", class_data->header.staticFieldsSize);
        dprintf(2, "instancefieldssz: %d\n", class_data->header.instanceFieldsSize);
        dprintf(2, "directMethodsz: %d\n", class_data->header.directMethodsSize);
        dprintf(2, "virtualMethodsz: %d\n", class_data->header.virtualMethodsSize);

        // Make sure we have enough methods
        if (class_data->header.directMethodsSize < 2) {
            dprintf(2, "Too few Methods\n");
            return -1;
        }

        for (mit = 0; mit < class_data->header.directMethodsSize; mit++) {

            meth = class_data->directMethods[mit];

            // Get Enough DUA in Method Body - at least 0x10*2 bytes
            code = dexGetCode(dexfile, &meth);
            if (code->insnsSize < 0x10) {
                dprintf(2, "Is that all you G0t?\n");
                return -1;
            }

            if (meth.accessFlags != (ACC_PUBLIC|ACC_CONSTRUCTOR)) {
                continue;
            }

            maincode = code;
        }

        if (!maincode) {
            dprintf(2, "hmmm weird...\n");
            return -1;
        }

        dprintf(2, "try # : %x\n", maincode->triesSize);
        dprintf(2, "dbginfo off : %x\n", maincode->debugInfoOff);

        // Run VM
        run(maincode->insns, maincode->insnsSize);

        free(class_data);
    }


    dexFileFree(dexfile);

    sysReleaseShmem(&pmap);

    return 0;
}
