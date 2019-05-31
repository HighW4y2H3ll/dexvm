
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "libdex/SysUtil.h"
#include "libdex/DexFile.h"
#include "libdex/DexClass.h"
#include "libdex/DexOpcodes.h"
#include "libdex/InstrUtils.h"

#include "linkframe.h"
#include "hashmap.h"
#include "encode.h"


DexFile *dexfile = NULL;

/**
 *  Register Encoding Rules:
 *  - int, float are 32bit, encoded in the higher part (N << 32)
 *  - double are 64bit, encoded into 2 regs, both only take the higher half
 *  - objects are 8 bytes aligned, use the lower bits to encode type
 */
size_t regs[65537] = {0};   // One more Reg to withstand *-wide copy at the end
size_t result_reg[2] = {0};
size_t xreg = 0;    // Exception Object Register

// Link Frame to store the context info inside invoke/call
// The Current link state in (nested) subroutine
LinkFrame *linkstate = NULL;


void DumpInst(DecodedInstruction *inst) {
    dprintf(2, "%s %d %d\n", dexGetOpcodeName(inst->opcode), inst->vA, inst->vB);
}


const DexClassDef *getClassDefByTypeIdx(u4 idx) {
    int i = 0;
    const DexClassDef *cls = NULL;
    const char *buf = dexStringByTypeIdx(dexfile, idx);

    if (buf[0] != 'L') {
        dprintf(2, "Error: Expected Class Descriptor\n");
        exit(-1);
    }

    for (i = 0; i < dexfile->pHeader->classDefsSize; i++) {
        cls = dexGetClassDef(dexfile, i);
        if (cls->classIdx == idx) {
            return cls;
        }
    }

    return cls;
}


/**
 *  Array Object
 */
struct ArrayObject {
    size_t size;
    size_t typecode;
    size_t data[0]; // Each Data field holds 2 slots, follow the same reg encoding
};

size_t getTypeCodeByTypdIdx(size_t idx) {
    const char *buf = dexStringByTypeIdx(dexfile, idx);

    if (buf[0] != '[') {
        dprintf(2, "Error: Expected Array Descriptor\n");
        exit(-1);
    }

    switch (buf[1]) {
    case 'Z':
    case 'B':
    case 'S':
    case 'I':
        return SINT;
    case 'C':
        return UINT;
    case 'J':
        return SWINT;
    case 'F':
        return FLOAT;
    case 'D':
        return DOUBLE;
    case 'L':
        return OBJECT;
    case '[':
        return ARRAY;
    default:
        dprintf(2, "Error: Unknown Type Descriptor\n");
        exit(-1);
    }
}

ArrayObject *newArrayObject(size_t len, size_t typeidx) {
    ArrayObject *obj = NULL;
    size_t sz = sizeof(ArrayObject) + 2*sizeof(size_t)*len;

    // !!! Integer Overflow 0x01000001 ==> Array(16)
    //if (sz & 0xff000000) {
    //    dprintf(2, "!!! Int Overflow\n");
    //    exit(-1);
    //}

    obj = (ArrayObject*)malloc(sz);
    memset(obj, 0, sz);

    obj->size = len;
    obj->typecode = getTypeCodeByTypdIdx(typeidx);
    return obj;
}


/**
 *  Runtime Object
 */
struct RuntimeObject {
    const DexClassData *type;
    size_t data[0]; // Each Data field holds 2 slots, follow the same reg encoding
};

// Dex could handle at most 2^32 class
HashMap *type_map = NULL;

DexClassData *findClassObject(const DexClassDef *cls) {
    DexClassData *class_data = NULL;
    const u1 *dat = dexGetClassData(dexfile, cls);

    class_data = (DexClassData*)lookup(type_map, cls->classIdx);
    if (class_data)
        return (DexClassData*)class_data;

    class_data = dexReadAndVerifyClassData(&dat, NULL);
    insert(type_map, cls->classIdx, (size_t)class_data);
    return class_data;
}

RuntimeObject *newClassObject(const DexClassDef *cls) {
    size_t sz = 0;
    RuntimeObject *obj = NULL;
    DexClassData *class_data = findClassObject(cls);

    // !!! Need 0x0100 0000 0000 0001 to Int overflow - probably too big to actually worry about
    sz = sizeof(RuntimeObject) + 2*sizeof(size_t)*class_data->header.instanceFieldsSize;
    obj = (RuntimeObject*)malloc(sz);

    memset(obj, 0, sz);
    obj->type = class_data;
    return obj;
}

const u2 *execute_one(const u2 *insns, u4 insn_size) {
    const char *buf;
    char *strptr;
    size_t sz;
    const DexClassDef *class_def = NULL;
    RuntimeObject *obj = NULL;
    ArrayObject *arr = NULL;
    Opcode op;
    DecodedInstruction inst;
    op = dexOpcodeFromCodeUnit(insns[0]);

    dexDecodeInstruction(insns, &inst);

    DumpInst(&inst);

    switch (inst.opcode) {
    case OP_MOVE:
    case OP_MOVE_FROM16:
    case OP_MOVE_16:
    case OP_MOVE_OBJECT:
    case OP_MOVE_OBJECT_FROM16:
    case OP_MOVE_OBJECT_16:
    {
        TypeCheck(&regs[inst.vA], &regs[inst.vB]);
        regs[inst.vA] = regs[inst.vB];
        break;
    }
    case OP_MOVE_RESULT:
    case OP_MOVE_RESULT_OBJECT:
    {
        TypeCheck(&regs[inst.vA], &result_reg[0]);
        regs[inst.vA] = result_reg[0];
        break;
    }
    case OP_MOVE_RESULT_WIDE:
    {
        TypeCheck(&regs[inst.vA], &result_reg[0]);
        regs[inst.vA] = result_reg[0];
        regs[inst.vA+1] = result_reg[1];
        break;
    }
    // WIDE reg pair is incremental, vN represents (vN, vN+1)
    case OP_MOVE_WIDE:
    case OP_MOVE_WIDE_FROM16:
    case OP_MOVE_WIDE_16:
    {
        TypeCheck(&regs[inst.vA], &regs[inst.vB]);

        // Handle overlapping move-wide v6, v7; && move-wide v7, v6;
        if (inst.vA > inst.vB) {
            regs[inst.vA+1] = regs[inst.vB+1];
            regs[inst.vA] = regs[inst.vB];
        } else {
            regs[inst.vA] = regs[inst.vB];
            regs[inst.vA+1] = regs[inst.vB+1];
        }
        break;
    }
    case OP_MOVE_EXCEPTION:
    {
        CheckTypeOrUndef(&xreg, OBJECT);
        CheckTypeOrUndef(&regs[inst.vA], OBJECT);
        regs[inst.vA] = xreg;
        break;
    }
    case OP_RETURN:
    case OP_RETURN_OBJECT:
    case OP_RETURN_WIDE:
    {
        // Type Check is done in OP_MOVE_RESULT
        if (inst.opcode == OP_RETURN_WIDE) {
            result_reg[0] = regs[inst.vA];
            result_reg[1] = regs[inst.vA+1];
        } else {
            result_reg[0] = regs[inst.vA];
            result_reg[1] = 0;
        }
        // Fall Through
    }
    case OP_RETURN_VOID:
    {
        // Restore the register set
        if (!linkstate) {
            dprintf(2, "Error: Return from nowhere!\n");
            exit(-1);
        }
        return (const u2*)restoreFrame(&linkstate, regs);
    }
    /**
     * Encoding for number <= 32bit
     *
     * low                         high     Memory
     *  |_____________|_____________|       64 bit
     *       tag      |    number   |
     *                       | high16
     */
    case OP_CONST_4:
    case OP_CONST_16:
    case OP_CONST:
    {
        CheckTypeOrUndef(&regs[inst.vA], SINT);
        regs[inst.vA] = EncodeType(inst.vB, SINT);
        break;
    }
    case OP_CONST_UINT:
    {
        CheckTypeOrUndef(&regs[inst.vA], UINT);
        regs[inst.vA] = EncodeType(inst.vB, UINT);
        break;
    }
    case OP_CONST_HIGH16:
    {
        CheckTypeOrUndef(&regs[inst.vA], SINT);
        regs[inst.vA] = EncodeType(inst.vB << 16, SINT);
        break;
    }
    /**
     * Encoding for wide number (64bit)
     *
     *               vN                                 vN+1
     * low                         high                                high        Memory
     *  |_____________|_____________|       |_____________|_____________|          2 reg
     *       tag      |    low 32   |       |     tag     |   high 32   |
     *                                                           | high16
     */
    case OP_CONST_WIDE_16:
    case OP_CONST_WIDE_32:
    {
        CheckTypeOrUndef(&regs[inst.vA], SINT);
        CheckTypeOrUndef(&regs[inst.vA+1], SINT);

        regs[inst.vA] = EncodeType(inst.vB, SINT);
        if (inst.vB & (1 << 31)) {
            regs[inst.vA+1] = EncodeType(-1, SINT);
        } else {
            regs[inst.vA+1] = EncodeType(0, SINT);
        }
        break;
    }
    case OP_CONST_WIDE:
    {
        CheckTypeOrUndef(&regs[inst.vA], DOUBLE);
        CheckTypeOrUndef(&regs[inst.vA+1], DOUBLE);

        regs[inst.vA] = EncodeType(inst.vB_wide & 0xffffffff, DOUBLE);
        regs[inst.vA+1] = EncodeType((inst.vB_wide >> 32) & 0xffffffff, DOUBLE);
        break;
    }
    case OP_CONST_WIDE_SLONG:
    {
        CheckTypeOrUndef(&regs[inst.vA], SWINT);
        CheckTypeOrUndef(&regs[inst.vA+1], SWINT);

        regs[inst.vA] = EncodeType(inst.vB_wide & 0xffffffff, SWINT);
        regs[inst.vA+1] = EncodeType((inst.vB_wide >> 32) & 0xffffffff, SWINT);
        break;
    }
    case OP_CONST_WIDE_ULONG:
    {
        CheckTypeOrUndef(&regs[inst.vA], UWINT);
        CheckTypeOrUndef(&regs[inst.vA+1], UWINT);

        regs[inst.vA] = EncodeType(inst.vB_wide & 0xffffffff, UWINT);
        regs[inst.vA+1] = EncodeType((inst.vB_wide >> 32) & 0xffffffff, UWINT);
        break;
    }
    case OP_CONST_WIDE_HIGH16:
    {
        CheckTypeOrUndef(&regs[inst.vA], SWINT);
        CheckTypeOrUndef(&regs[inst.vA+1], SWINT);

        regs[inst.vA] = EncodeType(0, SWINT);
        regs[inst.vA+1] = EncodeType(inst.vB << 16, SWINT);
        break;
    }
    case OP_CONST_STRING:
    case OP_CONST_STRING_JUMBO:
    {
        CheckTypeOrUndef(&regs[inst.vA], STRING);

        buf = dexStringById(dexfile, inst.vB);
        strptr = (char*)malloc(strlen(buf));
        strcpy(strptr, buf);

        regs[inst.vA] = EncodeType((size_t)strptr, STRING);
        break;
    }
    case OP_CONST_CLASS:
    case OP_NEW_INSTANCE:
    {
        CheckTypeOrUndef(&regs[inst.vA], OBJECT);

        class_def = getClassDefByTypeIdx(inst.vB);
        obj = newClassObject(class_def);
        //dprintf(2, "DEBUG %s - %d - %p\n", dexGetClassDescriptor(dexfile, class_def),
        //        obj->type->header.instanceFieldsSize, obj);
        regs[inst.vA] = EncodeType((size_t)obj, OBJECT);
        break;
    }
    case OP_NEW_ARRAY:
    {
        CheckTypeOrUndef(&regs[inst.vA], ARRAY);

        sz = getSInt(regs, inst.vB);
        arr = newArrayObject(sz, inst.vC);
        //dprintf(2, "ARRAY %d - %p - %x\n", sz, arr, arr->typecode);
        regs[inst.vA] = EncodeType((size_t)arr, ARRAY);

        break;
    }
    //case OP_INVOKE:
    //{
    //    // Stash the register set
    //}
    case OP_ARRAY_LENGTH:
    case OP_INSTANCE_OF:
    case OP_CHECK_CAST:
    case OP_MONITOR_ENTER:
    case OP_MONITOR_EXIT:
    case OP_NOP:
    default:
    {
        break;
    }
    }

    return &insns[dexGetWidthFromOpcode(op)];
}


// Initialization For Each Run
void init() {
    // Zero out all regs before every run
    memset(regs, 0, 65537*sizeof(size_t));
    memset(result_reg, 0, 2*sizeof(size_t));
    xreg = 0;

    // Check Link State
    if (linkstate) {
        dprintf(2, "Stack Not Cleaned?!");
        exit(-1);
    }
}

// Entry for VM
void run(const u2 *insns, u4 insn_size) {

    init();

    // Expected to run a trace to deduce the number of loops unrolled
#define EXEC_LOOP   \
    if (insn_size > 0) {                                \
        insn_size -= dexGetWidthFromInstruction(insns); \
        insns = execute_one(insns, insn_size);          \
    }
#define LOOP2(X)    \
    X   \
    X
#define LOOP4(X)    LOOP2(LOOP2(X))
#define LOOP16(X)   LOOP4(LOOP4(X))
#define LOOP256(X)  LOOP16(LOOP16(X))
    LOOP256(EXEC_LOOP);
}


int main(int argc, char** argv) {
    char *path;
    struct stat st;
    MemMapping pmap;
    int dexfd;
    u4 idx = 0;
    const DexClassDef *cls = NULL;
    DexClassData *class_data = NULL;
    HashEntry *hashentry = NULL;
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

    // Init Object Type Map
    type_map = (HashMap*)malloc(sizeof(HashMap));
    memset(type_map, 0, sizeof(HashMap));

    dprintf(2, "methodsz: %d\n", dexfile->pHeader->methodIdsSize);
    dprintf(2, "classsz: %d\n", dexfile->pHeader->classDefsSize);
    dprintf(2, "linksz: %d\n", dexfile->pHeader->linkSize);
    dprintf(2, "typesz: %d\n", dexfile->pHeader->typeIdsSize);
    dprintf(2, "protpsz: %d\n", dexfile->pHeader->protoIdsSize);
    for (idx = 0; idx < dexfile->pHeader->classDefsSize; idx++) {

        cls = dexGetClassDef(dexfile, idx);

        if (cls->accessFlags != ACC_PUBLIC)
            continue;

        class_data = findClassObject(cls);

        dprintf(2, "staticfieldsz: %d\n", class_data->header.staticFieldsSize);
        dprintf(2, "instancefieldssz: %d\n", class_data->header.instanceFieldsSize);
        dprintf(2, "directMethodsz: %d\n", class_data->header.directMethodsSize);
        dprintf(2, "virtualMethodsz: %d\n", class_data->header.virtualMethodsSize);

        // Make sure we have enough methods
        if (class_data->header.directMethodsSize < 2) {
            //dprintf(2, "Too few Methods\n");
            continue;
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
    }

    // Check linkstate
    if (linkstate) {
        dprintf(2, "Stack Not Cleaned?!");
        exit(-1);
    }
    // Release Object Type Map
    while (type_map->root) {
        hashentry = type_map->root;
        type_map->root = hashentry->next;
        free((DexClassData*)hashentry->data);
        free(hashentry);
    }
    free(type_map);

    dexFileFree(dexfile);

    sysReleaseShmem(&pmap);

    return 0;
}
