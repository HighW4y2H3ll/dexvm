
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
const DexCode *maincode = NULL;

/**
 *  Register Encoding Rules:
 *  - int, float are 32bit, encoded in the higher part (N << 32)
 *  - double are 64bit, encoded into 2 regs, both only take the higher half
 *  - objects are 8 bytes aligned, use the lower bits to encode type
 */
uint64_t regs[65537] = {0};   // One more Reg to withstand *-wide copy at the end
                              // Strong Typed - overlapping should be fine
                              // Might be able to corrupt wide data, but it wont be exploitable
uint64_t result_reg[2] = {0};
uint64_t xreg = 0;    // Exception Object Register

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
 *  Runtime Object
 */
struct RuntimeObject {
    //const DexClassData *type;
    uint64_t size;
    uint64_t data[0]; // Each Data field holds 2 slots, follow the same reg encoding
};


uint64_t getTypeCodeByTypeIdx(uint64_t idx) {
    const char *buf = dexStringByTypeIdx(dexfile, idx);

    switch (buf[0]) {
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

RuntimeObject *newStringObject(const char *buf, uint64_t len) {
    RuntimeObject *obj = NULL;
    uint64_t sz = sizeof(RuntimeObject) + len + 1;
    sz = (sz+7)&(~7);
    obj = (RuntimeObject*)malloc(sz);
    memset(obj, 0, sz);

    obj->size = len;
    memcpy(obj->data, buf, len);
}


// Dex could handle at most 2^32 class
HashMap *type_map = NULL;

DexClassData *findClassObject(const DexClassDef *cls) {
    DexClassData *class_data = NULL;
    const u1 *dat = dexGetClassData(dexfile, cls);

    class_data = (DexClassData*)lookup(type_map, cls->classIdx);
    if (class_data)
        return (DexClassData*)class_data;

    class_data = dexReadAndVerifyClassData(&dat, NULL);
    insert(type_map, cls->classIdx, (uint64_t)class_data);
    return class_data;
}


uint64_t initKeyValueEntry(uint64_t mask, const char *key) {
    uint64_t sz = sizeof(RuntimeObject) + 3*sizeof(uint64_t);
    RuntimeObject *obj = (RuntimeObject*)malloc(sz);
    memset(obj, 0, sz);
    obj->size = 3;  // 2 fields in one entry: [0] - string object for key, everything goes as string
                    //                        [1..2] - Anything data that use the same encoding in register
    encodeData(obj->data, 0, STRING,
            (uint64_t)newStringObject(key, strlen(key)));
    encodeData(obj->data, 1, mask, 0);
    return (uint64_t)obj;
}

RuntimeObject *newClassObject(const DexClassDef *cls) {
    uint64_t i, mask, sz;
    const char *name = NULL;
    RuntimeObject *obj = NULL;
    const DexFieldId *dfi = NULL;
    DexClassData *class_data = findClassObject(cls);

    // !!! Need 0x0100 0000 0000 0001 to Int overflow - probably too big to actually worry about
    sz = sizeof(RuntimeObject) + sizeof(uint64_t)*class_data->header.instanceFieldsSize;
    obj = (RuntimeObject*)malloc(sz);

    memset(obj, 0, sz);
    obj->size = class_data->header.instanceFieldsSize;
    for (i = 0; i < obj->size; i++) {
        dfi = dexGetFieldId(dexfile, class_data->instanceFields[i].fieldIdx);
        mask = getTypeCodeByTypeIdx(dfi->typeIdx);
        name = dexStringById(dexfile, dfi->nameIdx);
        //dprintf(2, "Debug %s - %x\n", name, mask);
        encodeData(obj->data, i, OBJECT,
                initKeyValueEntry(mask, name));
    }
    return obj;
}

RuntimeObject *newArrayObject(uint64_t len, uint64_t typeidx) {
    uint64_t i;
    char idxstr[17] = {0};
    RuntimeObject *obj = NULL;
    uint64_t sz = sizeof(RuntimeObject) + sizeof(uint64_t)*len;

    obj = (RuntimeObject*)malloc(sz);
    memset(obj, 0, sz);

    obj->size = len;
    for (i = 0; i < len; i++) {
        snprintf(idxstr, 16, "%llx", i);
        encodeData(obj->data, i, OBJECT,
                initKeyValueEntry(
                    getTypeCodeByTypeIdx(typeidx),
                    idxstr));
    }
    return obj;
}

uint64_t *lookupInstanceField(RuntimeObject *obj, const char *name) {
    uint64_t i;
    RuntimeObject *tmp_obj, *name_obj;

    for (i = 0; i < obj->size; i++) {
        tmp_obj = (RuntimeObject*)getDataChecked(obj->data, i, OBJECT);
        name_obj = (RuntimeObject*)getDataChecked(tmp_obj->data, 0, STRING);
        if (!strncmp(name, (char*)name_obj->data, name_obj->size))
            return &tmp_obj->data[1];
    }

    return NULL;
}


const u2 *execute_one(const u2 *insns) {
    const char *buf;
    uint64_t sz;
    const DexClassDef *class_def = NULL;
    RuntimeObject *obj = NULL;
    uint64_t *tmp_reg = NULL;
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
        CheckTypeEq(&regs[inst.vA], &regs[inst.vB]);
        regs[inst.vA] = regs[inst.vB];
        break;
    }
    case OP_MOVE_RESULT:
    case OP_MOVE_RESULT_OBJECT:
    {
        CheckTypeEq(&regs[inst.vA], &result_reg[0]);
        regs[inst.vA] = result_reg[0];
        result_reg[0] = 0;
        break;
    }
    case OP_MOVE_RESULT_WIDE:
    {
        CheckTypeEq(&regs[inst.vA], &result_reg[0]);
        regs[inst.vA] = result_reg[0];
        regs[inst.vA+1] = result_reg[1];
        result_reg[0] = 0;
        result_reg[1] = 0;
        break;
    }
    // WIDE reg pair is incremental, vN represents (vN, vN+1)
    case OP_MOVE_WIDE:
    case OP_MOVE_WIDE_FROM16:
    case OP_MOVE_WIDE_16:
    {
        CheckTypeEq(&regs[inst.vA], &regs[inst.vB]);

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
        xreg = 0;    // Null the xreg to clear the exception signal
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
        encodeData(regs, inst.vA, SINT, inst.vB);
        break;
    }
    case OP_CONST_UINT:
    {
        encodeData(regs, inst.vA, UINT, inst.vB);
        break;
    }
    case OP_CONST_HIGH16:
    {
        encodeData(regs, inst.vA, SINT, inst.vB << 16);
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
        encodeData(regs, inst.vA, SWINT, inst.vB);  // Auto sign-extend
        break;
    }
    case OP_CONST_WIDE:
    {
        encodeData(regs, inst.vA, DOUBLE, inst.vB_wide);
        break;
    }
    case OP_CONST_WIDE_SLONG:
    {
        encodeData(regs, inst.vA, SWINT, inst.vB_wide);
        break;
    }
    case OP_CONST_WIDE_ULONG:
    {
        encodeData(regs, inst.vA, UWINT, inst.vB_wide);
        break;
    }
    case OP_CONST_WIDE_HIGH16:
    {
        encodeData(regs, inst.vA, SWINT, inst.vB << 16);
        break;
    }
    case OP_CONST_STRING:
    case OP_CONST_STRING_JUMBO:
    {
        buf = dexStringById(dexfile, inst.vB);
        obj = newStringObject(buf, strlen(buf));

        encodeData(regs, inst.vA, STRING, (uint64_t)obj);
        break;
    }
    case OP_CONST_CLASS:
    case OP_NEW_INSTANCE:
    {
        class_def = getClassDefByTypeIdx(inst.vB);
        obj = newClassObject(class_def);
        //dprintf(2, "DEBUG %s - %p\n", dexGetClassDescriptor(dexfile, class_def), obj);
        encodeData(regs, inst.vA, OBJECT, (uint64_t)obj);
        break;
    }
    case OP_NEW_ARRAY:
    {
        sz = getDataChecked(regs, inst.vB, SINT);
        obj = newArrayObject(sz, inst.vC);
        //dprintf(2, "ARRAY %d - %p - %x\n", sz, arr, arr->typecode);
        encodeData(regs, inst.vA, ARRAY, (uint64_t)obj);

        break;
    }
    case OP_ARRAY_LENGTH:
    {
        CheckType(&regs[inst.vB], ARRAY);
        obj = (RuntimeObject*)getDataChecked(regs, inst.vB, ARRAY);
        encodeData(regs, inst.vA, SINT, obj->size);
        break;
    }
    case OP_THROW:
    {
        CheckType(&regs[inst.vA], OBJECT|STRING|ARRAY);
        xreg = regs[inst.vA];
        break;
    }
    case OP_GOTO:
    case OP_GOTO_16:
    case OP_GOTO_32:
    {
        return &insns[(s4)inst.vA]; // Sign Extend
    }
    //case OP_INVOKE:
    //{
    //    // Stash the register set
    //}
    case OP_IF_EQ:
    case OP_IF_NE:
    case OP_IF_LT:
    case OP_IF_GE:
    case OP_IF_GT:
    case OP_IF_LE:
    {
        if (DecodeCmp(&regs[inst.vA], &regs[inst.vB], inst.opcode))
            return &insns[(s4)inst.vC];  // Sign Extend
        break;
    }
    case OP_IF_EQZ:
    case OP_IF_NEZ:
    case OP_IF_LTZ:
    case OP_IF_GEZ:
    case OP_IF_GTZ:
    case OP_IF_LEZ:
    {
        if (DecodeCmpZ(&regs[inst.vA], inst.opcode))
            return &insns[(s4)inst.vC];  // Sign Extend
        break;
    }
    case OP_IGET:
    case OP_IGET_WIDE:
    case OP_IGET_OBJECT:
    case OP_IGET_BOOLEAN:
    case OP_IGET_BYTE:
    case OP_IGET_CHAR:
    case OP_IGET_SHORT:
    {
        buf = dexStringById(dexfile, inst.vC);    // Field Id now is String Id
        if (regs[inst.vB] & STRING) {
            obj = (RuntimeObject*)UNMASK_OBJECT(regs[inst.vB]);
            encodeData(regs, inst.vA, SINT, ((char*)obj->data)[atoi(buf)]);
        } else if (MASK_OBJECT(regs[inst.vB])) {
            tmp_reg = lookupInstanceField((RuntimeObject*)UNMASK_OBJECT(regs[inst.vB]), buf);
            CheckTypeEq(&regs[inst.vA], tmp_reg);
            memcpy(&regs[inst.vA], tmp_reg, 2*sizeof(uint64_t));
        }
        break;
    }
    case OP_IPUT:
    case OP_IPUT_WIDE:
    case OP_IPUT_OBJECT:
    case OP_IPUT_BOOLEAN:
    case OP_IPUT_BYTE:
    case OP_IPUT_CHAR:
    case OP_IPUT_SHORT:
    {
        buf = dexStringById(dexfile, inst.vC);    // Field Id now is String Id
        if (regs[inst.vB] & STRING) {
            obj = (RuntimeObject*)UNMASK_OBJECT(regs[inst.vB]);
            ((char*)obj->data)[atoi(buf)] = getDataChecked(regs, inst.vA, SINT) & 0xff;
        } else if (MASK_OBJECT(regs[inst.vB])) {
            tmp_reg = lookupInstanceField((RuntimeObject*)UNMASK_OBJECT(regs[inst.vB]), buf);
            CheckTypeEq(&regs[inst.vA], tmp_reg);
            memcpy(tmp_reg, &regs[inst.vA], 2*sizeof(uint64_t));
        }
        break;
    }
    case OP_CMPL_FLOAT:
    case OP_CMPG_FLOAT:
    case OP_CMPL_DOUBLE:
    case OP_CMPG_DOUBLE:
    case OP_CMP_LONG:
    case OP_PACKED_SWITCH:
    case OP_SPARSE_SWITCH:
    case OP_FILLED_NEW_ARRAY:
    case OP_FILLED_NEW_ARRAY_RANGE:
    case OP_FILL_ARRAY_DATA:
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

    // Handle Exception
    if (xreg) {
        const DexTry *tries = dexGetTries(maincode);
        dexGetCatchHandlerData(maincode);
    }

    return &insns[dexGetWidthFromOpcode(op)];
}


// Initialization For Each Run
void init() {
    // Zero out all regs before every run
    memset(regs, 0, 65537*sizeof(uint64_t));
    memset(result_reg, 0, 2*sizeof(uint64_t));
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
    if (insns < &insns[insn_size]) {                    \
        insns = execute_one(insns);                     \
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
            if (code->insnsSize < CONF_SEMILAVA_MAGIC_1) {
                dprintf(2, "Is that all you G0t?\n");
                return -1;
            }

            // Skip Ctor
            if (meth.accessFlags & ACC_CONSTRUCTOR) {
                continue;
            }

            // Only do static public function
            if ((meth.accessFlags & ACC_PUBLIC)
              && (meth.accessFlags & ACC_STATIC)) {
                maincode = code;
            }
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
