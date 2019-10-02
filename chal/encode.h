
// Heap Objects are 8 bytes aligned, so we have 3 bits to manipulate
#define OBJECT 1
#define STRING (1 << 1)
#define ARRAY (1 << 2)

// Numbers are managed in 32bit, while we have 64bit registers
// so we have the lower 32bit to tag type
#define SINT (1 << 3)
#define UINT (2 << 3)
#define FLOAT (3 << 3)
#define DOUBLE (1 << 5)
#define SWINT (2 << 5)
#define UWINT (3 << 5)


#define MASK_OBJECT(X)  (X & 0x7)
#define MASK_NUMBER(X)  (X & 0xffffffff)
#define MASK_WIDE(X)    (X & 0x1f)

#define ERROR_TYPE_CHECK(X)    if (X) {         \
    dprintf(2, "WRRRRRONG! Type Mismatch.\n");  \
    exit(-1);                                   \
}

uint64_t EncodeType(uint64_t n, uint64_t code) {
    if (MASK_OBJECT(code)) {
        return (n|code);
    } else {
        return ((n << 32)|code);
    }
}

void CheckTypeOrUndef(uint64_t *regA, uint64_t mask) {
    // Undefined
    if (!regA[0])   return;

    ERROR_TYPE_CHECK(!(regA[0] & mask));

    if (!MASK_WIDE(mask)) {
        ERROR_TYPE_CHECK(!(regA[1] & mask));
    }
}

void CheckType(uint64_t *regA, uint64_t mask) {
    ERROR_TYPE_CHECK(!(regA[0] & mask));

    if (!MASK_WIDE(mask)) {
        ERROR_TYPE_CHECK(!(regA[1] & mask));
    }
}

// Check 2 (wide) registers are of the same type
void CheckTypeEq(uint64_t *regA, uint64_t *regB) {
    // regA is undefined
    if (!regA[0])   return;

    ERROR_TYPE_CHECK(MASK_OBJECT(regA[0]) != MASK_OBJECT(regB[0]));

    // Done Checking Non-Number
    if (MASK_OBJECT(regA[0]))  // regA == regB
        return;

    ERROR_TYPE_CHECK(MASK_NUMBER(regA[0]) != MASK_NUMBER(regB[0]));

    // Done Checking Non-Wide
    if (MASK_WIDE(regA[0]))    // regA == regB
        return;

    ERROR_TYPE_CHECK(
            MASK_NUMBER(regA[1]) != MASK_NUMBER(regB[1])
          || MASK_NUMBER(regA[0]) != MASK_NUMBER(regA[1]));
}

// Extract Data from it's encoded form
uint64_t getDataChecked(uint64_t *reg, uint64_t idx, uint64_t mask) {
    ERROR_TYPE_CHECK(!(reg[idx] & mask));
    switch (mask) {
    case OBJECT:
    case STRING:
    case ARRAY:
        return reg[idx]&(~3);
    case SINT:
    case UINT:
    case FLOAT:
        return reg[idx] >> 32;
    case DOUBLE:
    case SWINT:
    case UWINT:
        ERROR_TYPE_CHECK(!(reg[idx+1] & mask));
        return (reg[idx] >> 32) | (reg[idx+1] & (~0xffffffff));
    default:
        ERROR_TYPE_CHECK(1);
    }
}


bool RegCmpEq(uint64_t *regA, uint64_t *regB) {
    return regA[0] == regB[0] && regA[1] == regB[1];
}

bool NumCmpLt(uint64_t *regA, uint64_t *regB) {
    int32_t ia, ib;
    uint32_t ua, ub;
    float fa, fb;
    double da, db;
    int64_t wia, wib;
    uint64_t wua, wub;
    uint64_t tmp;

    ERROR_TYPE_CHECK(MASK_OBJECT(regA[0]));
    ERROR_TYPE_CHECK(MASK_OBJECT(regB[0]));

    switch (MASK_NUMBER(regA[0])) {
    case SINT:
        ia = getDataChecked(regA, 0, SINT);
        ib = getDataChecked(regB, 0, SINT);
        return ia < ib;
    case UINT:
        ua = getDataChecked(regA, 0, UINT);
        ub = getDataChecked(regB, 0, UINT);
        return ua < ub;
    case FLOAT:
        tmp = getDataChecked(regA, 0, FLOAT);
        fa = *(float*)&tmp;
        tmp = getDataChecked(regB, 0, FLOAT);
        fb = *(float*)&tmp;
        return fa < fb;
    case DOUBLE:
        tmp = getDataChecked(regA, 0, DOUBLE);
        da = *(double*)&tmp;
        tmp = getDataChecked(regB, 0, DOUBLE);
        db = *(double*)&tmp;
        return da < db;
    case SWINT:
        wia = getDataChecked(regA, 0, SWINT);
        wib = getDataChecked(regB, 0, SWINT);
        return wia < wib;
    case UWINT:
        wua = getDataChecked(regA, 0, UWINT);
        wub = getDataChecked(regB, 0, UWINT);
        return wua < wub;
    default:
        ERROR_TYPE_CHECK(1);
    }
}

bool DecodeCmp(uint64_t *regA, uint64_t *regB, Opcode op) {
    switch (op) {
    case OP_IF_EQ:
        return RegCmpEq(regA, regB);
    case OP_IF_NE:
        return !RegCmpEq(regA, regB);
    // Followings don't apply to Object
    case OP_IF_LT:
        return NumCmpLt(regA, regB);
    case OP_IF_GE:
        return !NumCmpLt(regA, regB);
    // - Ordering of expr aside _or_ is important, cz RegCmpEq bypass type check
    case OP_IF_LE:
        return NumCmpLt(regA, regB) || RegCmpEq(regA, regB);
    case OP_IF_GT:
        return !(NumCmpLt(regA, regB) || RegCmpEq(regA, regB));
    default:
        return false;
    }
}

