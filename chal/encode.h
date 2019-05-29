
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

size_t EncodeType(size_t n, size_t code) {
    if (MASK_OBJECT(code)) {
        return (n|code);
    } else {
        return ((n << 32)|code);
    }
}

void CheckTypeOrUndef(size_t *regA, size_t mask) {
    // Undefined
    if (!regA[0])   return;

    ERROR_TYPE_CHECK(!(regA[0] & mask));

    if (!MASK_WIDE(mask)) {
        ERROR_TYPE_CHECK(!(regA[1] & mask));
    }
}

// Check 2 (wide) registers are of the same type
void TypeCheck(size_t *regA, size_t *regB) {
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
