
#include <stdlib.h>

struct LinkEntry {
    size_t regno;
    size_t regval;
    LinkEntry *next;
};

/**
 *  Struct to store the Link State
 *  - Act in a stack to handle nested subroutine invoke/call
 */
struct LinkFrame {
    //size_t regs[65537]; // TOO big ~512 kb, use linklist
    LinkEntry *reg;
    void *pc;
    LinkFrame *next;
};

// Pop the current frame from the frame stack
// Return the pc of current frame
void *restoreFrame(LinkFrame **curframe, size_t *regset);

// Create a clean slate for the subroutine
// - Stash the regs to the frame stack
// - NULL all the regs
void stashFrame(size_t *regset, void *pc, LinkFrame **curframe);

