
#include "linkframe.h"

#include <string.h>

void *restoreFrame(LinkFrame **curframe, size_t *regset) {
    void *pc = NULL;
    LinkEntry *lent = NULL;
    LinkFrame *frame = *curframe;

    // Return Null if curframe is NULL
    if (!frame)
        return pc;

    *curframe = frame->next;
    pc = frame->pc;

    // Clean out all regs first
    memset(regset, 0, 65537*sizeof(size_t));

    // Restore Regs
    lent = frame->reg;
    while (lent) {
        regset[lent->regno] = lent->regval;
        frame->reg = lent->next;
        free(lent);
        lent = frame->reg;
    }

    free(frame);
    return pc;
}

void stashFrame(size_t *regset, void *pc, LinkFrame **curframe) {
    size_t idx = 0;
    LinkEntry *lent = NULL;
    LinkFrame *frame = NULL;

    frame = (LinkFrame*)malloc(sizeof(LinkFrame));
    frame->reg = NULL;
    frame->pc = pc;
    frame->next = *curframe;
    *curframe = frame;

    // Scan through all regs, only store Non-Null regs
    for (idx = 0; idx < 65537; idx++) {
        if (regset[idx]) {
            lent = (LinkEntry*)malloc(sizeof(LinkEntry));

            lent->next = frame->reg;
            frame->reg = lent;

            lent->regno = idx;
            lent->regval = regset[idx];
        }
    }

    // Clean up regs
    memset(regset, 0, 65537*sizeof(size_t));
}


