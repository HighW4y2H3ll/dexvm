
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "libdex/SysUtil.h"
#include "libdex/DexFile.h"


int main(int argc, char** argv) {
    if (argc < 2) {
        dprintf(2, "Too Few Args\n");
        return -1;
    }
    char *path = argv[1];

    struct stat st;
    if (stat(path, &st) != 0) {
        dprintf(2, "File stat Error\n");
        return -1;
    }

    MemMapping pmap;
    if (sysCreatePrivateMap(st.st_size, &pmap) != 0) {
        dprintf(2, "Create Mapping Failed\n");
        return -1;
    }

    int dexfd = open(path, O_RDONLY);
    if (sysMapFileInShmemWritableReadOnly(dexfd, &pmap) != 0) {
        dprintf(2, "File Mapping Failed\n");
        return -1;
    }

    DexFile *dexfile = dexFileParse((unsigned char *)pmap.addr, pmap.length, kDexParseVerifyChecksum);
    dexFileFree(dexfile);

    sysReleaseShmem(&pmap);

    return 0;
}
