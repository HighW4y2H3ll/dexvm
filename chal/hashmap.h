
// This shoudl be hashmap, but clearly it's not. I was more ambitious than this
// But ughh, who cares. Let it be, let it be..
//#include <libdex/sha1.h>

struct HashEntry {
    uint64_t key;
    uint64_t data;
    HashEntry *next;
};

struct HashMap {
    uint64_t size;
    HashEntry *root;
};

uint64_t lookup(HashMap *map, uint64_t key) {
    HashEntry *e = NULL;
    for (e = map->root; e != NULL; e = e->next) {
        if (e->key == key)
            return e->data;
    }
    return 0;
}

void insert(HashMap *map, uint64_t key, uint64_t data) {
    HashEntry *e = (HashEntry*)malloc(sizeof(HashEntry));
    e->key = key;
    e->data = data;
    e->next = map->root;
    map->root = e;
    map->size++;
}
