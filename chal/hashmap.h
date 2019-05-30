
//#include <libdex/sha1.h>

struct HashEntry {
    size_t key;
    size_t data;
    HashEntry *next;
};

struct HashMap {
    size_t size;
    HashEntry *root;
};

size_t lookup(HashMap *map, size_t key) {
    HashEntry *e = NULL;
    for (e = map->root; e != NULL; e = e->next) {
        if (e->key == key)
            return e->data;
    }
    return 0;
}

void insert(HashMap *map, size_t key, size_t data) {
    HashEntry *e = (HashEntry*)malloc(sizeof(HashEntry));
    e->key = key;
    e->data = data;
    e->next = map->root;
    map->root = e;
    map->size++;
}
