#ifndef _TRIE_H_
#define _TRIE_H_

typedef struct trie_node_t {
    struct route_table_entry *table_entry;
    struct trie_node_t *children[2];
} trie_node_t;

typedef struct trie_t {
    trie_node_t *root;
} trie_t;

trie_t *trie_create();

void trie_add_address(trie_t *trie, struct route_table_entry *entry);

#endif