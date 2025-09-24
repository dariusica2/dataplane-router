#include "trie.h"
#include "lib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

trie_t *trie_create() {

    trie_t *trie;
    trie = malloc(sizeof(*trie));

    trie->root = NULL;

    return trie;
}

/* Takes an entry in the routing table and adds it to the trie */
void trie_add_address(trie_t *trie, struct route_table_entry *entry) {

    if (trie == NULL) {
        return;
    }

    if (trie->root == NULL) {
        trie->root = malloc(sizeof(trie_node_t));
        DIE(trie->root == NULL, "root malloc error");
        trie->root->children[0] = NULL;
        trie->root->children[1] = NULL;
        trie->root->table_entry = NULL;
    }

    uint32_t curr_mask = 0;
    trie_node_t *curr_node = trie->root;
    /* Current position refers to the order (from left to right) that bits are processed in */
    int curr_pos = 0;

    while (1) {

        /* Stopping when the mask matches the one given in the entry */
        if (curr_mask == ntohl(entry->mask)) {
            curr_node->table_entry = entry;
            break;
        }

        /* Shifting the bits in the prefix to find the next bit */
        uint8_t curr_bit= (ntohl(entry->prefix) >> (31 - curr_pos)) & 1;
        
        if (curr_node->children[curr_bit] == NULL) {
            curr_node->children[curr_bit] = malloc(sizeof(struct trie_node_t));
            DIE(curr_node->children[curr_bit] == NULL, "bit child malloc error");
            curr_node->children[curr_bit]->children[0] = NULL;
            curr_node->children[curr_bit]->children[1] = NULL;
            curr_node->children[curr_bit]->table_entry = NULL;
        }
        curr_node = curr_node->children[curr_bit];

        /* Updating the mask */
        curr_mask = (curr_mask >> 1) | (1 << 31);
        curr_pos++;
    }
}