#include "linked_list.h"
#include <stdlib.h>
#include <string.h>

linked_list_t *ll_create(unsigned int data_size) {

    linked_list_t *ll;
    ll = malloc(sizeof(*ll));

    ll->head = NULL;
    ll->data_size = data_size;
    ll->size = 0;

    return ll;
}

/* Adds an element to the list at the nth position */
void ll_add_nth_node(linked_list_t *list, unsigned int n, const void *new_data) {

    ll_node_t *prev, *curr;
    ll_node_t *new_node;

    if (!list) {
        return;
    }

    if (n > list->size) {
        n = list->size;
    }

    curr = list->head;
    prev = NULL;
    while (n > 0) {
        prev = curr;
        curr = curr->next;
        --n;
    }

    new_node = malloc(sizeof(*new_node));
    new_node->data = malloc(list->data_size);
    memcpy(new_node->data, new_data, list->data_size);

    new_node->next = curr;
    if (prev == NULL) {
        list->head = new_node;
    } else {
        prev->next = new_node;
    }

    list->size++;
}

/* Removes the nth element in the list and returns the pointer to the element */
ll_node_t *ll_remove_nth_node(linked_list_t *list, unsigned int n) {

    ll_node_t *prev, *curr;

    if (!list || !list->head) {
        return NULL;
    }

    if (n > list->size - 1) {
        n = list->size - 1;
    }

    curr = list->head;
    prev = NULL;
    while (n > 0) {
        prev = curr;
        curr = curr->next;
        --n;
    }

    if (prev == NULL) {
        list->head = curr->next;
    } else {
        prev->next = curr->next;
    }

    list->size--;

    return curr;
}

unsigned int ll_get_size(linked_list_t *list)
{
     if (!list) {
        return -1;
    }

    return list->size;
}

void ll_free(linked_list_t **pp_list)
{
    ll_node_t *curr;

    if (!pp_list || !*pp_list) {
        return;
    }

    while (ll_get_size(*pp_list) > 0) {
        curr = ll_remove_nth_node(*pp_list, 0);
        free(curr->data);
        curr->data = NULL;
        free(curr);
        curr = NULL;
    }

    free(*pp_list);
    *pp_list = NULL;
}