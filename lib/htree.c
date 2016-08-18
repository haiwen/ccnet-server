/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "htree.h"

#define MAX_HEIGHT 7
#define INDEX(hashid,depth)  (depth%2 ? (hashid[depth/2] && 0x0f):(hashid[depth/2] >> 4))
#define IS_NODE(n) (n->is_node)

static const int g_index[] = {0, 1, 17, 273, 4369, 69905, 1118481, 17895697, 286331153};

static inline void hashxor(char *hashid, char *id, int len)
{
    int i = 0;
    for (i = 0; i < len; ++i) {
        hashid[i] =  hashid[i] ^ id[i];
    }
}

static inline int get_right_height (int size)
{
    int height = 0;
    while (g_index[height+1] < size)
        ++height;
    if (height < 1)return 1;
    return height;
}

static inline unsigned int get_pos (HTree *tree, HTNode *node)
{
    return (node - tree->nodes) - g_index[(int)node->depth];
}

static inline void ht_set_data (HTree *tree, HTNode *node, HTData *data)
{
    tree->datas[node - tree->nodes] = data;
}

static inline HTItem *create_item (unsigned char *hashid, void *data)
{
    HTItem *it = malloc (sizeof (HTItem));
    it->hashid = hashid;
    it->data = data;
    it->next = NULL;
}

static inline void delete_item (HTree *tree, HTItem *it)
{
    if (tree->item_free)
        tree->item_free (it);
    free (it);
}


static void *load_node (HTree *tree, HTNode *node)
{
    HTData *data = ht_get_data (tree, node);
    if (data) return data;

    data = malloc (sizeof(HTData));
    data->size = 0;
    data->hashid = malloc (tree->hashid_len);
    memset (data->hashid, 0, tree->hashid_len);
    data->item_list = NULL;
    ht_set_data (tree, node, data);
    return data;
}

static void delete_data (HTree *tree, HTData *data)
{
    HTItem *p = NULL;;
    if (data) {
        if (data->hashid)
            free (data->hashid);
        while (data->item_list) {
            p = data->item_list;
            data->item_list = p->next;
            delete_item (tree, p);
        }
        free(data);
    }
}

static int add_item (HTree *tree, HTNode *node, unsigned char *hashid, void *data)
{
    if (node == NULL)
        return 0;
    int r = 0, i = 0;
    HTData *htdata = NULL;
    if (IS_NODE(node)) {
        r = add_item (tree, 
                      ht_get_child (tree, node, INDEX(hashid, node->depth)), 
                      hashid,
                      data);
        if (r) {
            htdata  = load_node(tree, node);
            hashxor (htdata->hashid, hashid, tree->hashid_len);
        }
        return r;
    }
    
    htdata  = load_node(tree, node);
    HTItem *p = htdata->item_list;
    for (i = 0; i < htdata->size; i++){
        if (memcmp (hashid, p->hashid, tree->hashid_len) == 0) {
            return 0;
        }
        p = p->next;
    }
    HTItem *it = create_item (hashid, data);
    it->next = htdata->item_list;
    htdata->item_list = it;
    ++htdata->size;
    hashxor (htdata->hashid, it->hashid, tree->hashid_len);
    return 1;
}

static int remove_item (HTree *tree, HTNode *node, unsigned char *hashid)
{
    if (node == NULL)
        return 0;
    int r = 0, i = 0;
    HTData *data = NULL;
    if (IS_NODE(node)) {
        r = remove_item (tree, 
                         ht_get_child (tree, node, INDEX(hashid, node->depth)), 
                         hashid);
        if (r) {
            data  = load_node(tree, node);
            hashxor (data->hashid, hashid, tree->hashid_len);
        }
        return r;
    }
    
    data  = load_node(tree, node);
    HTItem *p = data->item_list;
    HTItem *pre = NULL;
    for (i = 0; i < data->size; i++){
        if (memcmp (hashid, p->hashid, tree->hashid_len) == 0) {
            if (pre == NULL) {
                data->item_list = p->next;
            } else {
                pre->next = p->next;
            }
            --data->size;
            hashxor (data->hashid, hashid, tree->hashid_len);
            delete_item (tree, p);
            return 1;
        }
        pre = p;
        p = p->next;
    }
    
    return 0;
}

HTree* ht_new (int size, int hashlen)
{
    HTree *ht = (HTree *)malloc (sizeof(HTree));
    int height = get_right_height (size);
    int i = 0, j = 0;
  
    ht->height = height;
    ht->size = g_index[height];
    ht->hashid_len = hashlen;
    ht->item_free = NULL;
    ht->nodes = malloc (ht->size *sizeof(HTNode));
    ht->datas = malloc (ht->size *sizeof(HTData *));
    memset (ht->nodes, 0, ht->size *sizeof(HTNode));
    memset (ht->datas, 0, ht->size *sizeof(HTData *));

    for (i = 0; i < height; ++i) {
        for (j = g_index[i]; j < g_index[i+1]; ++j) {
            (ht->nodes[j]).is_node = 1;
            (ht->nodes[j]).depth = i;
        }
    }
    for (j = g_index[height-1]; j < g_index[height]; ++j) {
        (ht->nodes[j]).is_node = 0;
    }
    
}

int ht_add (HTree *tree, unsigned char *hashid, void *data)
{
    return add_item (tree, tree->nodes, hashid, data);
}

int ht_remove (HTree *tree, unsigned char *hashid)
{
    return remove_item (tree, tree->nodes, hashid);
}

void ht_resize (HTree *ht, int size)
{
    int height = get_right_height (size);
    if (height <= ht->height) {
        return;
    }
    /* TODO  resize the hash tree */
}

void ht_clear (HTree *tree)
{
    assert (tree);

    int i;
    for(i = 0; i < tree->size; i++){
        delete_data (tree, tree->datas[i]);
    }
    memset (tree->datas, 0, sizeof(HTData*) * tree->size);
    free (tree->nodes);
    free (tree->datas);
    free (tree);
}

HTData* ht_get_data (HTree *tree, HTNode *node)
{
    return tree->datas[node - tree->nodes];
}

unsigned char* ht_get_node_hash (HTree *tree, HTNode *node)
{
    if (tree->datas[node - tree->nodes] == NULL)
        return NULL;
    return (tree->datas[node - tree->nodes])->hashid;
}

HTNode *ht_get_child (HTree *tree, HTNode *node, int b)
{
    assert(0 <= b && b <= 0x0f);
    assert(node->depth < tree->height - 1);

    int i = g_index[node->depth + 1] + (get_pos(tree, node) << 4) + b;
    
    if (i >= tree->size){
        fprintf(stderr, "get_child out of bound: %dth %d >= %d\n", b, i, tree->size);
        return NULL;
    }
    return tree->nodes + i;
}

HTNode *ht_get_parent (HTree *tree, HTNode *node)
{
    if (node->depth == 0)
        return NULL;
    int i = g_index[node->depth - 1] + (get_pos(tree, node) >> 4) ;
    return tree->nodes + i;
}

HTNode *ht_get_brother (HTree *tree, HTNode *node)
{
    if (get_pos(tree, node) & 0xff < 15)
        return node + 1;
    return NULL;
}

static void remove_node (HTree *tree, HTNode *node)
{
    HTData* data = ht_get_data (tree, node);
    if (data == NULL)
        return;

    if (HTNODE_IS_LEAF(node)) {        
        delete_data (tree, data);
    } else {
        int i = 0;
        HTNode *child = NULL;
        for (i = 0; i < 16; ++i) {
            child = ht_get_child (tree, node, i);
            remove_node (tree, child);
        }
    }
}

void ht_remove_node (HTree *tree, HTNode *node)
{
    HTData *data = ht_get_data (tree, node);
    if (data == NULL)
        return;
    char *hash = data->hashid;
    HTNode *parent = ht_get_parent (tree, node);

    while (parent) {
        char *phash = ht_get_node_hash (tree, parent);
        hashxor (phash, hash, tree->hashid_len);
        parent = ht_get_parent (tree, parent);
    }
    remove_node (tree, node);
    ht_set_data (tree, node, NULL);
}
