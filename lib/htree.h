/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef __HTREE_H__
#define __HTREE_H__

typedef struct hash_tree HTree;
typedef void (*ItemFreeFunc)(void *);

struct ht_item {
    unsigned char *hashid;
    void *data;
    struct ht_item *next;
};

struct ht_data {
    int size;
    unsigned char *hashid;
    struct ht_item *item_list;
};

struct ht_node {
    unsigned char is_node;
    unsigned char depth;     /* from 0 */
};

struct hash_tree {
    int height;
    int hashid_len;
    int item_data_len;
    struct ht_node *nodes; /* an array of ht_node */
    struct ht_data **datas;  /*  an array of the pointer of ht_data*/
    int size;
    ItemFreeFunc item_free;
};

typedef struct ht_item HTItem;
typedef struct ht_data HTData;
typedef struct ht_node HTNode;

#define HTNODE_IS_LEAF(n) (!(((HTNode *)n)->is_node))
#define HTNODE_IS_NULL(tree, n) (ht_get_data(tree, n) == NULL)

HTree* ht_new (int size, int hashlen);
void ht_clear (HTree *tree);
int ht_add (HTree *tree, unsigned char *hashid, void *data);
int ht_remove (HTree *tree, unsigned char *hashid);
void ht_resize (HTree *ht, int size);
HTData* ht_get_data (HTree *tree, HTNode *node);
unsigned char* ht_get_node_hash (HTree *tree, HTNode *node);
HTNode *ht_get_parent (HTree *tree, HTNode *node);
HTNode *ht_get_child (HTree *tree, HTNode *node, int b);
HTNode *ht_get_brother (HTree *tree, HTNode *node);
void ht_remove_node (HTree *tree, HTNode *node);

static inline void ht_set_free_func (HTree *tree, ItemFreeFunc item_free)
{
    tree->item_free = item_free;
}

static inline HTNode *ht_get_root (HTree *tree) 
{
    return tree->nodes;
}

static inline int ht_get_node_seq (HTree *tree, HTNode *node)
{
    return node - tree->nodes;
}

static inline HTNode *ht_get_node_by_seq (HTree *tree, int seq)
{
    return tree->nodes + seq;
}



#endif /* __HTREE_H__ */
