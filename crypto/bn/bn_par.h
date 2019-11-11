#define NUM_THREADS 2

typedef struct _add_sub_args_st {
    BN_ULONG *r;
    const BN_ULONG *a;
    const BN_ULONG *b;
    int n;
    int id;
    char type;
    BN_ULONG carry;
} add_sub_args;
