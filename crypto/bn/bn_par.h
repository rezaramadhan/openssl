#define NUM_THREADS 5

typedef struct _add_args_st {
    BN_ULONG *r;
    const BN_ULONG *a;
    const BN_ULONG *b;
    int n;
    BN_ULONG carry;
} add_args;
