#define NUM_THREADS 2



typedef struct _mul_normal_args_st {
    BN_ULONG *r;
    const BN_ULONG *a;
    const BN_ULONG *b;
    int na;
    int nb;
    int nr;
} mul_normal_args;
