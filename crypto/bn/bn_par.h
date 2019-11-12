#define NUM_THREADS 2

typedef struct _recursive_args_st {
    BN_ULONG *r;
    BN_ULONG *a;
    BN_ULONG *b;
    int n2;
    int dna;
    int dnb;
    BN_ULONG *t;
    int used_thr;
} recursive_args;

// typedef struct _mul_normal_args_st {
//
// } mul_normal_args;
