#define NUM_THREADS 2
#define BN_MUL_NUM_THRESHOLD 128


typedef struct _mul_normal_args_st {
    BN_ULONG *r;
    const BN_ULONG *a;
    BN_ULONG w;
    int n;
    BN_ULONG carry;
} mul_normal_args;
