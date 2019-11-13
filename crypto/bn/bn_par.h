#define NUM_THREADS 16

typedef struct _recursive_args_st {
    BN_ULONG *r;
    BN_ULONG *a;
    BN_ULONG *b;
    int n2;
    int dna;
    int dnb;
    BN_ULONG *t;
    int *used_thr;
} recursive_args;

#define set_recursive_arg(arg, _r, _a, _b, _n, _da, _db, _t, _ut)({arg.r = _r;   arg.a = _a;   arg.b = _b;   arg.n2 = _n;   arg.dna = _da;   arg.dnb = _db;   arg.t = _t;   arg.used_thr = _ut; })

// typedef struct _mul_normal_args_st {
//
// } mul_normal_args;
