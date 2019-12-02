#define NUM_THREADS 2

#define MIN_BN_SIZE_MUL_RECURSIVE_PARALLEL 64
#define MIN_BN_SIZE_MUL_NORMAL_PARALLEL 64
#define MIN_BITS_EXP_PARALLEL 2048

typedef struct _mul_normal_args_st {
    BN_ULONG *r;
    BN_ULONG *a;
    BN_ULONG *b;
    int na;
    int nb;
    int nr;
} mul_normal_args;

typedef struct _add_sub_args_st {
    BN_ULONG *r;
    const BN_ULONG *a;
    const BN_ULONG *b;
    int n;
    int id;
    char type;
    BN_ULONG carry;
} add_sub_args;


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

typedef struct _exp_args_st {
    BIGNUM *r;
    const BIGNUM *a;
    BIGNUM *p;
    const BIGNUM *m;
    BN_MONT_CTX *mont_ctx;
    BIGNUM **val;
    BN_ULONG ri;
    int window;
} exp_args;

#define set_recursive_arg(arg, _r, _a, _b, _n, _da, _db, _t, _ut) \
        {\
            arg.r = _r;\
            arg.a = _a;\
            arg.b = _b;\
            arg.n2 = _n;\
            arg.dna = _da;\
            arg.dnb = _db;\
            arg.t = _t;\
            arg.used_thr = _ut;\
        }

#define set_exp_arg(arg, _r, _a, _p, _m, _mont, _val, _ri, _w) \
        {\
            arg.r = _r;\
            arg.a = _a;\
            arg.p = _p;\
            arg.m = _m;\
            arg.val = _val;\
            arg.mont_ctx = _mont;\
            arg.ri = _ri;\
            arg.window = _w;\
        }
