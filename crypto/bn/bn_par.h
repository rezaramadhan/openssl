#define NUM_THREADS 2

#define MIN_BITS_PARALLEL_EXP 2048

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
