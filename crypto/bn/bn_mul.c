/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <pthread.h>
#include "internal/cryptlib.h"
#include "bn_local.h"
#include "bn_par.h"

#if defined(OPENSSL_NO_ASM) || !defined(OPENSSL_BN_ASM_PART_WORDS)
/*
 * Here follows specialised variants of bn_add_words() and bn_sub_words().
 * They have the property performing operations on arrays of different sizes.
 * The sizes of those arrays is expressed through cl, which is the common
 * length ( basically, min(len(a),len(b)) ), and dl, which is the delta
 * between the two lengths, calculated as len(a)-len(b). All lengths are the
 * number of BN_ULONGs...  For the operations that require a result array as
 * parameter, it must have the length cl+abs(dl). These functions should
 * probably end up in bn_asm.c as soon as there are assembler counterparts
 * for the systems that use assembler files.
 */

BN_ULONG bn_sub_part_words(BN_ULONG *r,
                           const BN_ULONG *a, const BN_ULONG *b,
                           int cl, int dl)
{
    BN_ULONG c, t;

    assert(cl >= 0);
    c = bn_sub_words(r, a, b, cl);

    if (dl == 0)
        return c;

    r += cl;
    a += cl;
    b += cl;

    if (dl < 0) {
        for (;;) {
            t = b[0];
            r[0] = (0 - t - c) & BN_MASK2;
            if (t != 0)
                c = 1;
            if (++dl >= 0)
                break;

            t = b[1];
            r[1] = (0 - t - c) & BN_MASK2;
            if (t != 0)
                c = 1;
            if (++dl >= 0)
                break;

            t = b[2];
            r[2] = (0 - t - c) & BN_MASK2;
            if (t != 0)
                c = 1;
            if (++dl >= 0)
                break;

            t = b[3];
            r[3] = (0 - t - c) & BN_MASK2;
            if (t != 0)
                c = 1;
            if (++dl >= 0)
                break;

            b += 4;
            r += 4;
        }
    } else {
        int save_dl = dl;
        while (c) {
            t = a[0];
            r[0] = (t - c) & BN_MASK2;
            if (t != 0)
                c = 0;
            if (--dl <= 0)
                break;

            t = a[1];
            r[1] = (t - c) & BN_MASK2;
            if (t != 0)
                c = 0;
            if (--dl <= 0)
                break;

            t = a[2];
            r[2] = (t - c) & BN_MASK2;
            if (t != 0)
                c = 0;
            if (--dl <= 0)
                break;

            t = a[3];
            r[3] = (t - c) & BN_MASK2;
            if (t != 0)
                c = 0;
            if (--dl <= 0)
                break;

            save_dl = dl;
            a += 4;
            r += 4;
        }
        if (dl > 0) {
            if (save_dl > dl) {
                switch (save_dl - dl) {
                case 1:
                    r[1] = a[1];
                    if (--dl <= 0)
                        break;
                    /* fall thru */
                case 2:
                    r[2] = a[2];
                    if (--dl <= 0)
                        break;
                    /* fall thru */
                case 3:
                    r[3] = a[3];
                    if (--dl <= 0)
                        break;
                }
                a += 4;
                r += 4;
            }
        }
        if (dl > 0) {
            for (;;) {
                r[0] = a[0];
                if (--dl <= 0)
                    break;
                r[1] = a[1];
                if (--dl <= 0)
                    break;
                r[2] = a[2];
                if (--dl <= 0)
                    break;
                r[3] = a[3];
                if (--dl <= 0)
                    break;

                a += 4;
                r += 4;
            }
        }
    }
    return c;
}
#endif

#ifdef BN_RECURSION
/*
 * Karatsuba recursive multiplication algorithm (cf. Knuth, The Art of
 * Computer Programming, Vol. 2)
 */
pthread_mutex_t thr_count_lock;


void *bn_mul_recursive_thread(void *ptr) {
    recursive_args *args = (recursive_args *) ptr;
    BN_ULONG *r = args->r;
    BN_ULONG *a = args->a;
    BN_ULONG *b = args->b;
    int n2 = args->n2;
    int dna = args->dna;
    int dnb = args->dnb;
    BN_ULONG *t = args->t;
    int *used_thr = args->used_thr;

    bn_mul_recursive(r, a, b, n2, dna, dnb, t, used_thr);
    pthread_exit(NULL);
}

void *bn_mul_part_recursive_thread(void *ptr) {
    recursive_args *args = (recursive_args *) ptr;
    BN_ULONG *r = args->r;
    BN_ULONG *a = args->a;
    BN_ULONG *b = args->b;
    int n = args->n2;
    int tna = args->dna;
    int tnb = args->dnb;
    BN_ULONG *t = args->t;
    int *used_thr = args->used_thr;

    bn_mul_part_recursive(r, a, b, n, tna, tnb, t, used_thr);
    pthread_exit(NULL);
}

void start_mul_recursive_thread(pthread_t *thr, recursive_args *arg, BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n2, int dna, int dnb, BN_ULONG *tmp_thr, int *used_thr) {
    int rc;

    pthread_mutex_lock(&thr_count_lock);
    (*used_thr)++;
    pthread_mutex_unlock(&thr_count_lock);
    set_recursive_arg((*arg), r, a, b, n2, dna, dnb, tmp_thr, used_thr);

    // printf("thread_created %d\n", *(arg->used_thr));
    if ((rc = pthread_create(thr, NULL, bn_mul_recursive_thread, arg))) {
        fprintf(stderr, "error: pthread_create, rc: %d\n", rc);
        exit(EXIT_FAILURE);
    } else {
        // printf("create%d success\n", *used_thr);
    }
}

void start_mul_part_recursive_thread(pthread_t *thr, recursive_args *arg, BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n2, int dna, int dnb, BN_ULONG *tmp_thr, int *used_thr) {
    int rc;

    pthread_mutex_lock(&thr_count_lock);
    (*used_thr)++;
    pthread_mutex_unlock(&thr_count_lock);
    set_recursive_arg((*arg), r, a, b, n2, dna, dnb, tmp_thr, used_thr);

    // printf("thread_created %d\n", *(arg->used_thr));
    if ((rc = pthread_create(thr, NULL, bn_mul_part_recursive_thread, arg))) {
        fprintf(stderr, "error: pthread_create, rc: %d\n", rc);
        exit(EXIT_FAILURE);
    } else {
        // printf("create%d success\n", *used_thr);
    }
}

int get_used_thread(int* used_thr) {
    pthread_mutex_lock(&thr_count_lock);
    int u = *used_thr;
    pthread_mutex_unlock(&thr_count_lock);
    return u;
}
void set_used_thread(int* used_thr, int new_val) {
    pthread_mutex_lock(&thr_count_lock);
    *used_thr = new_val;
    pthread_mutex_unlock(&thr_count_lock);
}

/*-
 * r is 2*n2 words in size,
 * a and b are both n2 words in size.
 * n2 must be a power of 2.
 * We multiply and return the result.
 * t must be 2*n2 words in size
 * We calculate
 * a[0]*b[0] a_low*b_low
 * a[0]*b[0]+a[1]*b[1]+(a[0]-a[1])*(b[1]-b[0])
 *       a_low*b_low + a_high*b_high + (a_low-a_high)*(b_high-b_low)
 * a[1]*b[1] a_high*b_high
 */
/* dnX may not be positive, but n2/2+dnX has to be */
void bn_mul_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n2,
                      int dna, int dnb, BN_ULONG *t, int *used_thr)
{
    int n = n2 / 2, c1, c2;
    int tna = n + dna, tnb = n + dnb;
    unsigned int neg, zero;
    BN_ULONG ln, lo, *p;

# ifdef BN_MUL_COMBA
#  if 0
    if (n2 == 4) {
        bn_mul_comba4(r, a, b);
        return;
    }
#  endif
    /*
     * Only call bn_mul_comba 8 if n2 == 8 and the two arrays are complete
     * [steve]
     */
    if (n2 == 8 && dna == 0 && dnb == 0) {
        bn_mul_comba8(r, a, b);
        return;
    }
# endif                         /* BN_MUL_COMBA */
    /* Else do normal multiply */
    if (n2 < BN_MUL_RECURSIVE_SIZE_NORMAL) {
        bn_mul_normal(r, a, n2 + dna, b, n2 + dnb);
        if ((dna + dnb) < 0)
            memset(&r[2 * n2 + dna + dnb], 0,
                   sizeof(BN_ULONG) * -(dna + dnb));
        return;
    }
    /* r=(a[0]-a[1])*(b[1]-b[0]) */
    c1 = bn_cmp_part_words(a, &(a[n]), tna, n - tna); // a[0] > a[1] ? 1 : -1
    c2 = bn_cmp_part_words(&(b[n]), b, tnb, tnb - n); // b[1] > b[0] ? 1 : -1
    zero = neg = 0;
    switch (c1 * 3 + c2) {
    case -4: // a[0] < a[1], b[1] < b[0]
        bn_sub_part_words(t, &(a[n]), a, tna, tna - n); /* - */
        bn_sub_part_words(&(t[n]), b, &(b[n]), tnb, n - tnb); /* - */
        break;
    case -3: // a[0] < a[1], b[1] == b[0]
        zero = 1;
        break;
    case -2: // a[0] < a[1], b[1] > b[0]
        bn_sub_part_words(t, &(a[n]), a, tna, tna - n); /* - */
        bn_sub_part_words(&(t[n]), &(b[n]), b, tnb, tnb - n); /* + */
        neg = 1;
        break;
    case -1: // a[0] == a[1], b[1] < b[0]
    case 0: // a[0] == a[1], b[1] =p b[0]
    case 1: // a[0] == a[1], b[1] > b[0]
        zero = 1;
        break;
    case 2: // a[0] > a[1], b[1] < b[0]
        bn_sub_part_words(t, a, &(a[n]), tna, n - tna); /* + */
        bn_sub_part_words(&(t[n]), b, &(b[n]), tnb, n - tnb); /* - */
        neg = 1;
        break;
    case 3: // a[0] > a[1], b[1] == b[0]
        zero = 1;
        break;
    case 4: // a[0] > a[1], b[1] > b[0]
        bn_sub_part_words(t, a, &(a[n]), tna, n - tna);
        bn_sub_part_words(&(t[n]), &(b[n]), b, tnb, tnb - n);
        break;
    }

# ifdef BN_MUL_COMBA
    if (n == 4 && dna == 0 && dnb == 0) { /* XXX: bn_mul_comba4 could take
                                           * extra args to do this well */
        if (!zero)
            bn_mul_comba4(&(t[n2]), t, &(t[n]));
        else
            memset(&t[n2], 0, sizeof(*t) * 8);

        bn_mul_comba4(r, a, b);
        bn_mul_comba4(&(r[n2]), &(a[n]), &(b[n]));
    } else if (n == 8 && dna == 0 && dnb == 0) { /* XXX: bn_mul_comba8 could
                                                  * take extra args to do
                                                  * this well */
        if (!zero)
            bn_mul_comba8(&(t[n2]), t, &(t[n]));
        else
            memset(&t[n2], 0, sizeof(*t) * 16);

        bn_mul_comba8(r, a, b);
        bn_mul_comba8(&(r[n2]), &(a[n]), &(b[n]));
    } else
# endif                         /* BN_MUL_COMBA */
    {
        if (n2 < MIN_BN_SIZE_MUL_RECURSIVE_PARALLEL)
            set_used_thread(used_thr, 99999);

        pthread_t thr[3];
        recursive_args arg[3];
        int running_cnt = 0, rc;
        BN_ULONG* tp[3];
        p = &(t[n2 * 2]);
        if (!zero) {
            if (get_used_thread(used_thr) < NUM_THREADS) {
                tp[running_cnt] = (BN_ULONG *) calloc(n2*2, sizeof(BN_ULONG));
                start_mul_recursive_thread(&(thr[running_cnt]), &(arg[running_cnt]), &(t[n2]), t, &(t[n]), n, 0, 0, tp[running_cnt], used_thr);
                running_cnt++;
            } else
                bn_mul_recursive(&(t[n2]), t, &(t[n]), n, 0, 0, p, used_thr);
        } else
            memset(&t[n2], 0, sizeof(*t) * n2);

        if (get_used_thread(used_thr) < NUM_THREADS) {
            tp[running_cnt] = (BN_ULONG *) calloc(n2*2, sizeof(BN_ULONG));
            start_mul_recursive_thread(&(thr[running_cnt]), &(arg[running_cnt]), r, a, b, n, 0, 0, tp[running_cnt], used_thr);
            running_cnt++;
        } else
            bn_mul_recursive(r, a, b, n, 0, 0, p, used_thr);

        if (get_used_thread(used_thr) < NUM_THREADS) {
            tp[running_cnt] = (BN_ULONG *) calloc(n2*2, sizeof(BN_ULONG));
            start_mul_recursive_thread(&(thr[running_cnt]), &(arg[running_cnt]), &(r[n2]), &(a[n]), &(b[n]), n, dna, dnb, tp[running_cnt], used_thr);
            running_cnt++;
        } else
            bn_mul_recursive(&(r[n2]), &(a[n]), &(b[n]), n, dna, dnb, p, used_thr);

        /* block until all threads complete */
        // printf("running_cnt %d\n", running_cnt);
        for (int i = 0; i < running_cnt; i++) {
            // printf("i %d\n", i);
            if ((rc = pthread_join(thr[i], NULL))) {
                fprintf(stderr, "error: pthread_join, rc: %d\n", rc);
                exit(EXIT_FAILURE);
            } else {
                // printf("join%d success\n", i);
            }
            // printf("t%d %d\n", i, thr_data[i].carry);
            free(tp[i]);
        }
    }

    /*-
     * t[n2] holds (a[0]-a[1])*(b[1]-b[0]), c1 is the sign
     * r[0] holds (a[0]*b[0])
     * r[n2] holds (b[1]*b[1])
     */

    c1 = (int)(bn_add_words(t, r, &(r[n2]), n2));

    if (neg) {                  /* if t[n2] is negative */
        c1 -= (int)(bn_sub_words(&(t[n2]), t, &(t[n2]), n2));
    } else {
        /* Might have a carry */
        c1 += (int)(bn_add_words(&(t[n2]), &(t[n2]), t, n2));
    }

    /*-
     * t[n2] holds (a[0]-a[1])*(b[1]-b[0])+(a[0]*b[0])+(a[1]*b[1])
     * r[0] holds (a[0]*b[0])
     * r[n2] holds (b[1]*b[1])
     * c1 holds the carry bits
     */
    c1 += (int)(bn_add_words(&(r[n]), &(r[n]), &(t[n2]), n2));

    // resolve carry on r[n + n2] to last elmt
    if (c1) {
        p = &(r[n + n2]);
        lo = *p;
        ln = (lo + c1) & BN_MASK2;
        *p = ln;

        /*
         * The overflow will stop before we over write words we should not
         * overwrite
         */
        if (ln < (BN_ULONG)c1) {
            do {
                p++;
                lo = *p;
                ln = (lo + 1) & BN_MASK2;
                *p = ln;
            } while (ln == 0);
        }
    }
}

/*
 * n+tn is the word length t needs to be n*4 is size, as does r
 */
/* tnX may not be negative but less than n */
void bn_mul_part_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n,
                           int tna, int tnb, BN_ULONG *t, int *used_thr)
{
    int i, j, n2 = n * 2;
    int c1, c2, neg;
    BN_ULONG ln, lo, *p;

    if (n < 8) {
        bn_mul_normal(r, a, n + tna, b, n + tnb);
        return;
    }

    /* r=(a[0]-a[1])*(b[1]-b[0]) */
    c1 = bn_cmp_part_words(a, &(a[n]), tna, n - tna);
    c2 = bn_cmp_part_words(&(b[n]), b, tnb, tnb - n);
    neg = 0;
    switch (c1 * 3 + c2) {
    case -4:
        bn_sub_part_words(t, &(a[n]), a, tna, tna - n); /* - */
        bn_sub_part_words(&(t[n]), b, &(b[n]), tnb, n - tnb); /* - */
        break;
    case -3:
    case -2:
        bn_sub_part_words(t, &(a[n]), a, tna, tna - n); /* - */
        bn_sub_part_words(&(t[n]), &(b[n]), b, tnb, tnb - n); /* + */
        neg = 1;
        break;
    case -1:
    case 0:
    case 1:
    case 2:
        bn_sub_part_words(t, a, &(a[n]), tna, n - tna); /* + */
        bn_sub_part_words(&(t[n]), b, &(b[n]), tnb, n - tnb); /* - */
        neg = 1;
        break;
    case 3:
    case 4:
        bn_sub_part_words(t, a, &(a[n]), tna, n - tna);
        bn_sub_part_words(&(t[n]), &(b[n]), b, tnb, tnb - n);
        break;
    }
    /*
     * The zero case isn't yet implemented here. The speedup would probably
     * be negligible.
     */
# if 0
    if (n == 4) {
        bn_mul_comba4(&(t[n2]), t, &(t[n]));
        bn_mul_comba4(r, a, b);
        bn_mul_normal(&(r[n2]), &(a[n]), tn, &(b[n]), tn);
        memset(&r[n2 + tn * 2], 0, sizeof(*r) * (n2 - tn * 2));
    } else
# endif
    if (n == 8) {
        bn_mul_comba8(&(t[n2]), t, &(t[n]));
        bn_mul_comba8(r, a, b);
        bn_mul_normal(&(r[n2]), &(a[n]), tna, &(b[n]), tnb);
        memset(&r[n2 + tna + tnb], 0, sizeof(*r) * (n2 - tna - tnb));
    } else {
        if (n2 < MIN_BN_SIZE_MUL_RECURSIVE_PARALLEL)
            set_used_thread(used_thr, 99999);


        pthread_t thr[3];
        recursive_args arg[3];
        int running_cnt = 0, rc;
        BN_ULONG* tp[3];
        p = &(t[n2 * 2]);

        if (get_used_thread(used_thr) < NUM_THREADS) {
            tp[running_cnt] = (BN_ULONG *) calloc(n2*4, sizeof(BN_ULONG));
            start_mul_recursive_thread(&(thr[running_cnt]), &(arg[running_cnt]), &(t[n2]), t, &(t[n]), n, 0, 0, tp[running_cnt], used_thr);
            running_cnt++;
        } else
            bn_mul_recursive(&(t[n2]), t, &(t[n]), n, 0, 0, p, used_thr);

        if (get_used_thread(used_thr) < NUM_THREADS) {
            tp[running_cnt] = (BN_ULONG *) calloc(n2*4, sizeof(BN_ULONG));
            start_mul_recursive_thread(&(thr[running_cnt]), &(arg[running_cnt]), r, a, b, n, 0, 0, tp[running_cnt], used_thr);
            running_cnt++;
        } else
            bn_mul_recursive(r, a, b, n, 0, 0, p, used_thr);

        i = n / 2;
        /*
         * If there is only a bottom half to the number, just do it
         */
        if (tna > tnb)
            j = tna - i;
        else
            j = tnb - i;
        if (j == 0) {
            if (get_used_thread(used_thr) < NUM_THREADS) {
                tp[running_cnt] = (BN_ULONG *) calloc(n2*2, sizeof(BN_ULONG));
                start_mul_recursive_thread(&(thr[running_cnt]), &(arg[running_cnt]), &(r[n2]), &(a[n]), &(b[n]),
                                    i, tna - i, tnb - i, tp[running_cnt], used_thr);
                running_cnt++;
            } else
                bn_mul_recursive(&(r[n2]), &(a[n]), &(b[n]),
                                    i, tna - i, tnb - i, p, used_thr);
            memset(&r[n2 + i * 2], 0, sizeof(*r) * (n2 - i * 2));
        } else if (j > 0) {     /* eg, n == 16, i == 8 and tn == 11 */
            if (get_used_thread(used_thr) < NUM_THREADS) {
                tp[running_cnt] = (BN_ULONG *) calloc(n2*2, sizeof(BN_ULONG));
                start_mul_recursive_thread(&(thr[running_cnt]), &(arg[running_cnt]), &(r[n2]), &(a[n]), &(b[n]),
                                    i, tna - i, tnb - i, tp[running_cnt], used_thr);
                running_cnt++;
            } else
                bn_mul_recursive(&(r[n2]), &(a[n]), &(b[n]),
                                    i, tna - i, tnb - i, p, used_thr);
            memset(&(r[n2 + tna + tnb]), 0,
                   sizeof(BN_ULONG) * (n2 - tna - tnb));
        } else {                /* (j < 0) eg, n == 16, i == 8 and tn == 5 */

            memset(&r[n2], 0, sizeof(*r) * n2);
            if (tna < BN_MUL_RECURSIVE_SIZE_NORMAL
                && tnb < BN_MUL_RECURSIVE_SIZE_NORMAL) {
                bn_mul_normal(&(r[n2]), &(a[n]), tna, &(b[n]), tnb);
            } else {
                for (;;) {
                    i /= 2;
                    /*
                     * these simplified conditions work exclusively because
                     * difference between tna and tnb is 1 or 0
                     */
                    if (i < tna || i < tnb) {
                        if (get_used_thread(used_thr) < NUM_THREADS) {
                            tp[running_cnt] = (BN_ULONG *) calloc(n2*2, sizeof(BN_ULONG));
                            start_mul_part_recursive_thread(&(thr[running_cnt]), &(arg[running_cnt  ]), &(r[n2]),
                                             &(a[n]), &(b[n]),
                                             i, tna - i, tnb - i, tp[running_cnt], used_thr);
                            running_cnt++;
                        } else
                            bn_mul_part_recursive(&(r[n2]),
                                                  &(a[n]), &(b[n]),
                                                  i, tna - i, tnb - i, p, used_thr);
                        break;
                    } else if (i == tna || i == tnb) {
                        if (get_used_thread(used_thr) < NUM_THREADS) {
                            tp[running_cnt] = (BN_ULONG *) calloc(n2*2, sizeof(BN_ULONG));
                            start_mul_recursive_thread(&(thr[running_cnt]), &(arg[running_cnt]), &(r[n2]),
                                             &(a[n]), &(b[n]),
                                             i, tna - i, tnb - i, tp[running_cnt], used_thr);
                            running_cnt++;
                        } else
                            bn_mul_recursive(&(r[n2]),
                                             &(a[n]), &(b[n]),
                                             i, tna - i, tnb - i, p, used_thr);
                        break;
                    }
                }
            }
        }

        /* block until all threads complete */
        // printf("running_cnt %d\n", running_cnt);
        for (int i = 0; i < running_cnt; i++) {
            // printf("i %d\n", i);
            if ((rc = pthread_join(thr[i], NULL))) {
                fprintf(stderr, "error: pthread_join, rc: %d\n", rc);
                exit(EXIT_FAILURE);
            } else {
                // printf("join%d success\n", i);
            }
            // printf("t%d %d\n", i, thr_data[i].carry);
            free(tp[i]);
        }
    }

    /*-
     * t[32] holds (a[0]-a[1])*(b[1]-b[0]), c1 is the sign
     * r[10] holds (a[0]*b[0])
     * r[32] holds (b[1]*b[1])
     */

    c1 = (int)(bn_add_words(t, r, &(r[n2]), n2));

    if (neg) {                  /* if t[32] is negative */
        c1 -= (int)(bn_sub_words(&(t[n2]), t, &(t[n2]), n2));
    } else {
        /* Might have a carry */
        c1 += (int)(bn_add_words(&(t[n2]), &(t[n2]), t, n2));
    }

    /*-
     * t[32] holds (a[0]-a[1])*(b[1]-b[0])+(a[0]*b[0])+(a[1]*b[1])
     * r[10] holds (a[0]*b[0])
     * r[32] holds (b[1]*b[1])
     * c1 holds the carry bits
     */
    c1 += (int)(bn_add_words(&(r[n]), &(r[n]), &(t[n2]), n2));
    if (c1) {
        p = &(r[n + n2]);
        lo = *p;
        ln = (lo + c1) & BN_MASK2;
        *p = ln;

        /*
         * The overflow will stop before we over write words we should not
         * overwrite
         */
        if (ln < (BN_ULONG)c1) {
            do {
                p++;
                lo = *p;
                ln = (lo + 1) & BN_MASK2;
                *p = ln;
            } while (ln == 0);
        }
    }
}

/*-
 * a and b must be the same size, which is n2.
 * r needs to be n2 words and t needs to be n2*2
 */
void bn_mul_low_recursive(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n2,
                          BN_ULONG *t)
{
    int n = n2 / 2;
    int u = 99;
    bn_mul_recursive(r, a, b, n, 0, 0, &(t[0]), &u);
    if (n >= BN_MUL_LOW_RECURSIVE_SIZE_NORMAL) {
        bn_mul_low_recursive(&(t[0]), &(a[0]), &(b[n]), n, &(t[n2]));
        bn_add_words(&(r[n]), &(r[n]), &(t[0]), n);
        bn_mul_low_recursive(&(t[0]), &(a[n]), &(b[0]), n, &(t[n2]));
        bn_add_words(&(r[n]), &(r[n]), &(t[0]), n);
    } else {
        bn_mul_low_normal(&(t[0]), &(a[0]), &(b[n]), n);
        bn_mul_low_normal(&(t[n]), &(a[n]), &(b[0]), n);
        bn_add_words(&(r[n]), &(r[n]), &(t[0]), n);
        bn_add_words(&(r[n]), &(r[n]), &(t[n]), n);
    }
}
#endif                          /* BN_RECURSION */

int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int ret = bn_mul_fixed_top(r, a, b, ctx);

    bn_correct_top(r);
    bn_check_top(r);

    return ret;
}

int bn_mul_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int ret = 0;
    int top, al, bl;
    BIGNUM *rr;
#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
    int i;
#endif
#ifdef BN_RECURSION
    BIGNUM *t = NULL;
    int j = 0, k;
#endif

    bn_check_top(a);
    bn_check_top(b);
    bn_check_top(r);

    al = a->top;
    bl = b->top;

    if ((al == 0) || (bl == 0)) {
        BN_zero(r);
        return 1;
    }
    top = al + bl;

    BN_CTX_start(ctx);
    if ((r == a) || (r == b)) {
        if ((rr = BN_CTX_get(ctx)) == NULL)
            goto err;
    } else
        rr = r;

#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
    i = al - bl;
    // printf("i %d, al %d, bl %d\n", i, al, bl);
#endif
#ifdef BN_MUL_COMBA
    if (i == 0) {
# if 0
        if (al == 4) {
            if (bn_wexpand(rr, 8) == NULL)
                goto err;
            rr->top = 8;
            bn_mul_comba4(rr->d, a->d, b->d);
            goto end;
        }
# endif
    // printf("comba\n");
        if (al == 8) {
            if (bn_wexpand(rr, 16) == NULL)
                goto err;
            rr->top = 16;
            bn_mul_comba8(rr->d, a->d, b->d);
            goto end;
        }
    }
#endif                          /* BN_MUL_COMBA */
#ifdef BN_RECURSION
    if ((al >= BN_MULL_SIZE_NORMAL) && (bl >= BN_MULL_SIZE_NORMAL)) {
        if (i >= -1 && i <= 1) {
            // printf("recursion\n");
            /*
             * Find out the power of two lower or equal to the longest of the
             * two numbers
             */
            if (i >= 0) {
                j = BN_num_bits_word((BN_ULONG)al);
            }
            if (i == -1) {
                j = BN_num_bits_word((BN_ULONG)bl);
            }
            j = 1 << (j - 1);
            // printf("j %d\n", j);
            assert(j <= al || j <= bl);
            k = j + j;
            t = BN_CTX_get(ctx);
            if (t == NULL)
                goto err;
            if (al > j || bl > j) {
                // printf("mul-part-rec\n");
                if (bn_wexpand(t, k * 4) == NULL)
                    goto err;
                if (bn_wexpand(rr, k * 4) == NULL)
                    goto err;

                int used_thread = 1;
                bn_mul_part_recursive(rr->d, a->d, b->d,
                                      j, al - j, bl - j, t->d, &used_thread);
            } else {            /* al <= j && bl <= j */
                // al or bl is exacly the power of two
                if (bn_wexpand(t, k * 2) == NULL)
                    goto err;
                if (bn_wexpand(rr, k * 2) == NULL)
                    goto err;
                int used_thread = 1;
                bn_mul_recursive(rr->d, a->d, b->d, j, al - j, bl - j, t->d, &used_thread);
            }
            rr->top = top;
            goto end;
        }
    }
#endif                          /* BN_RECURSION */
    if (bn_wexpand(rr, top) == NULL)
        goto err;
    rr->top = top;
    // printf("normal\n");
    bn_mul_normal(rr->d, a->d, al, b->d, bl);

#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
 end:
#endif
    rr->neg = a->neg ^ b->neg;
    rr->flags |= BN_FLG_FIXED_TOP;
    if (r != rr && BN_copy(r, rr) == NULL)
        goto err;

    ret = 1;
 err:
    bn_check_top(r);
    BN_CTX_end(ctx);
    return ret;
}


void bn_mul_normal_seq(BN_ULONG *r, BN_ULONG *a, int na, BN_ULONG *b, int nb) {
    BN_ULONG* rr;

    rr = &(r[na]);
    if (nb <= 0) {
        (void)bn_mul_words(r, a, na, 0);
        return;
    } else
        rr[0] = bn_mul_words(r, a, na, b[0]);

    for (;;) {
        if (--nb <= 0)
            return;
        rr[1] = bn_mul_add_words(&(r[1]), a, na, b[1]);
        if (--nb <= 0)
            return;
        rr[2] = bn_mul_add_words(&(r[2]), a, na, b[2]);
        if (--nb <= 0)
            return;
        rr[3] = bn_mul_add_words(&(r[3]), a, na, b[3]);
        if (--nb <= 0)
            return;
        rr[4] = bn_mul_add_words(&(r[4]), a, na, b[4]);
        rr += 4;
        r += 4;
        b += 4;
    }
}

void *bn_mul_normal_thread(void *ptr) {
    mul_normal_args *args = (mul_normal_args *) ptr;

    BN_ULONG* a = args->a;
    BN_ULONG* b = args->b;
    BN_ULONG* r = args->r;
    int na = args->na;
    int nb = args->nb;
    args->nr = na + nb;

    bn_mul_normal_seq(r, a, na, b, nb);

    pthread_exit(NULL);
}

void print_arr(BN_ULONG *a, int n) {
    for (int i = 0; i < n; i++) {
        printf("%lx\n", a[i]);
    }
}

void bn_mul_normal(BN_ULONG *r, BN_ULONG *a, int na, BN_ULONG *b, int nb)
{
    if (na < nb) {
        int itmp;
        BN_ULONG *ltmp;

        itmp = na;
        na = nb;
        nb = itmp;
        ltmp = a;
        a = b;
        b = ltmp;
    }

    if (nb > MIN_BN_SIZE_MUL_NORMAL_PARALLEL) {

        memset(r, 0, (na+nb)*sizeof(BN_ULONG));

        pthread_t thr[NUM_THREADS];
        int rc;


        /* create a thread_data_t argument array */
        mul_normal_args thr_data[NUM_THREADS];
        // BN_ULONG* r_tmp[NUM_THREADS];

        /* create threads, divide array */
        int new_nb = nb/NUM_THREADS;
        int l_idx = 0;

        for (int i = 0; i < NUM_THREADS; ++i) {
            if (i == (NUM_THREADS - 1))
                thr_data[i].nb = new_nb + nb % NUM_THREADS;
            else
                thr_data[i].nb = new_nb;

            l_idx = new_nb * i;
            thr_data[i].a = a;
            thr_data[i].b = &(b[l_idx]);
            thr_data[i].na = na;
            thr_data[i].r = (BN_ULONG *) malloc((thr_data[i].nb + na)* sizeof(BN_ULONG));
            if (thr_data[i].r == NULL) {
                fprintf(stderr, "error: malloc error \n");
                exit(EXIT_FAILURE);
            }

            if ((rc = pthread_create(&thr[i], NULL, bn_mul_normal_thread, &thr_data[i]))) {
              fprintf(stderr, "error: pthread_create, rc: %d\n", rc);
              exit(EXIT_FAILURE);
            }
        }

        /* block until all threads complete */
        BN_ULONG carry;
        for (int i = 0; i < NUM_THREADS; ++i) {
            pthread_join(thr[i], NULL);

            int nr = thr_data[i].nr;
            carry = bn_add_words(r, r, thr_data[i].r, nr);

            if (i != NUM_THREADS - 1) {
                r[nr] = carry;
            }
            r += thr_data[i].nb;
            free(thr_data[i].r);
        }
    } else { //non parallel
        bn_mul_normal_seq(r, a, na, b, nb);
    }
}

void bn_mul_low_normal(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n)
{
    bn_mul_words(r, a, n, b[0]);

    for (;;) {
        if (--n <= 0)
            return;
        bn_mul_add_words(&(r[1]), a, n, b[1]);
        if (--n <= 0)
            return;
        bn_mul_add_words(&(r[2]), a, n, b[2]);
        if (--n <= 0)
            return;
        bn_mul_add_words(&(r[3]), a, n, b[3]);
        if (--n <= 0)
            return;
        bn_mul_add_words(&(r[4]), a, n, b[4]);
        r += 4;
        b += 4;
    }
}
