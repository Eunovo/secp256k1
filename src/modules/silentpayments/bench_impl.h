/***********************************************************************
 * Copyright (c) 2024 josibake                                         *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SILENTPAYMENTS_BENCH_H
#define SECP256K1_MODULE_SILENTPAYMENTS_BENCH_H

#include <stdio.h>
#include "../../../include/secp256k1_silentpayments.h"

#define NUM_LABELS 10
#define MAX_BENCH_TXS 10
#define OUTPUTS_PER_TX 2

typedef struct {
    secp256k1_context *ctx;
    secp256k1_pubkey spend_pubkeys[1];
    unsigned char scan_key[32];
    unsigned char input_pubkey33[33];
    size_t n_txs;
    secp256k1_xonly_pubkey tx_outputs[MAX_BENCH_TXS * OUTPUTS_PER_TX];
    secp256k1_xonly_pubkey tx_inputs[MAX_BENCH_TXS * OUTPUTS_PER_TX];
    secp256k1_silentpayments_prevouts_summary prevouts_summary[MAX_BENCH_TXS];
    const secp256k1_silentpayments_prevouts_summary *prevouts_summary_ptrs[MAX_BENCH_TXS * OUTPUTS_PER_TX];
    secp256k1_silentpayments_found_output found_outputs[MAX_BENCH_TXS * OUTPUTS_PER_TX];
    secp256k1_silentpayments_found_output *found_output_ptrs[MAX_BENCH_TXS * OUTPUTS_PER_TX];
    unsigned char scalar[32];
    unsigned char smallest_outpoint[MAX_BENCH_TXS * 36];
} bench_silentpayments_data;

/* we need a non-null pointer for the cache */
static int noop;
void* label_cache = &noop;
const unsigned char* label_lookup(const unsigned char* key, const void* cache_ptr) {
    (void)key;
    (void)cache_ptr;
    return NULL;
}

static void bench_silentpayments_scan_setup_n(void* arg, size_t n_txs) {
    size_t i, k;
    bench_silentpayments_data *data = (bench_silentpayments_data*)arg;
    const unsigned char tx_outputs[2][32] = {
        {0x84,0x17,0x92,0xc3,0x3c,0x9d,0xc6,0x19,0x3e,0x76,0x74,0x41,0x34,0x12,0x5d,0x40,0xad,0xd8,0xf2,0xf4,0xa9,0x64,0x75,0xf2,0x8b,0xa1,0x50,0xbe,0x03,0x2d,0x64,0xe8},
        {0x2e,0x84,0x7b,0xb0,0x1d,0x1b,0x49,0x1d,0xa5,0x12,0xdd,0xd7,0x60,0xb8,0x50,0x96,0x17,0xee,0x38,0x05,0x70,0x03,0xd6,0x11,0x5d,0x00,0xba,0x56,0x24,0x51,0x32,0x3a},
    };
    const unsigned char static_tx_input[32] = {
        0xf2,0x07,0x16,0x2b,0x1a,0x7a,0xbc,0x51,
        0xc4,0x20,0x17,0xbe,0xf0,0x55,0xe9,0xec,
        0x1e,0xfc,0x3d,0x35,0x67,0xcb,0x72,0x03,
        0x57,0xe2,0xb8,0x43,0x25,0xdb,0x33,0xac
    };
    const unsigned char smallest_outpoint[36] = {
        0x16, 0x9e, 0x1e, 0x83, 0xe9, 0x30, 0x85, 0x33, 0x91,
        0xbc, 0x6f, 0x35, 0xf6, 0x05, 0xc6, 0x75, 0x4c, 0xfe,
        0xad, 0x57, 0xcf, 0x83, 0x87, 0x63, 0x9d, 0x3b, 0x40,
        0x96, 0xc5, 0x4f, 0x18, 0xf4, 0x00, 0x00, 0x00, 0x00,
    };
    const unsigned char spend_pubkey[33] = {
        0x02,0xee,0x97,0xdf,0x83,0xb2,0x54,0x6a,
        0xf5,0xa7,0xd0,0x62,0x15,0xd9,0x8b,0xcb,
        0x63,0x7f,0xe0,0x5d,0xd0,0xfa,0x37,0x3b,
        0xd8,0x20,0xe6,0x64,0xd3,0x72,0xde,0x9a,0x01
    };
    const unsigned char scan_key[32] = {
        0xa8,0x90,0x54,0xc9,0x5b,0xe3,0xc3,0x01,
        0x56,0x65,0x74,0xf2,0xaa,0x93,0xad,0xe0,
        0x51,0x85,0x09,0x03,0xa6,0x9c,0xbd,0xd1,
        0xd4,0x7e,0xae,0x26,0x3d,0x7b,0xc0,0x31
    };
    secp256k1_keypair input_keypair;
    secp256k1_pubkey input_pubkey;
    const secp256k1_xonly_pubkey *tx_input_ptrs[2];
    size_t pubkeylen = 33;

    data->n_txs = n_txs;

    for (i = 0; i < 32; i++) {
        data->scalar[i] = i + 1;
    }

    /* Set up n_txs transactions */
    for (k = 0; k < n_txs; k++) {
        size_t base_idx = k * OUTPUTS_PER_TX;

        /* Parse output pubkeys for this transaction (same outputs for all txs in benchmark) */
        for (i = 0; i < OUTPUTS_PER_TX; i++) {
            CHECK(secp256k1_xonly_pubkey_parse(data->ctx, &data->tx_outputs[base_idx + i], tx_outputs[i]));
        }

        /* Create unique input keys for each transaction by tweaking the scalar */
        data->scalar[0] = (unsigned char)(k + 1);
        CHECK(secp256k1_keypair_create(data->ctx, &input_keypair, data->scalar));
        CHECK(secp256k1_keypair_pub(data->ctx, &input_pubkey, &input_keypair));
        if (k == 0) {
            CHECK(secp256k1_ec_pubkey_serialize(data->ctx, data->input_pubkey33, &pubkeylen, &input_pubkey, SECP256K1_EC_COMPRESSED));
        }

        /* Create the input public keys for this transaction */
        CHECK(secp256k1_keypair_xonly_pub(data->ctx, &data->tx_inputs[base_idx], NULL, &input_keypair));
        CHECK(secp256k1_xonly_pubkey_parse(data->ctx, &data->tx_inputs[base_idx + 1], static_tx_input));

        /* Create unique smallest outpoint for each transaction */
        memcpy(&data->smallest_outpoint[k * 36], smallest_outpoint, 36);
        data->smallest_outpoint[k * 36 + 32] = (unsigned char)k;  /* Make it unique */

        /* Create prevouts_summary for this transaction */
        tx_input_ptrs[0] = &data->tx_inputs[base_idx];
        tx_input_ptrs[1] = &data->tx_inputs[base_idx + 1];
        CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(data->ctx,
            &data->prevouts_summary[k],
            &data->smallest_outpoint[k * 36],
            tx_input_ptrs, 2,
            NULL, 0
        ));
    }

    /* Set up pointer arrays for batch API */
    for (k = 0; k < n_txs; k++) {
        for (i = 0; i < OUTPUTS_PER_TX; i++) {
            size_t idx = k * OUTPUTS_PER_TX + i;
            data->prevouts_summary_ptrs[idx] = &data->prevouts_summary[k];
            data->found_output_ptrs[idx] = &data->found_outputs[idx];
        }
    }

    CHECK(secp256k1_ec_pubkey_parse(data->ctx, &data->spend_pubkeys[0], spend_pubkey, pubkeylen));
    memcpy(data->scan_key, scan_key, 32);
}

static void bench_silentpayments_scan_setup(void* arg) {
    bench_silentpayments_scan_setup_n(arg, 1);
}

static void bench_silentpayments_scan_setup_multi(void* arg) {
    bench_silentpayments_scan_setup_n(arg, MAX_BENCH_TXS);
}

static void bench_silentpayments_tx_scan(void* arg, int iters, int use_labels, int use_batch) {
    size_t i, k;
    uint32_t n_found = 0;
    bench_silentpayments_data *data = (bench_silentpayments_data*)arg;
    const secp256k1_silentpayments_label_lookup label_lookup_fn = use_labels ? label_lookup : NULL;
    const void *label_context = use_labels ? label_cache : NULL;
    size_t total_outputs = data->n_txs * OUTPUTS_PER_TX;

    if (use_batch) {
        const secp256k1_xonly_pubkey *tx_output_ptrs[MAX_BENCH_TXS * OUTPUTS_PER_TX];
        const secp256k1_silentpayments_prevouts_summary *prevouts_summary_ptrs_copy[MAX_BENCH_TXS * OUTPUTS_PER_TX];

        for (i = 0; i < (size_t)iters; i++) {
            size_t j;
            /* Need to reset pointer arrays each iteration since batch_scan_txs modifies them */
            for (j = 0; j < total_outputs; j++) {
                tx_output_ptrs[j] = &data->tx_outputs[j];
                prevouts_summary_ptrs_copy[j] = data->prevouts_summary_ptrs[j];
            }

            CHECK(secp256k1_silentpayments_recipient_batch_scan_txs(data->ctx,
                data->found_output_ptrs, &n_found,
                tx_output_ptrs, total_outputs,
                prevouts_summary_ptrs_copy,
                data->scan_key,
                &data->spend_pubkeys[0],
                label_lookup_fn, label_context)
            );
            CHECK(n_found == 0);
        }
    } else {
        const secp256k1_xonly_pubkey *tx_output_ptrs[OUTPUTS_PER_TX];

        for (i = 0; i < (size_t)iters; i++) {
            for (k = 0; k < data->n_txs; k++) {
                size_t j, base_idx = k * OUTPUTS_PER_TX;
                for (j = 0; j < OUTPUTS_PER_TX; j++) {
                    tx_output_ptrs[j] = &data->tx_outputs[base_idx + j];
                }

                CHECK(secp256k1_silentpayments_recipient_scan_outputs(data->ctx,
                    data->found_output_ptrs, &n_found,
                    tx_output_ptrs, OUTPUTS_PER_TX,
                    data->scan_key,
                    &data->prevouts_summary[k],
                    &data->spend_pubkeys[0],
                    label_lookup_fn, label_context)
                );
                CHECK(n_found == 0);
            }
        }
    }
}

static void bench_silentpayments_full_scan(void *arg, int iters) {
    bench_silentpayments_tx_scan(arg, iters, 0, 0);
}

static void bench_silentpayments_full_scan_with_labels(void *arg, int iters) {
    bench_silentpayments_tx_scan(arg, iters, 1, 0);
}

static void bench_silentpayments_batch_scan(void *arg, int iters) {
    bench_silentpayments_tx_scan(arg, iters, 0, 1);
}

static void bench_silentpayments_batch_scan_with_labels(void *arg, int iters) {
    bench_silentpayments_tx_scan(arg, iters, 1, 1);
}

static void bench_silentpayments_prevouts_summary_create(void *arg, int iters) {
    int i;
    secp256k1_silentpayments_prevouts_summary prevouts_summary;
    bench_silentpayments_data *data = (bench_silentpayments_data*)arg;
    const secp256k1_xonly_pubkey *tx_input_ptrs[2];
    tx_input_ptrs[0] = &data->tx_inputs[0];
    tx_input_ptrs[1] = &data->tx_inputs[1];

    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(data->ctx,
            &prevouts_summary,
            data->smallest_outpoint,
            tx_input_ptrs, 2,
            NULL, 0)
        );
    }
}

static void bench_silentpayments_batch_prevouts_summary_create(void *arg, int iters) {
    size_t k;
    int i;
    bench_silentpayments_data *data = (bench_silentpayments_data*)arg;
    secp256k1_silentpayments_prevouts_summary summaries[MAX_BENCH_TXS];
    secp256k1_silentpayments_prevouts_summary *summary_ptrs[MAX_BENCH_TXS];
    const secp256k1_xonly_pubkey *xonly_per_tx[MAX_BENCH_TXS][OUTPUTS_PER_TX];
    const secp256k1_xonly_pubkey * const *xonly_ptrs[MAX_BENCH_TXS];
    size_t n_xonly[MAX_BENCH_TXS];
    const unsigned char *outpoints[MAX_BENCH_TXS];

    for (k = 0; k < data->n_txs; k++) {
        size_t base_idx = k * OUTPUTS_PER_TX;
        xonly_per_tx[k][0] = &data->tx_inputs[base_idx];
        xonly_per_tx[k][1] = &data->tx_inputs[base_idx + 1];
        xonly_ptrs[k] = xonly_per_tx[k];
        n_xonly[k] = OUTPUTS_PER_TX;
        outpoints[k] = &data->smallest_outpoint[k * 36];
        summary_ptrs[k] = &summaries[k];
    }

    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_silentpayments_recipient_batch_prevouts_summary_create(data->ctx,
            summary_ptrs,
            outpoints,
            xonly_ptrs, n_xonly,
            NULL, NULL,
            data->n_txs)
        );
    }
}

static void bench_silentpayments_label_create(void *arg, int iters) {
    secp256k1_silentpayments_label label;
    unsigned char label_tweak[32];
    int i;

    bench_silentpayments_data *data = (bench_silentpayments_data*)arg;
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_silentpayments_recipient_label_create(
            data->ctx,
            &label, label_tweak,
            data->scan_key, 0)
        );
    }
}

static void bench_silentpayments_batch_label_create(void *arg, int iters) {
    secp256k1_silentpayments_label labels[NUM_LABELS];
    secp256k1_silentpayments_label *label_ptrs[NUM_LABELS];
    unsigned char label_tweaks[NUM_LABELS][32];
    unsigned char *label_tweak_ptrs[NUM_LABELS];
    int i;
    bench_silentpayments_data *data = (bench_silentpayments_data*)arg;

    for (i = 0; i < NUM_LABELS; i++) {
        label_ptrs[i] = &labels[i];
        label_tweak_ptrs[i] = label_tweaks[i];
    }
    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_silentpayments_recipient_batch_label_create(
            data->ctx,
            label_ptrs, label_tweak_ptrs,
            data->scan_key, NUM_LABELS)
        );
    }
}

static void run_silentpayments_bench(int iters, int argc, char** argv) {
    bench_silentpayments_data data;
    int d = argc == 1;

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    if (d || have_flag(argc, argv, "silentpayments") || have_flag(argc, argv, "silentpayments_full_scan")) run_benchmark("silentpayments_full_scan", bench_silentpayments_full_scan, bench_silentpayments_scan_setup, NULL, &data, 10, iters);
    if (d || have_flag(argc, argv, "silentpayments") || have_flag(argc, argv, "silentpayments_full_scan_with_labels")) run_benchmark("silentpayments_full_scan_with_labels", bench_silentpayments_full_scan_with_labels, bench_silentpayments_scan_setup, NULL, &data, 10, iters);

    if (d || have_flag(argc, argv, "silentpayments") || have_flag(argc, argv, "silentpayments_batch_scan")) {
        char batch_scan_name[64];
        sprintf(batch_scan_name, "silentpayments_batch_scan_%utxs", MAX_BENCH_TXS);

        run_benchmark(batch_scan_name, bench_silentpayments_batch_scan, bench_silentpayments_scan_setup_multi, NULL, &data, 10, iters);
    }
    if (d || have_flag(argc, argv, "silentpayments") || have_flag(argc, argv, "silentpayments_batch_scan_with_labels")) {
        char batch_scan_labels_name[64];
        sprintf(batch_scan_labels_name, "silentpayments_batch_scan_%utxs_with_labels", MAX_BENCH_TXS);

        run_benchmark(batch_scan_labels_name, bench_silentpayments_batch_scan_with_labels, bench_silentpayments_scan_setup_multi, NULL, &data, 10, iters);
    }

    if (d || have_flag(argc, argv, "silentpayments") || have_flag(argc, argv, "silentpayments_prevouts_summary_create")) run_benchmark("silentpayments_prevouts_summary_create", bench_silentpayments_prevouts_summary_create, bench_silentpayments_scan_setup, NULL, &data, 10, iters);
    if (d || have_flag(argc, argv, "silentpayments") || have_flag(argc, argv, "silentpayments_batch_prevouts_summary_create")) {
        char batch_prevouts_name[64];
        sprintf(batch_prevouts_name, "silentpayments_batch_prevouts_summary_create_%utxs", MAX_BENCH_TXS);
        run_benchmark(batch_prevouts_name, bench_silentpayments_batch_prevouts_summary_create, bench_silentpayments_scan_setup_multi, NULL, &data, 10, iters);
    }

    if (d || have_flag(argc, argv, "silentpayments")) {
        char batch_label_create_bench_name[64];
        sprintf(batch_label_create_bench_name, "silentpayments_batch_create_%ulabels", NUM_LABELS);

        run_benchmark("silentpayments_create_label", bench_silentpayments_label_create, bench_silentpayments_scan_setup, NULL, &data, 10, iters);
        run_benchmark(batch_label_create_bench_name, bench_silentpayments_batch_label_create, bench_silentpayments_scan_setup, NULL, &data, 10, iters);
    }

    secp256k1_context_destroy(data.ctx);
}

#endif /* SECP256K1_MODULE_SILENTPAYMENTS_BENCH_H */
