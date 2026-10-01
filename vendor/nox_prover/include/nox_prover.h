// NONOS Operating System (AGPL-3.0-or-later)
/*
 * nox_prover: a NOX Shield spend proved on the device.
 *
 * Link libnox_prover.a (build_ios.py, or cargo for Android). Every string the
 * library returns belongs to the caller, who hands it back to nox_free. The
 * proof JSON holds the spender's new note secrets: store it as a secret and
 * wipe it once stored.
 */
#ifndef NOX_PROVER_H
#define NOX_PROVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Result codes, one per error kind. */
#define NOX_OK               0
#define NOX_ERR_REQUEST      1  /* the request or the seed file is malformed or inconsistent */
#define NOX_ERR_POLICY       2  /* the request breaks an anonymity default and does not opt out */
#define NOX_ERR_ENTROPY      3  /* not enough entropy: pass 512 fresh bytes */
#define NOX_ERR_CACHE        4  /* the periodic cache is malformed or not the launch circuit's */
#define NOX_ERR_CIRCUIT      5  /* the circuit refused the witness */
#define NOX_ERR_NOT_VERIFIED 6  /* a proof did not verify */
#define NOX_ERR_CANCELLED    7  /* cancelled between phases */
#define NOX_ERR_NULL         8  /* a required pointer was null */
#define NOX_ERR_RANK         9  /* the rank certificate fell short: prove again with fresh entropy */

/* The bytes of fresh randomness a proof needs. */
#define NOX_ENTROPY_BYTES 512

/* Phases, in the order progress reports them. */
enum nox_phase {
    NOX_PHASE_REQUEST = 0,
    NOX_PHASE_BLINDING,
    NOX_PHASE_REGION,
    NOX_PHASE_PRODUCTS,
    NOX_PHASE_PERIODIC,
    NOX_PHASE_COMPOSITION,
    NOX_PHASE_COMPOSITION_TREE,
    NOX_PHASE_DEEP,
    NOX_PHASE_FRI,
    NOX_PHASE_QUERIES,
    NOX_PHASE_VERIFIED
};

/* Called at every phase boundary, possibly from a worker thread. */
typedef void (*nox_progress_fn)(void *ctx, uint32_t phase, float fraction);

/* Prove a spend. `cache` is the bundled periodic cache; its root is checked
 * against the launch circuit's before use. `progress` may be NULL. `cancel`
 * may be NULL; otherwise set *cancel nonzero to stop at the next phase
 * boundary. On NOX_OK, *out is the proof JSON; otherwise it is the reason. */
int32_t nox_prove_ex(const char *request, const char *seed,
                     const uint8_t *entropy, size_t entropy_len,
                     const uint8_t *cache, size_t cache_len,
                     nox_progress_fn progress, void *ctx,
                     const volatile uint8_t *cancel,
                     char **out);

/* Verify a proof against its 36 public words and the bundled cache. */
int32_t nox_verify(const uint8_t *proof, size_t proof_len,
                   const uint64_t *publics, size_t n_publics,
                   const uint8_t *cache, size_t cache_len);

/* The earlier interface: no cache, no progress, no cancellation.
 * Returns 0 on success, 1 on a refusal, 2 on a null argument. */
int32_t nox_prove(const char *request, const char *seed,
                  const uint8_t *entropy, size_t entropy_len,
                  char **out);

/* Free a string the library returned; it is wiped first. */
void nox_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* NOX_PROVER_H */
