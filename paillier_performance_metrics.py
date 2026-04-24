"""
Paillier Homomorphic Encryption — Performance Metrics Suite
============================================================
Measures and reports performance across all cryptographic and banking
operations used in the Banking Data Privacy Preservation System.

Mirrors the exact 13-benchmark structure of the BFV metrics suite so
results can be compared side-by-side.

Metrics covered
---------------
1.  Key Generation          – time to generate a Paillier key pair (512-bit)
2.  Encryption              – throughput for encrypt_balance (floats)
3.  Decryption              – throughput for decrypt_balance
4.  Homomorphic Addition    – add_encrypted / add_balances
5.  Homomorphic Subtraction – process_transaction (withdrawal path)
6.  Scalar Multiplication   – multiply_encrypted_by_constant (interest calc)
7.  Deposit (end-to-end)    – encrypt → homomorphic add → decrypt
8.  Withdrawal (e2e)        – encrypt → homomorphic sub → decrypt
9.  Transfer (e2e)          – two-account homomorphic update
10. Serialization           – str(ciphertext) + int(str) round-trip
11. Total-balance analytics – N-account homomorphic sum
12. Correctness / accuracy  – decryption error across many samples
13. Ciphertext size         – size in bytes of a serialized Paillier ciphertext

Usage
-----
    python paillier_performance_metrics.py [--runs N] [--verbose] [--export]

    --runs N     Number of repetitions per benchmark (default: 50)
    --verbose    Print per-run timings
    --export     Save results to paillier_metrics_report.json

Requirements
------------
    pip install tabulate   # optional, for pretty tables
"""

import time
import statistics
import argparse
import random
import sys
import os
import json

# ── Ensure the Paillier module is importable ──────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from homomorphic_encryption import (
        HomomorphicBankingSystem,
        generate_keypair,
        encrypt, decrypt,
        encrypt_float, decrypt_float,
        add_encrypted,
        multiply_encrypted_by_constant,
        PaillierPublicKey, PaillierPrivateKey,
    )
except ModuleNotFoundError:
    print(
        "\n[ERROR] Cannot find 'homomorphic_encryption.py'.\n"
        "Place this script in the SAME directory as that file and re-run.\n"
    )
    sys.exit(1)

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

# ── ANSI colours ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

PRECISION = 100000   # matches HomomorphicBankingSystem.precision


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _timer(fn, *args, **kwargs):
    """Return (result, elapsed_seconds)."""
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    return result, time.perf_counter() - t0


def _bench(label: str, fn, runs: int, *args, verbose: bool = False, **kwargs):
    """
    Run fn(*args, **kwargs) for `runs` iterations.
    Returns a dict of timing statistics + throughput.
    """
    times = []
    for _ in range(runs):
        _, elapsed = _timer(fn, *args, **kwargs)
        times.append(elapsed)
        if verbose:
            print(f"    [{label}] {elapsed * 1000:.3f} ms")

    mean   = statistics.mean(times)
    median = statistics.median(times)
    stdev  = statistics.stdev(times) if len(times) > 1 else 0.0

    return {
        'label':       label,
        'runs':        runs,
        'mean_ms':     mean   * 1000,
        'median_ms':   median * 1000,
        'stdev_ms':    stdev  * 1000,
        'min_ms':      min(times) * 1000,
        'max_ms':      max(times) * 1000,
        'ops_per_sec': 1.0 / mean if mean > 0 else float('inf'),
    }


def _rand_balance():
    """Random realistic balance ₹0.01 – ₹9999.99."""
    return round(random.uniform(0.01, 9999.99), 2)


# ─────────────────────────────────────────────────────────────────────────────
# Individual benchmarks  (same numbering / names as BFV suite)
# ─────────────────────────────────────────────────────────────────────────────

def bench_keygen(runs, verbose):
    print(f"  {CYAN}1/13  Key Generation…{RESET}")
    return _bench("Key Generation", generate_keypair, runs, 512, verbose=verbose)


def bench_encrypt(pk, runs, verbose):
    print(f"  {CYAN}2/13  Encryption (float)…{RESET}")
    return _bench("Encrypt (float)", encrypt_float, runs,
                  pk, _rand_balance(), PRECISION, verbose=verbose)


def bench_decrypt(pk, sk, runs, verbose):
    print(f"  {CYAN}3/13  Decryption…{RESET}")
    ct = encrypt_float(pk, 5000.00, PRECISION)
    return _bench("Decrypt (float)", decrypt_float, runs,
                  sk, ct, PRECISION, verbose=verbose)


def bench_hom_add(pk, runs, verbose):
    print(f"  {CYAN}4/13  Homomorphic Addition…{RESET}")
    ct1 = encrypt_float(pk, _rand_balance(), PRECISION)
    ct2 = encrypt_float(pk, _rand_balance(), PRECISION)
    return _bench("HE Addition", add_encrypted, runs, pk, ct1, ct2, verbose=verbose)


def bench_hom_sub(pk, runs, verbose):
    """
    Paillier subtraction: add the encrypted negative
    (mirrors HomomorphicBankingSystem.process_transaction with is_credit=False).
    """
    print(f"  {CYAN}5/13  Homomorphic Subtraction…{RESET}")
    amount = 1000.00
    def _sub():
        ct_balance = encrypt_float(pk, 9000.00, PRECISION)
        scaled     = int(amount * PRECISION)
        neg        = pk.n - scaled
        ct_neg     = encrypt(pk, neg)
        return add_encrypted(pk, ct_balance, ct_neg)
    return _bench("HE Subtraction", _sub, runs, verbose=verbose)


def bench_scalar_mul(pk, runs, verbose):
    """
    Scalar multiplication used for interest calculation:
    multiply_encrypted_by_constant(pk, ct, interest_multiplier)
    """
    print(f"  {CYAN}6/13  Scalar Multiplication (Interest)…{RESET}")
    ct              = encrypt_float(pk, 1000.00, PRECISION)
    interest_rate   = 0.05
    multiplier      = int((1 + interest_rate) * PRECISION)
    return _bench("Scalar Multiply ×1.05", multiply_encrypted_by_constant,
                  runs, pk, ct, multiplier, verbose=verbose)


def bench_deposit_e2e(system, runs, verbose):
    print(f"  {CYAN}7/13  Deposit (end-to-end)…{RESET}")
    def _deposit():
        enc = system.encrypt_balance(10000.00)
        enc = system.process_transaction(enc, 500.00, is_credit=True)
        return system.decrypt_balance(enc)
    return _bench("Deposit E2E", _deposit, runs, verbose=verbose)


def bench_withdrawal_e2e(system, runs, verbose):
    print(f"  {CYAN}8/13  Withdrawal (end-to-end)…{RESET}")
    def _withdraw():
        enc = system.encrypt_balance(10000.00)
        enc = system.process_transaction(enc, 500.00, is_credit=False)
        return system.decrypt_balance(enc)
    return _bench("Withdrawal E2E", _withdraw, runs, verbose=verbose)


def bench_transfer_e2e(system, runs, verbose):
    print(f"  {CYAN}9/13  Transfer (end-to-end)…{RESET}")
    def _transfer():
        enc_from = system.encrypt_balance(20000.00)
        enc_to   = system.encrypt_balance(5000.00)
        enc_from = system.process_transaction(enc_from, 2000.00, is_credit=False)
        enc_to   = system.process_transaction(enc_to,   2000.00, is_credit=True)
        system.decrypt_balance(enc_from)
        system.decrypt_balance(enc_to)
    return _bench("Transfer E2E", _transfer, runs, verbose=verbose)


def bench_serialization(system, runs, verbose):
    """
    Paillier serialization: ciphertext is a plain Python int.
    Firestore stores it as str(int); loading does int(str).
    """
    print(f"  {CYAN}10/13 Serialization round-trip…{RESET}")
    ct = system.encrypt_balance(12345.67)
    def _round_trip():
        s   = str(ct)           # → Firestore (matches save_account)
        ct2 = int(s)            # ← Firestore (matches load_account)
        return ct2
    return _bench("Serialization RT", _round_trip, runs, verbose=verbose)


def bench_analytics_total(system, runs, verbose):
    print(f"  {CYAN}11/13 Total-Balance Analytics (5 accounts)…{RESET}")
    balances = [_rand_balance() for _ in range(5)]
    def _total():
        cts   = [system.encrypt_balance(b) for b in balances]
        total = cts[0]
        for ct in cts[1:]:
            total = system.add_balances(total, ct)
        return system.decrypt_balance(total)
    return _bench("Analytics (5 accs)", _total, runs, verbose=verbose)


def bench_correctness(system, samples=200):
    """
    Correctness: encrypt → deposit → withdrawal → decrypt.
    Checks absolute error and pass-rate (error < ₹0.01).
    """
    print(f"  {CYAN}12/13 Correctness / Accuracy ({samples} samples)…{RESET}")
    errors = []
    fail   = 0
    for _ in range(samples):
        a = round(random.uniform(0.01, 4000.00), 2)
        b = round(random.uniform(0.01, 1000.00), 2)
        c = round(random.uniform(0.01, b),       2)   # c ≤ b → result ≥ 0
        expected = round(a + b - c, 2)

        ct  = system.encrypt_balance(a)
        ct  = system.process_transaction(ct, b, is_credit=True)
        ct  = system.process_transaction(ct, c, is_credit=False)
        got = round(system.decrypt_balance(ct), 2)

        err = abs(got - expected)
        errors.append(err)
        if err >= 0.01:
            fail += 1

    return {
        'samples':       samples,
        'mean_error':    statistics.mean(errors),
        'max_error':     max(errors),
        'pass_rate_pct': (1 - fail / samples) * 100,
    }


def bench_ciphertext_size(system):
    """
    Paillier ciphertext is a large integer (~2× the key modulus in bits).
    For 512-bit keys: n is 1024 bits → ciphertext is ~309 decimal digits.
    """
    print(f"  {CYAN}13/13 Ciphertext Size…{RESET}")
    ct  = system.encrypt_balance(12345.67)
    s   = str(ct)                          # Firestore serialization
    n   = system.public_key.n
    return {
        'ciphertext_bytes':    len(s.encode('utf-8')),
        'ciphertext_kb':       len(s.encode('utf-8')) / 1024,
        'decimal_digits':      len(s),
        'key_bits':            n.bit_length(),
        'n_bit_length':        n.bit_length(),
        'precision':           system.precision,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Report rendering
# ─────────────────────────────────────────────────────────────────────────────

def render_timing_table(results):
    headers = ["Operation", "Runs", "Mean (ms)", "Median (ms)",
               "StdDev (ms)", "Min (ms)", "Max (ms)", "Ops/sec"]
    rows = []
    for r in results:
        rows.append([
            r['label'],
            r['runs'],
            f"{r['mean_ms']:.3f}",
            f"{r['median_ms']:.3f}",
            f"{r['stdev_ms']:.3f}",
            f"{r['min_ms']:.3f}",
            f"{r['max_ms']:.3f}",
            f"{r['ops_per_sec']:.2f}",
        ])
    if HAS_TABULATE:
        return tabulate(rows, headers=headers, tablefmt="rounded_outline")
    # Fallback: plain text
    col_w = [max(len(h), max(len(str(r[i])) for r in rows))
             for i, h in enumerate(headers)]
    sep  = "  ".join("-" * w for w in col_w)
    hdr  = "  ".join(h.ljust(col_w[i]) for i, h in enumerate(headers))
    lines = [hdr, sep]
    for row in rows:
        lines.append("  ".join(str(v).ljust(col_w[i]) for i, v in enumerate(row)))
    return "\n".join(lines)


def render_correctness(c):
    lines = [
        f"  Samples tested            : {c['samples']}",
        f"  Mean abs. error           : {c['mean_error']:.6f} ₹",
        f"  Max abs. error            : {c['max_error']:.6f} ₹",
        f"  Pass rate (< ₹0.01 error) : {c['pass_rate_pct']:.1f}%",
    ]
    if c['pass_rate_pct'] >= 99.0:
        status = GREEN + "PASS ✅"
    else:
        status = RED + "DEGRADED ⚠️"
    lines.append(f"  Status                    : {status}{RESET}")
    return "\n".join(lines)


def render_size(s):
    return (
        f"  Serialized ciphertext size : {s['ciphertext_bytes']:,} bytes "
        f"({s['ciphertext_kb']:.2f} KB)\n"
        f"  Decimal digits             : {s['decimal_digits']}\n"
        f"  Key modulus bit-length     : {s['key_bits']} bits  "
        f"(prime p,q each 512 bits → n = p×q)\n"
        f"  Float precision factor     : {s['precision']:,}  "
        f"(5 decimal places)"
    )


def export_json(timing_results, correctness, size, path="paillier_metrics_report.json"):
    report = {
        "scheme":      "Paillier",
        "key_bits":    512,
        "precision":   PRECISION,
        "timing":      timing_results,
        "correctness": correctness,
        "ciphertext_size": size,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    return path


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Paillier Homomorphic Encryption — Performance Metrics")
    parser.add_argument("--runs",    type=int,  default=50,
                        help="Repetitions per benchmark (default 50)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print per-run timings")
    parser.add_argument("--export",  action="store_true",
                        help="Export results to paillier_metrics_report.json")
    args = parser.parse_args()

    RUNS    = args.runs
    VERBOSE = args.verbose

    print(f"\n{BOLD}{CYAN}{'='*65}")
    print(" Paillier Homomorphic Encryption — Performance Metrics Suite")
    print(f"{'='*65}{RESET}")
    print(f"  Scheme             : Paillier (additive HE)")
    print(f"  Key size           : 512 bits")
    print(f"  Float precision    : {PRECISION:,}  (5 decimal places)")
    print(f"  Runs per benchmark : {RUNS}")
    print(f"  Verbose mode       : {VERBOSE}")
    print(f"  tabulate installed : {HAS_TABULATE}")
    print()

    # ── Shared system ────────────────────────────────────────────────────────
    print(f"{BOLD}Initialising Paillier Banking System (512-bit key gen)…{RESET}")
    t0     = time.perf_counter()
    system = HomomorphicBankingSystem(bits=512)
    t_init = time.perf_counter() - t0
    pk     = system.public_key
    sk     = system.private_key
    print(f"  Keys ready in {t_init * 1000:.1f} ms\n")

    print(f"{BOLD}Running benchmarks…{RESET}\n")

    timing_results = []

    timing_results.append(bench_keygen(RUNS, VERBOSE))
    timing_results.append(bench_encrypt(pk, RUNS, VERBOSE))
    timing_results.append(bench_decrypt(pk, sk, RUNS, VERBOSE))
    timing_results.append(bench_hom_add(pk, RUNS, VERBOSE))
    timing_results.append(bench_hom_sub(pk, RUNS, VERBOSE))
    timing_results.append(bench_scalar_mul(pk, RUNS, VERBOSE))
    timing_results.append(bench_deposit_e2e(system, RUNS, VERBOSE))
    timing_results.append(bench_withdrawal_e2e(system, RUNS, VERBOSE))
    timing_results.append(bench_transfer_e2e(system, RUNS, VERBOSE))
    timing_results.append(bench_serialization(system, RUNS, VERBOSE))
    timing_results.append(bench_analytics_total(system, RUNS, VERBOSE))

    correctness = bench_correctness(system, samples=max(100, RUNS * 2))
    size        = bench_ciphertext_size(system)

    # ── Report ───────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{CYAN}{'='*65}")
    print(" RESULTS")
    print(f"{'='*65}{RESET}\n")

    print(f"{BOLD}── Timing Benchmarks ──────────────────────────────────────{RESET}")
    print(render_timing_table(timing_results))

    print(f"\n{BOLD}── Correctness / Accuracy ─────────────────────────────────{RESET}")
    print(render_correctness(correctness))

    print(f"\n{BOLD}── Ciphertext & Scheme Parameters ─────────────────────────{RESET}")
    print(render_size(size))

    # ── Quick interpretation ─────────────────────────────────────────────────
    print(f"\n{BOLD}── Interpretation ─────────────────────────────────────────{RESET}")
    enc_ms = next(r for r in timing_results if r['label'] == "Encrypt (float)")['mean_ms']
    add_ms = next(r for r in timing_results if r['label'] == "HE Addition")['mean_ms']
    dep_ms = next(r for r in timing_results if r['label'] == "Deposit E2E")['mean_ms']
    ser_ms = next(r for r in timing_results if r['label'] == "Serialization RT")['mean_ms']
    int_ms = next(r for r in timing_results if r['label'] == "Scalar Multiply ×1.05")['mean_ms']

    print(f"  • Encrypting a balance (512-bit) takes  {enc_ms:.1f} ms on average.")
    print(f"  • Homomorphic add takes                 {add_ms:.1f} ms (no decryption needed).")
    print(f"  • Interest calc (scalar mul) takes      {int_ms:.1f} ms.")
    print(f"  • A full deposit takes                  {dep_ms:.1f} ms end-to-end.")
    print(f"  • Firestore serialization (str/int) RT  {ser_ms:.3f} ms  (near-zero).")

    if correctness['pass_rate_pct'] >= 99.9:
        print(f"  • Decryption is {GREEN}perfectly accurate{RESET} across all tested values.")
    elif correctness['pass_rate_pct'] >= 99.0:
        print(f"  • Decryption accuracy is {GREEN}excellent{RESET} ({correctness['pass_rate_pct']:.1f}%).")
    else:
        print(f"  • {RED}Accuracy degraded{RESET}: {correctness['pass_rate_pct']:.1f}% — review precision or key size.")

    # ── Export ───────────────────────────────────────────────────────────────
    if args.export:
        path = export_json(timing_results, correctness, size)
        print(f"\n  {GREEN}Results exported → {path}{RESET}")

    print(f"\n{BOLD}{CYAN}{'='*65}{RESET}")
    print(f"{GREEN}All benchmarks complete!{RESET}\n")


if __name__ == '__main__':
    main()
