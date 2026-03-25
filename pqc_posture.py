#!/usr/bin/env python3
"""
PQC Posture — Full Crypto Inventory + Risk Score + Migration Plan + CBOM

This is the REAL product. Not a toy. Scans actual codebases,
generates industry-standard output, scores risk, gives migration paths.
"""

import os
import re
import json
import hashlib
import time
from dataclasses import dataclass, asdict
from typing import List, Dict
from collections import Counter


@dataclass(frozen=True)
class CryptoFinding:
    file: str
    line: int
    algorithm: str
    category: str  # key_exchange, signature, hash, symmetric, protocol
    risk: str  # CRITICAL, HIGH, MEDIUM, LOW (adjusted for context)
    raw_risk: str  # original risk before context adjustment
    quantum_status: str  # BROKEN, WEAKENED, SAFE
    context: str  # test, config, import, operation, reference, comment
    usage: str  # what the code is actually doing
    migration: str  # what to replace it with
    nist_ref: str  # NIST standard reference


# Comprehensive crypto detection — not just keywords, ACTUAL USAGE PATTERNS
CRYPTO_PATTERNS = {
    # ═══ KEY EXCHANGE (quantum BREAKS these) ═══
    "RSA Key Exchange": {
        "patterns": [
            r'RSA\.generate',
            r'rsa\w*\.generate_private_key',  # catches rsa_mod.generate_private_key
            r'PKCS1_OAEP',
            r'PKCS1_v1_5',
            r'pkcs1v15',
            r'RSA_generate_key',
            r'openssl_pkey_new',  # PHP — don't require RSA inline, it's in $config
            r'KeyPairGenerator\.getInstance\("RSA"',
            r'Cipher\.getInstance\("RSA',  # Java Cipher.getInstance("RSA/ECB/...")
            r'crypto\.generateKeyPairSync\("rsa"',
            r'generateKeyPairSync\("rsa"',  # Node.js destructured import
            r'rsa\.GenerateKey\(',
            r'RsaPrivateKey::new',  # Rust rsa crate
            r'RsaPublicKey::from',  # Rust rsa crate
            r'RSA_2048',  # AWS KMS key spec
            r'RSA_4096',  # AWS KMS key spec
        ],
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-KEM 768 (CRYSTALS-Kyber) — NIST FIPS 203",
        "nist_ref": "NIST SP 800-208, FIPS 203",
    },
    "Diffie-Hellman": {
        "patterns": [
            r'DiffieHellman',
            r'dh\.generate_parameters',
            r'DHParameterNumbers',
            r'createDiffieHellman',
            r'KeyAgreement\.getInstance\("DH"',
        ],
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-KEM 768 (CRYSTALS-Kyber) — NIST FIPS 203",
        "nist_ref": "NIST SP 800-56A",
    },
    "ECDH": {
        "patterns": [
            r'ECDH',
            r'ec\.ECDH\(',
            r'KeyAgreement\.getInstance\("ECDH"',
            r'crypto\.diffieHellman.*curve',
        ],
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-KEM 768 (CRYSTALS-Kyber) — NIST FIPS 203",
        "nist_ref": "NIST SP 800-56A",
    },

    # ═══ SIGNATURES (quantum BREAKS these) ═══
    "ECDSA": {
        "patterns": [
            r'ECDSA',
            r'ec\.generate_private_key',
            r'ec\.SECP256R1',
            r'ec\.SECP384R1',
            r'ec\.SECP521R1',
            r'ECDSASign',
            r'Signature\.getInstance\(".*ECDSA"',
            r'crypto\.sign.*ec',
            r'ecdsa\.GenerateKey\(',
        ],
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 65 (CRYSTALS-Dilithium) — NIST FIPS 204",
        "nist_ref": "NIST FIPS 186-5, FIPS 204",
    },
    "RSA Signature": {
        "patterns": [
            r'RSA_sign',
            r'PKCS1v15.*sign',
            r'PSS.*sign',
            r'Signature\.getInstance\(".*RSA"',
            r'crypto\.sign.*rsa',
        ],
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 65 (CRYSTALS-Dilithium) — NIST FIPS 204",
        "nist_ref": "NIST FIPS 186-5, FIPS 204",
    },
    "DSA": {
        "patterns": [
            r'DSA\.generate',
            r'dsa\.generate_private_key',
            r'KeyPairGenerator\.getInstance\("DSA"',
        ],
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 65 (CRYSTALS-Dilithium) — NIST FIPS 204",
        "nist_ref": "NIST FIPS 186-5",
    },
    "Ed25519": {
        "patterns": [
            r'Ed25519',
            r'ed25519\.Ed25519PrivateKey',
            r'crypto\.sign.*ed25519',
            r'ed25519\.GenerateKey\(',
        ],
        "category": "signature",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "ML-DSA 44 or FALCON-512 — NIST FIPS 204/205",
        "nist_ref": "NIST FIPS 204",
    },

    # ═══ HASH FUNCTIONS (quantum WEAKENS these) ═══
    "MD5": {
        "patterns": [
            r'hashlib\.md5',
            r'MD5\.new',
            r'MD5\(',  # C/C++ MD5() function
            r'MessageDigest\.getInstance\("MD5"',
            r'crypto\.createHash\([\'"]md5[\'"]',  # Node.js single or double quotes
            r'createHash\([\'"]md5[\'"]',  # Node.js destructured
            r'md5\.New\(\)',
            r'\bmd5\(',  # PHP md5() function
            r'MD5PasswordHasher',  # Django
            r'MD5_DIGEST_LENGTH',  # C OpenSSL
        ],
        "category": "hash",
        "risk": "HIGH",
        "quantum_status": "WEAKENED",
        "migration": "SHA-256 or SHA-3-256 minimum. SHA-384+ recommended.",
        "nist_ref": "NIST SP 800-131A (MD5 deprecated)",
    },
    "SHA-1": {
        "patterns": [
            r'hashlib\.sha1',
            r'SHA\.new',
            r'SHA1\.new',
            r'MessageDigest\.getInstance\("SHA-1"',
            r'crypto\.createHash\([\'"]sha1[\'"]',  # Node.js
            r'createHash\([\'"]sha1[\'"]',  # Node.js destructured
            r'createHmac\([\'"]sha1[\'"]',  # Node.js HMAC-SHA1
            r'sha1\.New\(\)',
            r'\bsha1\(',  # PHP sha1() function
            r'SHA1PasswordHasher',  # Django
        ],
        "category": "hash",
        "risk": "HIGH",
        "quantum_status": "WEAKENED",
        "migration": "SHA-256 or SHA-3-256 minimum",
        "nist_ref": "NIST SP 800-131A (SHA-1 deprecated)",
    },

    # ═══ SYMMETRIC (quantum resistant but needs bigger keys) ═══
    "DES/3DES": {
        "patterns": [
            r'DES\.new',
            r'DESede',
            r'TripleDES',
            r'DES3\.new',
            r'crypto\.createCipheriv\([\'"]des',
            r'DES-CBC',  # OpenSSL cipher suite names
            r'DES-CBC3',  # 3DES cipher suite
        ],
        "category": "symmetric",
        "risk": "HIGH",
        "quantum_status": "WEAKENED",
        "migration": "AES-256-GCM",
        "nist_ref": "NIST SP 800-131A (DES withdrawn)",
    },
    "AES-128": {
        "patterns": [
            r'AES.*128',
            r'aes-128',
            r'AES/CBC/.*128',
        ],
        "category": "symmetric",
        "risk": "MEDIUM",
        "quantum_status": "WEAKENED",
        "migration": "AES-256-GCM (Grover's halves effective key length)",
        "nist_ref": "NIST SP 800-131A",
    },
    "AES-256": {
        "patterns": [
            r'AES.*256',
            r'aes-256',
            r'AES/GCM/.*256',
        ],
        "category": "symmetric",
        "risk": "LOW",
        "quantum_status": "SAFE",
        "migration": "Already quantum-resistant (128-bit effective security with Grover's)",
        "nist_ref": "NIST SP 800-131A",
    },

    # ═══ SSH (quantum BREAKS these) ═══
    "SSH RSA/ECDSA Keys": {
        "patterns": [
            r'ssh-rsa\b',  # RSA host/auth keys
            r'ecdsa-sha2-nistp',  # ECDSA SSH keys
            r'RSAAuthentication\s+yes',
            r'PubkeyAcceptedAlgorithms.*ssh-rsa',
            r'HostKeyAlgorithms.*ssh-rsa',
            r'paramiko\.RSAKey',
            r'paramiko\.ECDSAKey',
            r'ssh\.ParsePrivateKey',  # Go SSH
            r'kex_algorithms.*diffie-hellman',
        ],
        "category": "key_exchange",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "SSH keys: Ed448 short-term, ML-DSA when OpenSSH supports it. KEX: sntrup761x25519",
        "nist_ref": "NIST SP 800-131A, draft-ietf-sshm-pq",
    },

    # ═══ CERTIFICATES (quantum BREAKS RSA/ECDSA certs) ═══
    "X.509 RSA/ECDSA Certificates": {
        "patterns": [
            r'openssl\s+req.*-newkey\s+rsa',  # openssl req -newkey rsa:2048
            r'openssl\s+x509',  # x509 cert operations
            r'keytool.*-genkeypair.*RSA',  # Java keytool
            r'X509Certificate',  # Java/C# X.509
            r'x509\.CreateCertificate',  # Go x509
            r'certbot.*--rsa-key-size',  # Let's Encrypt RSA
            r'CERTIFICATE_VERIFY_FAILED',  # cert validation
        ],
        "category": "signature",
        "risk": "HIGH",
        "quantum_status": "BROKEN",
        "migration": "Hybrid certificates (X.509 with ML-DSA + ECDSA dual-signed)",
        "nist_ref": "NIST SP 800-208",
    },

    # ═══ WEB SERVER TLS CONFIG ═══
    "Weak TLS Server Config": {
        "patterns": [
            r'ssl_protocols\s+.*TLSv1[^.2-3]',  # nginx ssl_protocols
            r'ssl_ciphers\s+.*(?:RC4|DES|MD5|NULL)',  # nginx weak ciphers
            r'SSLProtocol\s+.*TLSv1\b',  # Apache SSLProtocol
            r'SSLCipherSuite\s+.*(?:RC4|DES|NULL)',  # Apache weak ciphers
            r'ssl-min-ver\s+TLSv1\.0',  # HAProxy
            r'minVersion.*TLS10',  # Traefik
            r'tls_minimum_protocol_version.*TLSv1_0',  # Envoy
        ],
        "category": "protocol",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "TLS 1.3 minimum, remove weak cipher suites",
        "nist_ref": "NIST SP 800-52 Rev 2",
    },

    # ═══ DEPENDENCY CONFIG PATTERNS ═══
    "Crypto Dependencies": {
        "patterns": [
            r'pycryptodome',  # Python crypto lib
            r'pyOpenSSL',  # Python OpenSSL binding
            r'"bcrypt"',  # npm bcrypt (not quantum-broken but track)
            r'bouncycastle',  # Java crypto provider
            r'jasypt',  # Java encryption
            r'"ring"',  # Rust crypto crate
            r'golang\.org/x/crypto/ssh',  # Go SSH crypto
            r'golang\.org/x/crypto/ed25519',  # Go Ed25519
        ],
        "category": "key_exchange",
        "risk": "MEDIUM",
        "quantum_status": "WEAKENED",
        "migration": "Track library versions; plan upgrade to PQC-enabled releases",
        "nist_ref": "NIST IR 8547",
    },

    # ═══ PROTOCOLS ═══
    "TLS 1.0/1.1": {
        "patterns": [
            r'TLSv1_0',
            r'TLSv1_1',
            r'TLSv1\b',  # K8s/nginx annotations: "TLSv1 TLSv1.1"
            r'TLSv1\.1\b',  # TLSv1.1 as a string
            r'SSLv3',
            r'ssl\.PROTOCOL_TLSv1\b',
            r'TLS_RSA_WITH',
            r'SSL_PROTOCOLS.*TLSv1\b',  # nginx/envoy SSL protocol config
        ],
        "category": "protocol",
        "risk": "CRITICAL",
        "quantum_status": "BROKEN",
        "migration": "TLS 1.3 with hybrid PQC key exchange (ML-KEM + X25519)",
        "nist_ref": "NIST SP 800-52 Rev 2",
    },
    "JWT with RSA/ECDSA": {
        "patterns": [
            r'RS256',
            r'RS384',
            r'RS512',
            r'ES256',
            r'ES384',
            r'PS256',
        ],
        "category": "protocol",
        "risk": "HIGH",
        "quantum_status": "BROKEN",
        "migration": "Consider PQC-compatible token signing when libraries support it",
        "nist_ref": "RFC 7518, NIST FIPS 204",
    },
}

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist',
             'build', '.next', '.tox', 'vendor', 'third_party'}
SCAN_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs',
                   '.rb', '.php', '.cs', '.c', '.cpp', '.h', '.yaml', '.yml',
                   '.toml', '.cfg', '.ini', '.conf', '.tf', '.hcl', '.json5',
                   '.properties', '.xml', '.gradle', '.env.example'}

# Test file indicators — findings here are LOWER priority
TEST_INDICATORS = {'test_', '_test.', 'tests/', 'test/', 'spec/', '_spec.',
                   'mock', 'fixture', 'conftest', '__tests__', 'testing/'}


def _is_test_file(filepath: str) -> bool:
    """Detect if a file is test/fixture code vs production."""
    lower = filepath.lower()
    return any(ind in lower for ind in TEST_INDICATORS)


def _context_risk_multiplier(finding_risk: str, filepath: str, line_content: str) -> tuple:
    """Adjust risk based on context. Returns (adjusted_risk, context_label)."""
    is_test = _is_test_file(filepath)
    lower_line = line_content.lower()

    # Test code = demote risk
    if is_test:
        demoted = {"CRITICAL": "MEDIUM", "HIGH": "LOW", "MEDIUM": "LOW", "LOW": "LOW"}
        return demoted[finding_risk], "test"

    # Comments / docstrings mentioning crypto aren't real usage
    if any(marker in lower_line for marker in ['todo', 'fixme', 'deprecated', 'example', 'sample']):
        return "LOW", "comment"

    # Config files with crypto settings = HIGH (these affect production)
    if filepath.endswith(('.yaml', '.yml', '.toml', '.cfg', '.ini', '.conf')):
        return finding_risk, "config"

    # Import statements = the library is USED, real risk
    if any(kw in lower_line for kw in ['import ', 'require(', 'from ', 'use ']):
        return finding_risk, "import"

    # Actual crypto operations = highest risk
    if any(kw in lower_line for kw in ['generate', 'sign(', 'verify(', 'encrypt', 'decrypt',
                                        'keygen', 'private_key', 'public_key', '.new(']):
        return finding_risk, "operation"

    return finding_risk, "reference"


def scan_codebase(path: str) -> Dict:
    """Full crypto inventory scan with CBOM output."""
    start = time.time()
    findings = []
    files_scanned = 0
    files_with_crypto = set()
    crypto_libs_found = set()

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SCAN_EXTENSIONS:
                continue

            fpath = os.path.join(root, fname)
            try:
                with open(fpath, 'r', errors='ignore') as f:
                    lines = f.readlines()
                files_scanned += 1
            except Exception:
                continue

            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*'):
                    continue

                # Strip inline comments before matching — avoids false positives
                # from comments like "pass  # uses AES-256-GCM now"
                code_part = stripped
                if '#' in code_part and not ext == '.yaml' and not ext == '.yml' and not ext == '.cfg' and not ext == '.ini' and not ext == '.conf':
                    code_part = code_part[:code_part.index('#')]
                elif '//' in code_part:
                    code_part = code_part[:code_part.index('//')]

                for algo_name, config in CRYPTO_PATTERNS.items():
                    for pattern in config['patterns']:
                        if re.search(pattern, code_part):
                            rel_path = os.path.relpath(fpath, path)
                            adjusted_risk, context = _context_risk_multiplier(
                                config['risk'], rel_path, stripped
                            )
                            findings.append(CryptoFinding(
                                file=rel_path,
                                line=i,
                                algorithm=algo_name,
                                category=config['category'],
                                risk=adjusted_risk,
                                raw_risk=config['risk'],
                                quantum_status=config['quantum_status'],
                                context=context,
                                usage=stripped[:120],
                                migration=config['migration'],
                                nist_ref=config['nist_ref'],
                            ))
                            files_with_crypto.add(rel_path)

                # Detect crypto library imports
                for lib_pattern, lib_name in [
                    (r'from cryptography', 'cryptography (Python)'),
                    (r'import crypto', 'crypto (Node.js)'),
                    (r'import javax\.crypto', 'javax.crypto (Java)'),
                    (r'from hashlib', 'hashlib (Python)'),
                    (r'import ssl', 'ssl (Python)'),
                    (r'from OpenSSL', 'pyOpenSSL'),
                    (r'require\("crypto"\)', 'crypto (Node.js)'),
                    (r'import "crypto/', 'crypto (Go)'),
                    (r'use openssl', 'OpenSSL (Rust)'),
                ]:
                    if re.search(lib_pattern, code_part):
                        crypto_libs_found.add(lib_name)

    elapsed_ms = int((time.time() - start) * 1000)

    # Risk scoring — production code weighted 3x vs test code
    prod_findings = [f for f in findings if f.context != 'test']
    test_findings = [f for f in findings if f.context == 'test']

    risk_counts = Counter(f.risk for f in findings)
    category_counts = Counter(f.category for f in findings)
    algo_counts = Counter(f.algorithm for f in findings)
    status_counts = Counter(f.quantum_status for f in findings)

    prod_risk = Counter(f.risk for f in prod_findings)
    test_risk = Counter(f.risk for f in test_findings)

    # Risk score weighted: production findings count 3x
    risk_score = min(100, (
        prod_risk.get('CRITICAL', 0) * 25 +
        prod_risk.get('HIGH', 0) * 10 +
        prod_risk.get('MEDIUM', 0) * 3 +
        prod_risk.get('LOW', 0) * 1 +
        test_risk.get('CRITICAL', 0) * 3 +  # test findings count much less
        test_risk.get('HIGH', 0) * 1
    ))

    # CBOM (Crypto Bill of Materials)
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "tools": [{"name": "PQC Posture Scanner", "version": "0.1.0"}],
            "component": {"name": os.path.basename(path), "type": "application"},
        },
        "cryptoProperties": {
            "algorithms": [
                {
                    "name": algo,
                    "occurrences": count,
                    "quantumSafe": algo_counts.get(algo, '') != 'BROKEN',
                }
                for algo, count in algo_counts.items()
            ],
            "libraries": list(crypto_libs_found),
        },
    }

    return {
        "scan_path": path,
        "files_scanned": files_scanned,
        "files_with_crypto": len(files_with_crypto),
        "total_findings": len(findings),
        "scan_time_ms": elapsed_ms,
        "risk_score": risk_score,
        "risk_level": "CRITICAL" if risk_score >= 50 else "HIGH" if risk_score >= 25 else "MEDIUM" if risk_score >= 10 else "LOW",
        "quantum_exposure": {
            "broken": status_counts.get("BROKEN", 0),
            "weakened": status_counts.get("WEAKENED", 0),
            "safe": status_counts.get("SAFE", 0),
        },
        "by_risk": dict(risk_counts),
        "by_category": dict(category_counts),
        "by_algorithm": dict(algo_counts),
        "crypto_libraries": sorted(crypto_libs_found),
        "findings": [asdict(f) for f in findings],
        "cbom": cbom,
        "migration_priority": [
            asdict(f) for f in sorted(
                findings,
                key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}[x.risk]
            )
        ][:20],
    }


def print_report(result: Dict):
    """Print human-readable posture report."""
    print(f"\n{'='*70}")
    print(f"  PQC POSTURE REPORT — {result['scan_path']}")
    print(f"{'='*70}\n")

    # Risk gauge
    score = result['risk_score']
    level = result['risk_level']
    bar_len = score // 2
    bar = '#' * bar_len + '-' * (50 - bar_len)
    print(f"  QUANTUM RISK SCORE: {score}/100 [{level}]")
    print(f"  [{bar}]")
    print()

    # Summary
    print(f"  Files scanned:       {result['files_scanned']}")
    print(f"  Files with crypto:   {result['files_with_crypto']}")
    print(f"  Total findings:      {result['total_findings']}")
    print(f"  Scan time:           {result['scan_time_ms']}ms")
    print()

    # Quantum exposure
    exp = result['quantum_exposure']
    print(f"  QUANTUM EXPOSURE:")
    print(f"    BROKEN (quantum defeats):    {exp['broken']}")
    print(f"    WEAKENED (quantum degrades): {exp['weakened']}")
    print(f"    SAFE (quantum-resistant):    {exp['safe']}")
    print()

    # By category
    print(f"  BY CATEGORY:")
    for cat, count in sorted(result['by_category'].items()):
        print(f"    {cat:20s} {count}")
    print()

    # Crypto libraries
    if result['crypto_libraries']:
        print(f"  CRYPTO LIBRARIES DETECTED:")
        for lib in result['crypto_libraries']:
            print(f"    - {lib}")
        print()

    # Context breakdown
    context_counts = Counter(f.get('context', '?') for f in result.get('findings', []))
    if context_counts:
        print(f"  BY CONTEXT:")
        for ctx, cnt in sorted(context_counts.items(), key=lambda x: -x[1]):
            label = {"test": "Test code (demoted)", "operation": "REAL crypto ops",
                     "import": "Library imports", "config": "Config files",
                     "reference": "Code references", "comment": "Comments/docs"}.get(ctx, ctx)
            print(f"    {label:30s} {cnt}")
        print()

    # Production-only findings (filter out test)
    prod_findings = [f for f in result.get('findings', []) if f.get('context') != 'test']
    test_findings = [f for f in result.get('findings', []) if f.get('context') == 'test']
    print(f"  PRODUCTION vs TEST:")
    print(f"    Production findings: {len(prod_findings)} (ACTION REQUIRED)")
    print(f"    Test-only findings:  {len(test_findings)} (lower priority)")
    print()

    # Top findings with migration paths (production only)
    print(f"  MIGRATION PRIORITY — PRODUCTION CODE (top 10):")
    print(f"  {'Risk':10s} {'Context':10s} {'Algorithm':18s} {'File':28s} {'Migration':25s}")
    print(f"  {'-'*95}")
    seen = set()
    count = 0
    for f in result['migration_priority']:
        if f.get('context') == 'test':
            continue
        key = f"{f['algorithm']}:{f['file']}"
        if key in seen:
            continue
        seen.add(key)
        ctx = f.get('context', '?')[:10]
        print(f"  {f['risk']:10s} {ctx:10s} {f['algorithm'][:18]:18s} {f['file'][:28]:28s} {f['migration'][:25]}")
        count += 1
        if count >= 10:
            break

    # CBOM summary
    print(f"\n  CBOM (Crypto Bill of Materials):")
    print(f"    Format: CycloneDX 1.6")
    print(f"    Algorithms found: {len(result['cbom']['cryptoProperties']['algorithms'])}")
    print(f"    Libraries found:  {len(result['cbom']['cryptoProperties']['libraries'])}")

    print(f"\n{'='*70}")
    if score >= 50:
        print(f"  VERDICT: CRITICAL quantum exposure. Migration urgently recommended.")
    elif score >= 25:
        print(f"  VERDICT: HIGH quantum exposure. Plan migration within 6 months.")
    elif score >= 10:
        print(f"  VERDICT: MODERATE exposure. Monitor and plan for PQC transition.")
    else:
        print(f"  VERDICT: LOW exposure. Continue monitoring.")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    import sys

    targets = [
        ("/root/openclaw", "OpenClaw Gateway"),
        ("/root/ai-factory", "AI Factory"),
        ("/root/quantum-mcp", "Quantum MCP"),
        ("/root/codeguard-mcp", "CodeGuard Pro"),
        ("/root/polymarket-mcp", "Polymarket MCP"),
    ]

    print("\n" + "="*70)
    print("  PQC POSTURE — FULL INFRASTRUCTURE AUDIT")
    print("  Scanning Miles's entire stack for quantum vulnerabilities")
    print("="*70)

    all_results = []
    for path, name in targets:
        if os.path.isdir(path):
            print(f"\n  Scanning {name}...")
            result = scan_codebase(path)
            all_results.append((name, result))
            print_report(result)

            # Save CBOM to file
            cbom_path = os.path.join(path, "CBOM.json")
            with open(cbom_path, 'w') as f:
                json.dump(result['cbom'], f, indent=2)

    # Summary across all projects
    print("\n" + "="*70)
    print("  INFRASTRUCTURE-WIDE SUMMARY")
    print("="*70 + "\n")

    total_findings = sum(r['total_findings'] for _, r in all_results)
    total_broken = sum(r['quantum_exposure']['broken'] for _, r in all_results)
    total_files = sum(r['files_scanned'] for _, r in all_results)

    print(f"  {'Project':25s} {'Risk Score':12s} {'Findings':10s} {'Broken':8s} {'Status'}")
    print(f"  {'-'*80}")
    for name, r in all_results:
        status = "MIGRATE NOW" if r['risk_score'] >= 50 else "PLAN" if r['risk_score'] >= 25 else "MONITOR" if r['risk_score'] >= 10 else "OK"
        print(f"  {name:25s} {r['risk_score']:>5}/100     {r['total_findings']:>5}      {r['quantum_exposure']['broken']:>4}    {status}")

    print(f"\n  TOTAL: {total_files} files, {total_findings} findings, {total_broken} quantum-broken")
    print(f"  CBOM files generated in each project directory")
