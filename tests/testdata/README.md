# NIST FIPS 203 ACVP Reference Test Vectors

This directory contains official Known Answer Test (KAT) vectors published by NIST as part of the **Automated Cryptographic Validation Protocol (ACVP)** for standard **NIST FIPS 203** (ML-KEM).

## Upstream Provenance

- **Repository**: [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server)
- **Pinned Git Commit**: `f38183487eebff2952da0e5a3441371218acfe3f`
- **Datasets**:
  - `ML-KEM-keyGen-FIPS203`
  - `ML-KEM-encapDecap-FIPS203`

## Test Vector Inventory

| Operation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 | Total |
| :--- | :---: | :---: | :---: | :---: |
| **KeyGen (AFT)** | 25 | 25 | 25 | **75** |
| **Encap (AFT)** | 25 | 25 | 25 | **75** |
| **Decap (VAL)** | 10 | 10 | 10 | **30** |
| **Total** | 60 | 60 | 60 | **180** |

## Cryptographic Integrity Checksums (SHA-256)

These checksums verify that the test vectors and expected results have not been altered:

| File Path | SHA-256 Hash |
| :--- | :--- |
| `ML-KEM-keyGen-FIPS203/prompt.json.gz` | `1daed3c5730a9cf22ab85858173004e66510339352b600abcd969fc2508f06bc` |
| `ML-KEM-keyGen-FIPS203/expectedResults.json.gz` | `a02dcd5d9112588bd9c309d985bf22a2c4c63bb8393d1c17f6cdb14ed7d83bd9` |
| `ML-KEM-encapDecap-FIPS203/prompt.json.gz` | `bf6fd5d18e072342321917f08645bfc6d43bc13f4363634b2d1dd8263f649803` |
| `ML-KEM-encapDecap-FIPS203/expectedResults.json.gz` | `8078b3ede531e54f71aed25e6af1334c8640df54934d3af69433387ae2074b68` |
