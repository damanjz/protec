# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
(Security tab → Report a vulnerability) rather than public issues.

## Scope and design

- Crypto: Argon2id (KDF) + XChaCha20-Poly1305 (AEAD).
- Envelope encryption with a versioned, authenticated on-disk format.
- No network access of any kind. The vault file is the only persistence.

This software has **not** undergone a third-party audit. Use at your own risk
until it reaches a reviewed release.
