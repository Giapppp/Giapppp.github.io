---
author: "Giap"
title: "Whitebox Cryptography - Short Introduction"
date: "2025-07-17"
categories: ["Learning"]
tags: ["Whitebox"]
---

## Introduction

Introduced by Chow et al. in 2002 [1], **white-box cryptography** focuses on designing and analyzing cryptographic implementations (typically block ciphers) intended to remain secure even when an adversary has full access to the execution environment. The goal is to ensure that, despite this complete visibility, sensitive information such as secret keys cannot be extracted, while preserving the cipher’s functionality (e.g., encryption and decryption).

White-box cryptography stands in contrast to **black-box cryptography**, where the adversary can neither observe nor manipulate the internal workings of the cipher. Importantly, the cryptographic algorithm must function identically in both the black-box and white-box settings; only the attacker’s capabilities differ.

Depending on the environment in which the implementation is deployed, different security threats arise:

- **White-box cryptography**: Key extraction, code decomposition, and related attacks.
- **Black-box cryptography**: Key recovery, distinguishing attacks, and others.

There is a competition about whitebox cryptography name [WhibOx](https://whibox.io/), which invited white-box designers both from academia and industry to submit their implementation in the form of (possibly obfuscated) C code. At the same time, everyone could attempt to attack these programs and recover the embedded secret key. If you are interested in whitebox cryptography then give it a look !

> If you are a CTF enjoyer, I suggest trying Hvítur Kassi 1/2 in FCSC 2019. You can find the source code at https://hackropole.fr/en/fcsc2019/.

## SPNbox

### Introduce 

$SPNbox$ was introduced in AsiaCrypt 2016 [2], which is based on the substitution-permutation network cipher but with some changes to fit in whitebox purpose like:
- Key-dependent S-box
- Round-dependent constant in each round
- Using circulant/hadamard matrix for diffusion

These changes make $SPNbox$ has efficient constant-time running but still safety.

### Detail

We will talk about $SPNbox-n_{in}$, where $n_{in} = 8$, block length $n = 128$ and $128$-bit master key. For bigger $n_{in}$ you can check in [2].

- **State.** The state of $SPNbox-n_in$ is organised as a vector of $t = n/n_in$ elements of $n_{in}$ bits each: $$X = \lbrace X_0,\dots,X_{t-1} \rbrace.$$ Each of the $n_{in}$-bit elements $X_i$ can in turn be represented by a vector of $l = n_{in}/8$ bytes: $X_i = \lbrace X_{i,l-1},...,X_{i,0} \rbrace.$

- **Key Schedule.** The $k$-bit master key is expanded to $R_{n_{in} + 1}$ round keys $k_0,\dots,k_{R_{n_{in}}}$ of $n_{in}$ bits using any generic key derivation function (KDF): $$(k_0,\dots,k_{R_{n_{in}}}) = KDF(k, n_{in} \times (R_{n_{in}} + 1)).$$ For example, one can use SHAKE extendable output function for KDF, which is based on SHA-3 hash.

- **Round Transformation.** The encryption of a plaintext $X^0$ to a ciphertext $X^R$ is accomplished by applying $R$ rounds of the following round transformation to the plaintext: $$X^R = (\bigcirc_{r=1}^{10}(\sigma^r \circ \theta \circ \gamma))(X^0).$$ We define each layer below:

**1. The nonlinear layer $\gamma$.**
- $\gamma$ is a nonlinear substitution layer, in which $t$ key-dependent identical bijective $n_{in}$-bit S-boxes are applied to the state: $$\begin{aligned}\gamma: GF(2^{n_{in}})^t &\to GF(2^{n_{in}})^t \\ (X_0,\dots,X_{t-1}) &\mapsto (S_{n_{in}}(X_0),\dots,S_{n_{in}}(X_{t-1}))\end{aligned}.$$ 
- The key-dependent $n_{in}$-bit bijective S-boxes $S_{n_{in}}$ are small SPN-type block ciphers themselves. They are based on the round transformation of the AES and consist of $R_{n_{in}}$ rounds operating on a state $x=\lbrace x_0, \dots, x_{l-1} \rbrace$ of $l = n_{in}/8$ bytes: $$\begin{aligned} S_{n_{in}}: GF(2^8)^l &\to GF(2^8)^l \newline x &\mapsto (\bigcirc_{i=1}^{R_{n_{in}}}({AK}^i \circ MC_{n_{in}} \circ SB))({AK}^0(x)).\end{aligned}$$ Here $SB$ denotes the application of the AES S-box to each byte of the state, $AK^i$ is defined as the addition of the round key $k_i$ by XOR (expanded by the key schedule). $MC_{n_{in}}$ implements a maximum distance separable (MDS) diffusion layer on all $l$ bytes of the state and based on the AES MixColumn operation. For $n_{in} = 8$, $MC_{n_{in}}$ is the identity mapping.

**2. The linear layer $\theta$.**
- $\theta$ is a linear diffusion layer that applies a $t \times t$ MDS matrix to the state: $$\begin{aligned} \theta :GF(2^{n_{in}})^t &\to GF(2^{n_{in}})^t \newline (X_0,\dots,X_{t-1}) &\mapsto (X_0,\dots,X_{t-1}) \times M_{n_{in}} \end{aligned}$$.
- When $n_{in} = 8$, we have $$M_8=had(0x08, 0x16, 0x8a, 0x01, 0x70, 0x8d, 0x24, 0x76, 0xa8, 0x91, 0xad, 0x48, 0x05, 0xb5, 0xaf, 0xf8)$$ where $had(a_0,\dots,a_{t-1})$ is the $t \times t$ Hadamard matrix $A$ with coefficients $A_{i,j}=a_{i\oplus j}$ with $t$ a power of two.

**3. The Affine layer $\sigma^r$.**
- $\sigma^r$ is an affine layer that adds round-dependent constants to the state: $$\begin{aligned} \sigma^r : GF(2^{n_{in}})^t &\to GF(2^{n_{in}})^t \newline (X_0,\dots,X_{t-1}) &\mapsto (X_0 \oplus C_0^r,\dots,X_{t-1} \oplus C_{t-1}^r)\end{aligned}$$ with $C_i^r=(r-1) \times t + i + 1$ for $0 \le i \le t - 1$.

When $n_{in} = 8$ we have $R_8 = 64$.

## Implementation

You can find the implementation at https://github.com/Giapppp/whitebox-cryptography. There are some notifications about this repo:
- Usually White-box implementation only have one functionality (encryption/decryption), but my implementation can do both of them because I just want to check my implementation work perfectly or not. So if you want to make it looks like real world application, remove one option and it will be okay.
- This implementation is just for learning purpose.

## Conclusion

In this post, we explored white-box cryptography and introduced $SPNbox$ — a space-hard block cipher designed to run efficiently in constant time while providing strong security guarantees. Thanks to these properties, $SPNbox$ is a promising candidate for real-world applications such as digital rights management (DRM), host card emulation in cloud-based mobile payments (HCE), and memory-leakage resilient software.

## Resources

[1]. https://crypto.stanford.edu/DRM2002/whitebox.pdf

[2]. https://www.iacr.org/archive/asiacrypt2016/10031190/10031190.pdf