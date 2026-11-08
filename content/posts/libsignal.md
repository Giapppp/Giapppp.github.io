---
title: "A cryptographic vulnerability in Signal"
date: 2026-11-08
description: My writeup for the vulnerability I found in zkcredential, the anonymous credential library inside libsignal, which implements the Signal Protocol and other cryptographic components used by Signal.
categories: ["Writeup"]
tags: ["ZKP"]
language: "English"
---

Recently, I found and reported a cryptographic bug in `zkcredential`, the Rust crate that `libsignal` uses to build Signal's anonymous credentials. The credential public key publishes a different value for each credential length, and these values are correlated. With one honestly issued credential, we can change an attribute and fix the MAC ourselves, without asking the issuer. With only an existing presentation, we can change its ciphertext and commitments while keeping the original proof bytes. Here is my writeup for the bug and how it reaches Signal's call-link credentials.

Signal fixed the issue in [libsignal v0.101.0](https://github.com/signalapp/libsignal/releases/tag/v0.101.0) on August 14, 2026, and credits me in the August 2026 entry of their [security acknowledgements](https://signal.org/security/). Thanks to the Signal team for the response!

The construction below is for the vulnerable version. I reproduced the finding on commit [`88595dd6079572bbed404ea36a6f26237c808cbb`](https://github.com/signalapp/libsignal/tree/88595dd6079572bbed404ea36a6f26237c808cbb), and all code links in this post refer to that commit unless I say otherwise.

## Background

### Algebraic MAC credentials

`zkcredential` implements the algebraic MAC credentials from [Chase, Perrin and Zaverucha](https://eprint.iacr.org/2019/1416) (CPZ). In Signal's setting, the server both issues and verifies credentials, so it can check the MAC with its own secret key. The client only has to prove in zero knowledge that it holds a valid MAC over some hidden attributes.

The issuer's secret key is $(W,x_0,x_1,y_0,\dots,y_6)$, where $W$ is a point and the others are scalars. Attributes are points $M_0,\dots,M_{n-1}$. A credential is a tuple $(t,U,V)$ with

$$
V=W+(x_0+x_1t)U+\sum_j y_jM_j.
$$

We can see this in [`credential_core`](https://github.com/signalapp/libsignal/blob/88595dd6079572bbed404ea36a6f26237c808cbb/rust/zkcredential/src/credentials.rs#L82-L85):

```rust
let mut V = self.W + (self.x0 + self.x1 * t) * U;
for (yn, Mn) in self.y.iter().zip(M) {
    V += yn * Mn;
}
```

Note that $V$ is linear in every attribute. Keep this in mind, because the whole bug comes from it.

The public key contains $C_W$ and a point

$$
I=G_V-x_0G_{x_0}-x_1G_{x_1}-\sum_j y_jG_{y_j},
$$

where all the $G$'s are fixed public generators.

### Presenting a credential

To present a credential, the client picks a random scalar $z$ and commits to everything:

$$
\begin{aligned}
C_{x_0} &= zG_{x_0}+U, \newline
C_{x_1} &= zG_{x_1}+tU, \newline
C_V &= zG_V+V, \newline
C_{y_j} &= zG_{y_j}+M_j.
\end{aligned}
$$

Slot $0$ is a bit special: it holds an aggregate of the public attributes, which the verifier adds back by itself. The verifier uses its secret key to compute

$$
Z=C_V-W-x_0C_{x_0}-x_1C_{x_1}-\sum_j y_jC_{y_j}.
$$

All the $U$, $V$ and $M_j$ terms cancel, so an honest presentation gives $Z=zI$. The client proves this relation with POKSHO, Signal's Schnorr-style proof library, together with one relation for each attribute.

For an encrypted attribute, two points $M_1,M_2$ are encrypted under a key $(a_1,a_2)$:

$$
E_{A_1}=a_1M_1,
\qquad
E_{A_2}=a_2E_{A_1}+M_2.
$$

The proof has to link the ciphertext to the commitments. For the second point, it uses the relation

$$
C_{y_2}-E_{A_2}=zG_{y_2}-a_2E_{A_1},
$$

which we can see in the [statement construction](https://github.com/signalapp/libsignal/blob/88595dd6079572bbed404ea36a6f26237c808cbb/rust/zkcredential/src/presentation.rs#L278-L288):

```rust
// C_y2 - E_A2 = z * G_y2 + a2_uid * -E_A1
st.add(
    &format!("C_y{0}-E_A{0}", attr.second_point_index),
    &[
        ("z", &format!("G_y{}", attr.second_point_index)),
        (
            &format!("a2_{key_id}"),
            &format!("-E_A{}", attr.first_point_index),
        ),
    ],
);
```

## The bug: a ladder in the public key

In the CPZ paper, $I$ is computed once over the maximum number of attributes. `zkcredential` does something different, and the [doc comment](https://github.com/signalapp/libsignal/blob/88595dd6079572bbed404ea36a6f26237c808cbb/rust/zkcredential/src/credentials.rs#L96-L102) explains why:

```rust
/// The value of `I` depends on the total number of attributes used.
///
/// In the original paper, `I` is computed over the maximum number of attributes only, but that
/// makes presentation proofs larger for credentials that don't use that many attributes. Here
/// we provide `I_n` for any supported number of attributes. We do skip `I_0`, since that would
/// be a credential with only public attributes, in which case you could just use a classic MAC.
I: [RistrettoPoint; NUM_SUPPORTED_ATTRS - 1],
```

The array is built [cumulatively](https://github.com/signalapp/libsignal/blob/88595dd6079572bbed404ea36a6f26237c808cbb/rust/zkcredential/src/credentials.rs#L115-L130):

```rust
let C_W = private_key.W + (private_key.wprime * system.G_wprime);
let mut I_i = system.G_V - (private_key.x0 * system.G_x0) - (private_key.x1 * system.G_x1);

let mut y_and_G_y_iter = private_key.y.iter().zip(system.G_y);
let (y0, G_y0) = y_and_G_y_iter.next().expect("correct number of parameters");
I_i -= y0 * G_y0;

let I = [(); NUM_SUPPORTED_ATTRS - 1].map(|_| {
    let (yn, G_yn) = y_and_G_y_iter.next().expect("correct number of parameters");
    I_i -= yn * G_yn;
    I_i
});
```

Let $I_n$ be the entry for a credential with $n$ attribute points, as in the doc comment. Then

$$
I_n=G_V-x_0G_{x_0}-x_1G_{x_1}-\sum_{j<n}y_jG_{y_j}.
$$

Each entry subtracts exactly one more term than the previous one, so two adjacent entries give us

$$
I_i-I_{i+1}=y_iG_{y_i}.
$$

The serialized array holds $I_2$ to $I_7$, so we get $y_iG_{y_i}$ for $i=2,\dots,6$. We still can't recover $y_i$, since that is a discrete log. But we don't need it! Look at the MAC formula again: $y_iG_{y_i}$ is exactly how much $V$ changes when $M_i$ changes by $G_{y_i}$. The public key hands us the MAC contribution of a known point, and the next section shows two ways to use it.

## Two attacks

### Forging a related credential

Take one honestly issued credential $(t,U,V)$ over attributes $M_0,\dots,M_{n-1}$, and choose an index $i$ in $\lbrace 2,\dots,6\rbrace$. Choose any nonzero scalar $k$ and set

$$
\begin{aligned}
M_i' &= M_i+kG_{y_i}, \newline
V' &= V+k(I_i-I_{i+1}).
\end{aligned}
$$

Substituting $I_i-I_{i+1}=y_iG_{y_i}$, we have

$$
\begin{aligned}
V'
&= W+(x_0+x_1t)U+\sum_j y_jM_j+ky_iG_{y_i} \newline
&= W+(x_0+x_1t)U+\sum_{j\neq i}y_jM_j+y_i(M_i+kG_{y_i}) \newline
&= W+(x_0+x_1t)U+\sum_{j\neq i}y_jM_j+y_iM_i'.
\end{aligned}
$$

So $(t,U,V')$ is a valid credential for the modified attributes. We didn't talk to the issuer, and we didn't need any secret. After this, the normal presentation code works without changes, because the client only needs $t$, $U$, $V'$ and the attributes to make a fresh proof.

Which indices can we change? Slot $0$ is the public attribute aggregate, which the verifier recomputes, and slot $1$ never appears alone in a difference ($I_2$ already subtracts both $y_0$ and $y_1$). So the malleable indices are $2$ to $6$. A two-point encrypted attribute stored at $M_1,M_2$ therefore has a malleable second point.

### Reusing a proof without the credential

The second attack doesn't even need a credential. We only need an existing presentation, its ciphertext, and the public parameters.

Suppose the presentation contains an encrypted attribute with its second point at index $2$. Choose a nonzero $k$ and set

$$
\Delta=kG_{y_2},
\qquad
L=k(I_2-I_3).
$$

Now change three points and leave the POKSHO proof alone:

$$
\begin{aligned}
E_{A_2}' &= E_{A_2}+\Delta, \newline
C_{y_2}' &= C_{y_2}+\Delta, \newline
C_V' &= C_V+L.
\end{aligned}
$$

The proof statement only sees the difference between $C_{y_2}$ and $E_{A_2}$, and this difference doesn't change:

$$
C_{y_2}'-E_{A_2}'=C_{y_2}-E_{A_2}.
$$

The verifier also derives $Z$ from $C_V$ and the $C_y$ values. We have

$$
\begin{aligned}
Z'
&= Z+L-y_2\Delta \newline
&= Z+ky_2G_{y_2}-ky_2G_{y_2} \newline
&= Z.
\end{aligned}
$$

On the verifier side, these two derived values are [exactly what gets passed to POKSHO](https://github.com/signalapp/libsignal/blob/88595dd6079572bbed404ea36a6f26237c808cbb/rust/zkcredential/src/presentation.rs#L660-L700):

```rust
let mut Z = C_V - W - x0 * C_x0 - x1 * C_x1;
for (yn, C_yn) in y.iter().zip(C_y.iter()) {
    Z -= yn * C_yn;
}
// ...
point_args.add(
    format!("C_y{second_point_index}-E_A{second_point_index}"),
    C_y[second_point_index] - self.core.attr_points[second_point_index],
);
// ...
point_args.add("Z", Z);
```

We didn't touch any of the other points in the statement ($C_{x_0}$, $C_{x_1}$, $C_{y_1}$, $E_{A_1}$, $I_n$, ...). So POKSHO receives the identical statement, computes the identical Fiat-Shamir challenge, and the original 224-byte proof still verifies. Also, $E_{A_2}'$ is an encryption of $M_2+\Delta$, so the result is a valid presentation for the related credential from the previous section. We got it without the credential and without proving anything.

If you read [my Fiat-Shamir post](https://blog.zksecurity.xyz/posts/fiat-shamir/), this is the `libsignal` example from that post. There, I looked at it from the transcript side: the verifier gives POKSHO the difference $C_{y,2}-E_{A,2}$ and the derived $Z$, and the [`verify_proof` call](https://github.com/signalapp/libsignal/blob/88595dd6079572bbed404ea36a6f26237c808cbb/rust/zkcredential/src/presentation.rs#L700-L706) passes only `self.core.authenticated_message`, without the raw presentation commitments. Any change that keeps these combinations the same keeps the challenge the same. The shift in that post, with a scalar $a$, is exactly our $\Delta$ and $L$ with $k=a$. (Here I use $k$, because $a_1,a_2$ already name the encryption key, and I write $C_{y_2}$ for $C_{y,2}$.)

In that post, the ladder only appears in a footnote, but it is the other half of the finding. The Fiat-Shamir gap alone isn't enough: if we move $C_{y_2}$ and $E_{A_2}$ by $\Delta$, then $Z$ changes by $-y_2\Delta$, and we can only cancel this through $C_V$ if we know the point $y_2\Delta$. That point is exactly what $I_2-I_3$ leaks. The same footnote also mentions the credential forgery from the previous section. So the unbound transcript, the leaked MAC term and the forgery are all parts of one finding.

## Impact on Signal

`zkcredential` is used by several credentials in `zkgroup`, and whether a credential is reached depends on where its points are. After my report, Signal ran an internal audit of every credential and shared the results with me. The table below puts the point layouts together with their results:

| Credential | Point layout | Result |
| --- | --- | --- |
| [`CallLinkAuthCredential`](https://github.com/signalapp/libsignal/blob/88595dd6079572bbed404ea36a6f26237c808cbb/rust/zkgroup/src/api/call_links/auth_credential.rs#L41-L44) | Public aggregate at $M_0$; encrypted ACI at $M_1,M_2$ | Both attacks reach $M_2$, so the encrypted user ID can be changed to an invalid value |
| [`CreateCallLinkCredential`](https://github.com/signalapp/libsignal/blob/88595dd6079572bbed404ea36a6f26237c808cbb/rust/zkgroup/src/api/call_links/create_credential.rs#L106-L110) | Same as above, plus a revealed room point at $M_3$ | Forgery reaches $M_2,M_3$; proof reuse reaches $M_2$. Signal no longer uses the encrypted user ID, so there is no impact |
| [`AuthCredentialWithPniZkc`](https://github.com/signalapp/libsignal/blob/88595dd6079572bbed404ea36a6f26237c808cbb/rust/zkgroup/src/api/auth/auth_credential_with_pni/zkc.rs#L89-L93) (group auth) | Public aggregate at $M_0$; encrypted ACI at $M_1,M_2$; encrypted PNI at $M_3,M_4$ | Reached in structure, but a changed credential doesn't match any user ID already in the group, so it can't do anything useful there |
| [`BackupAuthCredential`](https://github.com/signalapp/libsignal/blob/88595dd6079572bbed404ea36a6f26237c808cbb/rust/zkgroup/src/api/backups/auth_credential.rs#L174-L179), [`AvatarUploadCredential`](https://github.com/signalapp/libsignal/blob/88595dd6079572bbed404ea36a6f26237c808cbb/rust/zkgroup/src/api/avatars/avatar_upload_credential.rs#L428-L431) | Points stop at $M_1$ | Not reached |

The other credentials are outside `zkcredential`. `ProfileKeyCredential` and `ReceiptCredential` were never ported to it, and the endorsements (`GroupSendEndorsement` and `DonationPermit`) use a different system. None of them are affected. The group case also depends on this: because profile key credentials don't use `zkcredential`, bad profile data can't get into a group, and a changed auth credential has no existing member to match.

The Signal apps use the call-link presentation. At the time of my report, the official [Android v8.20.5](https://github.com/signalapp/Signal-Android/releases/tag/v8.20.5), [Desktop v8.20.0](https://github.com/signalapp/Signal-Desktop/releases/tag/v8.20.0) and [iOS 8.22.0.1774](https://github.com/signalapp/Signal-iOS/releases/tag/8.22.0.1774) releases all shipped libsignal 0.97.3 and created this presentation when joining a call link.

The attack doesn't allow impersonation. Changing $M_2$ while $M_1$ stays the same doesn't give us a chosen victim ACI. In fact, [UID decryption](https://github.com/signalapp/libsignal/blob/v0.97.3/rust/zkgroup/src/crypto/uid_encryption.rs#L70-L108) decodes $M_2$, recomputes $M_1$ from the result and compares, so a modified ciphertext doesn't decrypt to any real user. For `CallLinkAuthCredential`, we get a valid presentation with an invalid user ID that nobody issued. According to Signal, this doesn't let a malicious user receive audio or video from the end-to-end encrypted call, and the attacker still needs to know the call link. Admin passkeys, approval and credential expiration are not bypassed either.

The practical impact is limited. Still, at the cryptographic layer, the credential is no longer unforgeable for related messages, and that is the property everything else is built on.

## Disclosure and fix

Even though the impact is limited, Signal told me they had started working on improvements for `CallLinkAuthCredential`. The fix is in commit [`03b08494`](https://github.com/signalapp/libsignal/commit/03b08494feb85bee7e1b2755a2a5ca88596f773b), released as [v0.101.0](https://github.com/signalapp/libsignal/releases/tag/v0.101.0).

The fix has two parts, one for each failure. Binding the raw values into the transcript alone would stop proof reuse, but a holder could still forge a credential and make a fresh proof. Blinding the ladder alone would stop both attacks in practice, but the transcript would still not cover the points the application uses, so a later change in the algebra could open the same gap again. Signal changed both.

First, the ladder is blinded. Instead of deriving new keys for every length (which is what my suggested patch did), the fix only makes the slot $0$ coefficient depend on the number of attributes, as we can see in [`y0`](https://github.com/signalapp/libsignal/blob/03b08494feb85bee7e1b2755a2a5ca88596f773b/rust/zkcredential/src/credentials.rs#L105-L131):

```rust
let mut sho =
    ShoHmacSha256::new(b"Signal_ZKCredential_SlotZeroBlinding_20260805");
sho.absorb_and_ratchet(&self.y[0].to_bytes());
sho.absorb_and_ratchet(&(total_attr_count as u64).to_be_bytes());
sho.get_scalar()
```

Every $I_n$ contains a slot $0$ term, so with $y_0^{(n)}$ derived per length, adjacent entries now give

$$
I_i-I_{i+1}=y_iG_{y_i}+\left(y_0^{(i)}-y_0^{(i+1)}\right)G_{y_0}.
$$

The second term is unknown, so the difference is no longer a usable MAC contribution. In the Fiat-Shamir post, I wrote that the attribute MAC keys must be separated by attribute count; Signal's fix shows that it is enough to separate one of them. I like this fix: changing a single coefficient is enough, because every entry of the ladder shares it. (Two-attribute credentials keep the original $y_0$ as a migration aid, but $y_0^{(3)}$ is still different from it.)

Second, the presentation now binds the raw values. In the new standard mode, the POKSHO message contains the length-prefixed application message, the encryption public keys, and for every encrypted attribute, both $C_{y_2}$ and $E_{A_2}$ (see [`prepare_full_authenticated_message`](https://github.com/signalapp/libsignal/blob/03b08494feb85bee7e1b2755a2a5ca88596f773b/rust/zkcredential/src/presentation.rs#L374-L415)). This is smaller than absorbing the complete presentation commitments, as I suggested in the Fiat-Shamir post, but it covers the gap: $C_{x_0}$, $C_{x_1}$, the first point of each attribute and $I_n$ (which depends on the attribute count) are already in the statement, and with $C_{y_2}$ also fixed, $Z$ fixes $C_V$.

Since the same key bytes now have a new meaning, the change is versioned. Key pairs carry a `StandardMode` or `LegacyMode` marker, and the call-link credentials record which version of the server params issued them, with a temporary `verify_against_appropriate_params` helper so the server can accept both during migration. `LegacyMode` keeps the old behavior for compatibility, so the fix applies to keys in `StandardMode`. On the [current `main`](https://github.com/signalapp/libsignal/blob/85094258/rust/zkgroup/src/api/generic_server_params.rs), new call-link, backup and avatar credentials use the standard params, while `AuthCredentialWithPniZkc` stays in legacy mode, which matches Signal's assessment above that a changed group auth credential can't do anything useful.

## Lessons

I want to remember two things from this bug.

First, a small optimization can leave the paper's security proof behind. Publishing $I_n$ for every length only looks like a way to make proofs smaller. But every extra public value is a combination of secret key material, and two of them together cancel everything except one MAC term. Writing out what each public value contains lets us see the problem right away.

Second, the Fiat-Shamir transcript should contain what the verifier receives, not only what it derives. Hashing $C_{y_2}-E_{A_2}$ and $Z$ is enough for POKSHO to check its equations, but the application uses $C_{y_2}$, $E_{A_2}$ and $C_V$, and those were free to move. Here, the gap only became exploitable because of the ladder, which is a good reminder to look at the algebra and the transcript together.

I'm happy to help keep Signal safe. Thanks for reading!
