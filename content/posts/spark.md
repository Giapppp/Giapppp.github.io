---
title: "I found a cryptographic bug in Firo"
date: 2026-09-08
description: My writeup for the vulnerability I found in Spark protocol, which is used by Firo
categories: ["Writeup"]
tags: ["ZKP"]
---

Recently, I independently found and reported a cryptographic bug in Spark, the private transaction protocol used by Firo. With one owned coin, we can construct a spend that counts the coin twice, creates new private coins, and leaves the original coin spendable. Here is my writeup for the bug and how it affects a Spark transaction.

I wasn't the first person to report it. In their [August 13 announcement](https://firo.org/2026/08/13/spark-vulnerability-mitigated.html), Firo credits Carter Annandale with the original disclosure on August 1, and records my independent report on August 6. They temporarily disabled multi-input Spark spends while preparing a permanent fix.

The construction below is for the vulnerable version. I reproduced the finding on commit [`98f7d13311b2655798f47e005f5658651b137dcf`](https://github.com/firoorg/firo/tree/98f7d13311b2655798f47e005f5658651b137dcf), and all code links in this post refer to that commit.

## The proof used in Spark

[Spark](https://eprint.iacr.org/2021/1173) builds on the [Lelantus](https://eprint.iacr.org/2019/373) protocol. For this bug, we only need to look at the modified Chaum-Pedersen proving system in Appendix A of the Spark paper. It combines the authorization of several inputs into one proof.

For each input, we want to prove knowledge of $x_i,y_i,z_i$ satisfying

$$
\begin{aligned}
S_i &= x_iF+y_iG+z_iH, \newline
U &= x_iT_i+y_iG.
\end{aligned}
$$

Here, $T_i$ is the linking tag. A valid tag lets the network recognize another spend of the same coin without revealing which coin in the cover set we are spending. The authorization proof needs to bind this tag to the witness for $S_i$; otherwise, checking whether a tag has been used before won't stop a double spend.

The modified protocol checks two aggregate equations for all inputs. In the implementation, the verifier combines those two equations into one multiexponentiation with a random weight $w$.

Combining equations like this saves verification work, but we still need to prove the relation for each input. In this construction, we can split the responses between two invalid tags so that both aggregate equations pass. We only need $l=2$.

## Constructing the forged proof

Using the notation from Section 2.3, we start with a statement whose witness we know:

$$
\begin{aligned}
S &= xF+yG+zH, \newline
P &= U-yG,
\end{aligned}
$$

where $x,y,z\in\mathbb{F}$; $F,G,H,U,P\in\mathbb{G}$; and $P\neq\mathcal{O}$. Let $S_0=S_1=S$.

Choose two different nonzero values $\alpha,\beta\in\mathbb{F}$ such that $\alpha x\neq1$ and $\beta x\neq1$, then set

$$
T_0=\alpha P,
\qquad
T_1=\beta P.
$$

Both tags are invalid for the known witness because

$$
xT_0+yG=\alpha xP+yG\neq P+yG=U,
$$

and the same is true for $T_1$.

To make the two invalid tags work together, we solve for two scalars:

$$
\begin{aligned}
X_0 &= \frac{1-\beta x}{\alpha-\beta}, \newline
X_1 &= \frac{\alpha x-1}{\alpha-\beta}.
\end{aligned}
$$

These values give us exactly the two relations we need:

$$
X_0+X_1=x,
\qquad
X_0T_0+X_1T_1=P.
$$

Choose random $r_0,r_1,b_0,b_1,v\in\mathbb{F}$ and calculate

$$
\begin{aligned}
A_1 &= (r_0+r_1)F+(b_0+b_1)G+vH, \newline
A_{2,0} &= r_0T_0+b_0G, \newline
A_{2,1} &= r_1T_1+b_1G.
\end{aligned}
$$

These commitments are fixed before the challenge. After getting the challenge $c$, for both the interactive and non-interactive case, construct the remaining values

$$
\begin{aligned}
t_{1,0} &= r_0+(c+c^2)X_0, \newline
t_{1,1} &= r_1+(c+c^2)X_1, \newline
t_2 &= b_0+b_1+(c+c^2)y, \newline
t_3 &= v+(c+c^2)z.
\end{aligned}
$$

Now we can substitute these responses into the verifier equations.

The first equation is:

$$
A_1+\sum_{i=0}^{l-1}c^{i+1}S_i=\sum_{i=0}^{l-1}t_{1,i}F+t_2G+t_3H
$$

We have

$$
\begin{aligned}
RHS
&=(r_0+r_1)F+(c+c^2)(X_0+X_1)F \newline
&\quad +(b_0+b_1)G+(c+c^2)yG+vH+(c+c^2)zH \newline
&=A_1+(c+c^2)(xF+yG+zH) \newline
&=A_1+(c+c^2)S \newline
&=A_1+cS_0+c^2S_1 \newline
&=LHS.
\end{aligned}
$$

The second equation is:

$$
\sum_{i=0}^{l-1}(A_{2,i}+c^{i+1}U)=\sum_{i=0}^{l-1}t_{1,i}T_i+t_2G
$$

We have

$$
\begin{aligned}
RHS
&=(r_0+(c+c^2)X_0)T_0+(r_1+(c+c^2)X_1)T_1 \newline
&\quad +(b_0+b_1+(c+c^2)y)G \newline
&=A_{2,0}+A_{2,1}+(c+c^2)(X_0T_0+X_1T_1+yG) \newline
&=A_{2,0}+A_{2,1}+(c+c^2)(P+yG) \newline
&=A_{2,0}+A_{2,1}+(c+c^2)U \newline
&=LHS.
\end{aligned}
$$

Both equations pass! Neither tag is valid for our witness, but the verifier accepts them together.

In the honest prover, each response has the form $t_{1,i}=r_i+c^{i+1}x_i$, but the verifier never checks that response $i$ contains only its assigned power of $c$. In the forged proof, both responses contain shares of both $c$ and $c^2$. The first equation only sees $\sum_i t_{1,i}$, while the second equation only sees $\sum_i t_{1,i}T_i$. The random $w$ in production does not help because both equations above are already satisfied separately.

## From the equations to the code

We can see the same response structure in [`Chaum::prove`](https://github.com/firoorg/firo/blob/98f7d13311b2655798f47e005f5658651b137dcf/src/libspark/chaum.cpp#L69-L82):

```cpp
Scalar c = challenge(mu, S, T, proof.A1, proof.A2);

proof.t1.resize(n);
proof.t3 = t;
Scalar c_power(c);
for (std::size_t i = 0; i < n; i++) {
    if (c_power.isZero()) {
        throw std::invalid_argument("Unexpected challenge!");
    }
    proof.t1[i] = r[i] + c_power*x[i];
    proof.t2 += s[i] + c_power*y[i];
    proof.t3 += c_power*z[i];
    c_power *= c;
}
```

The prover calculates $c$ before constructing `t1`, so a modified prover can use the responses above. The commitments are already fixed, and we don't need to predict the challenge or search for a particular hash output.

On the verifier side, [all `t1` values are added into the coefficient of $F$](https://github.com/firoorg/firo/blob/98f7d13311b2655798f47e005f5658651b137dcf/src/libspark/chaum.cpp#L129-L135). The other equation [multiplies each response by its supplied tag](https://github.com/firoorg/firo/blob/98f7d13311b2655798f47e005f5658651b137dcf/src/libspark/chaum.cpp#L172-L181). These are the two sums we just made satisfy the checks.

So the implementation accepts the forged authorization proof. Now we need to see whether we can put it inside a complete Spark spend.

### Counting one coin twice

A Spark spend contains logical inputs inside its payload. Each has a statement `S1`, a value commitment `C1`, a linking tag, and a Grootle membership proof.

We can duplicate the owned coin's cover-set ID, `S1`, `C1`, and valid Grootle proof, then provide $T_0$ and $T_1$ as the two linking tags. The [consumed-coin checks](https://github.com/firoorg/firo/blob/98f7d13311b2655798f47e005f5658651b137dcf/src/libspark/spend_transaction.cpp#L279-L286) compare vector sizes, so they accept two entries. Later, the verifier [puts both entries into the Grootle batch](https://github.com/firoorg/firo/blob/98f7d13311b2655798f47e005f5658651b137dcf/src/libspark/spend_transaction.cpp#L389-L413) without checking whether they refer to the same coin. The membership proof still proves membership for each copy.

After accepting our Chaum-Pedersen proof, the verifier adds every input commitment into the balance statement. The two checks are next to each other in [`SpendTransaction::verify`](https://github.com/firoorg/firo/blob/98f7d13311b2655798f47e005f5658651b137dcf/src/libspark/spend_transaction.cpp#L322-L338):

```cpp
// Verify the authorizing Chaum-Pedersen proof
Chaum chaum(
    tx.params->get_F(),
    tx.params->get_G(),
    tx.params->get_H(),
    tx.params->get_U()
);
if (!chaum.verify(mu, tx.S1, tx.T, tx.chaum_proof)) {
    return false;
}

// Verify the balance proof
Schnorr schnorr(tx.params->get_H());
GroupElement balance_statement;
for (std::size_t u = 0; u < w; u++) {
    balance_statement += tx.C1[u];
}
```

Because `C1` appears twice, the balance proof counts its value twice. If our coin has value $v$ and the transaction fee is $f$, we can create a private output with value $2v-f$, while a normal spend would create $v-f$.

There is also a [duplicate-input check in transaction validation](https://github.com/firoorg/firo/blob/98f7d13311b2655798f47e005f5658651b137dcf/src/validation.cpp#L621-L641), but it checks the outer input scripts or outpoints. A Spark spend has [one wrapper input](https://github.com/firoorg/firo/blob/98f7d13311b2655798f47e005f5658651b137dcf/src/spark/state.cpp#L622-L627), with our two logical inputs inside the payload. That outer check cannot see the duplication.

### The original coin remains spendable

Firo does check for linking tags that have already been used. We can see this in [`CheckLTag`](https://github.com/firoorg/firo/blob/98f7d13311b2655798f47e005f5658651b137dcf/src/spark/state.cpp#L26-L45):

```cpp
static bool CheckLTag(
        CValidationState &state,
        CSparkTxInfo *sparkTxInfo,
        const GroupElement& lTag,
        int nHeight,
        bool fConnectTip) {
    // check for Spark transaction in this block as well
    if (sparkTxInfo &&
        !sparkTxInfo->fInfoIsComplete &&
            sparkTxInfo->spentLTags.find(lTag) != sparkTxInfo->spentLTags.end())
        return state.DoS(0, error("CTransaction::CheckTransaction() : two or more spends with same linking tag in the same block"));

    // check for used linking tags in state
    if (sparkState.IsUsedLTag(lTag)) {
        if (nHeight == INT_MAX || fConnectTip) {
            return state.DoS(0, error("CTransaction::CheckTransaction() : The Spark coin has been used"));
        }
    }
    return true;
}
```

However, it compares the exact points supplied in the transaction. We chose $\alpha\neq\beta$ and $P\neq\mathcal{O}$, so $T_0$ and $T_1$ are different points. By choosing fresh tags, we can pass the checks against earlier spends as well.

After verification, the state [checks and records the supplied tags](https://github.com/firoorg/firo/blob/98f7d13311b2655798f47e005f5658651b137dcf/src/spark/state.cpp#L810-L843). The coin's genuine linking tag never appears in our transaction, so it remains unused.

This makes the effect larger than just counting the input twice. We have created $2v-f$ in new private coins while keeping the original coin spendable. The extra output is unbacked, and fresh forged tags let us repeat the construction with the same coin.

We only need a coin we own, its normal secrets, public cover-set data, and a modified prover. Everything goes through the normal validation path: Spark state [deserializes the payload](https://github.com/firoorg/firo/blob/98f7d13311b2655798f47e005f5658651b137dcf/src/spark/state.cpp#L178-L194), reconstructs the cover-set data, and [calls the spend verifier](https://github.com/firoorg/firo/blob/98f7d13311b2655798f47e005f5658651b137dcf/src/spark/state.cpp#L756-L802). Both mempool admission and block validation reach these checks.

## What happened after disclosure

The temporary restriction to single-input spends blocks this construction because we need two responses to redistribute the witness. This restriction has to apply during block validation too. A mempool-only rule would still allow a miner to include a forged spend directly in a block.

Firo's August announcement described the issue as an inflation vulnerability originating in the paper. The failure is in proving authorization for each input; the construction doesn't require another user's private keys.

On August 27, Firo published the [v0.14.18.0 release announcement](https://firo.org/2026/08/27/firo-v014180-release.html). The release introduces a new versioned Spark spend format containing the permanent fix, with activation set for block `1,371,000`, estimated at September 4, 2026. The announcement says multi-input spending resumes with that format and existing Spark coins remain valid without migration.

For me, the part to remember from this bug is the freedom in the prover's responses. The honest prover puts $c^{i+1}x_i$ into response $i$, but a malicious prover can put shares of both $c$ and $c^2$ into each response. Writing out what the verifier checks lets us see why this works, even with the random weight $w$.

Thanks for reading!
