---
author: "Giap"
title: "Yao's Garbled Circuit"
date: "2024-08-17"
categories: ["Learning"]
tags: ["MPC", "Garbled Circuit"]
---

## Introduction

Yao's Garbled Circuit is a cryptographic protocol that enables two-party secure computation in which two mistrusting parties can jointly evaluate a function over their private inputs without the presence of a trusted third party. 

The invention of garbled circuit was credited to Andrew Yao, as Yao introduced the idea in [[FOCS'86]](#1). The first written document about thus technique was by Goldreich, Micali and Wigderson in [[STOC'87]](#2).

Yao's protocol solving Yao's Millionaires' Problem [[IEEE'82]](#3) was the beginning example of secure computation, yet it's not directly relate to garbled circuit.

## Background

### Boolean Circuits

A Boolean circuit is a mathematical model for combinational digital logic circuits. Boolean circuits are defined in terms of the logic gates they contain. For example, a circuit might contain binary AND and OR gates and unary NOT gates, or be entirely described by binary NAND gates. Each gate corresponds to some Boolean function that takes a fixed number of bits as input and outputs a single bit.

<p align="center">
  <img src="https://hackmd.io/_uploads/r1eKXUXqC.png" />
</p>
<p style="text-align: center;"><sub>Example of a boolean circuit. Image is taken from <a href="https://wiki.mpcalliance.org/garbled_circuit.html">MPC Wiki</a> </sub></p>


### Oblivious Transfer

In cryptography, an oblivious transfer (OT) protocol is a type of protocol in which a sender transfers one of potentially many pieces of information to a receiver, but remains oblivious as to what piece (if any) has been transferred.

There are three types of OT protocol: 1-2 oblivious transfer, 1-out-of-n oblivious transfer and k-out-of-n oblivious transfer.

Let's take an example with 1-2 oblivious transfer type: Suppose a sender has two messages $m_0$ and $m_1$, the receiver has a bit $b$. With oblivious transfer protocol, they can ensure two things:

- The receiver learns $m_b$, but not the other message
- The sender learns nothing

<p align="center">
  <img src="https://hackmd.io/_uploads/HJ_wnHQqR.png" />
</p>
<p style="text-align: center;"><sub>An illustration of OT protocol.</sub></p>

The oblivious transfer can be built using asymmetric cryptography like RSA cryptosystem, Diffie-Hellman Key Exchange,... 

## Explain Protocol

There are two roles in Yao's Garbled Circuit protocol:

- Garbled circuit generator, or Garbler, who generates garbled circuit from pre-calculated boolean circuit truth table, and send it to evaluator.
- Evaluator, who takes the garbled circuit, evaluates it and produces final result. Then they share the result with the garbler.

To make the explanation easier, we will use only AND gate as our boolean circuits with symbol $\land$; Ginny will be garbler and Eve will be evaluator. We also note that $g$, $e$ are Ginny's secret message and Eve's secret message.

### Garbled Gate Generation

Ginny picks four random strings called labels $W_G^0$, $W_G^1$, $W_E^0$ and $W_E^1$. $W_G^0$ and $W_G^1$ correspond to the event that $g = 0$ or $g = 1$, respectively; and $W_E^0$, $W_E^1$ correspond that $e = 0$ or $e = 1$. 

Ginny then uses every pair of labels corresponding to a possible scenario $((g = 0, e = 0), (g = 1, e = 0), (g = 0, e = 1), (g = 1, e = 1))$ to encrypt the output corresponding to that scenario. The two relevant labels are put through a key derivation function $H$ to derive a symmetric encryption key, and that key is used to encrypt $g \land e$

The garbled gate consists of the four resulting ciphertexts, in a random order.

<p align="center">
  <img src="https://hackmd.io/_uploads/By4ACHm50.png" />
</p>
<p style="text-align: center;"><sub>The garbling of an AND gate.</sub></p>

### Garbled Gate Evaluation

After received garbled gate, Eve needs to decrypt the ciphertext which corresponds to the real values $g$ and $e$, encrypted with $H(W_G^g, W_E^e)$. To do this, Eve need two values $W_G^g$ and $W_E^e$. 

- Ginny sends Eve $W_G^g$, because Ginny knows $g$ and Evan doesn't.
- Because Ginny doesn't know $e$, so Ginny can't send directly $W_E^e$ to Eve. She also can't send both $W_E^0$ and $W_E^1$ to Eve, because with two keys, Eve can decrypt two ciphertexts in the garbled gate, therefore knows Ginny's secret message. To solve this problem, Ginny and Eve use oblivious transfer, which allows Eve to learn only $W_E^e$ without revealing $e$ to Ginny

When Eve has two values $W_G^g$ and $W_E^e$, Eve can try to decrypt all ciphertexts in garbled gate. If the decryption is success, Eve will send the result to Ginny and both of them will know $g \land e$, without knowing each other secret.

### From Gates to Circuits

From only AND gate, we can extend to a much more complicated circuit: Ginny will garble the entire circuit. For gates whose output serves as input to other gates, instead of encrypting the output bit, she will encrypt a label corresponding to the output bit: $W_w^0$ or $W_w^1$. That label will then be used to derive a key for the decryption of ciphertexts in other gates.

<p align="center">
  <img src="https://hackmd.io/_uploads/Hy0E7IX9A.jpg" />
</p>
<p style="text-align: center;"><sub>An example of complicated garbled circuit. Image is taken from <a href="https://wiki.mpcalliance.org/garbled_circuit.html">MPC Wiki</a> </sub></p>

## Optimizations to Yao's Garbled Circuits

### Point-and-permute

The Point-and-permute technique saves Eve from trying to decrypt all four ciphertexts.

In this optimization, garbler generates two *select bits* $p^0$ and $p^1$ in addition to label $W^0$ and $W^1$. For $v \in \lbrace 0, 1 \rbrace$, the select bit $p^v$ is equal to $v \oplus r$, where $r \in \lbrace 0, 1 \rbrace$ is a randomly chosen bit. By this way, the select bit $p^v$ is different for the two possible underlying values $v$, but does not reveal anything about $v$. The select bit $p$ of each wire is retrieved along with the wire label.

When evaluating a gate, evaluator uses the two select bits $p_i, p_j$ corresponding to the two input wires $w_i, w_j$ to determine which ciphertext in gate $k$ to decrypt. More precisely, garbler always places $Enc(H(W_i^{v_i}, W_j^{v_j}), W_k^{g_k(v_i, v_j)}||p_k^{g_k(v_i, v_j)})$ in the $(2p_i^{w_i} + p_j^{w_j})$.

<p align="center">
  <img src="https://hackmd.io/_uploads/rkmw8IQqA.png" />
</p>
<p style="text-align: center;"><sub>Garbled AND gate by using point-and-permute optimization.</sub></p>

This reduces the evaluation load by 4 times, and also does not reveal anything about the output value because the select bits are randomly generated. Because of it's productive, all optimizations below are combined with Point-and-permute optimization.

Note that with this one, we can use simpler and more efficient encryption schemes such as the one-time pad.

### Free XOR [[KS08]](#4)

The free-XOR technique enables the computation of XOR gates for free, as the name suggests. It does so by fixing the relationship between labels $W^0$ and $W^1$. When garbling the circuit, garbler picks a random string $R \gets \{0, 1\}^L$ and a random labels $W^0$, then set $W^1 = W^0 \oplus R$. 

If gate $g_k$ is an XOR gate and takes wires $w_i$ and $w_j$ as input, the new label for wire $w_k$ can be computed simply by taking the XOR of labels $W_i$ and $W_j$. We can calculate $W^0_k = W_i^0 \oplus W_j^0$ and $W^1_k = W^0_k \oplus R$. This works because

$$\begin{aligned} W_i^0 \oplus W_j^0 &= W_k^0 \\ W_i^0 \oplus W_j^1 &= W_i^0 \oplus W_j^0 \oplus R = W_k^0 \oplus R \\ W_i^1 \oplus W_j^0 &= W_i^0 \oplus W_j^0 \oplus R = W_k^0 \oplus R \\ W_i^1 \oplus W_j^1 &= W_i^0 \oplus R \oplus W_j^0 \oplus R = W_i^0 \oplus W_j^0 = W_k^0\end{aligned}$$

<p align="center">
  <img src="https://hackmd.io/_uploads/Skc7dUm50.png" />
</p>
<p style="text-align: center;"><sub>Garbled XOR gate by using free-XOR optimization. We won't need to use key derivation function.</sub></p>

Remember that when use this optimization, we still need to garble AND gates. 

### Garbled Row reduction (GRR3) [[NPS99]](#5)

This optimization reduces the size of garbled tables from 4 rows to 3 rows. It can be achieved by choosing proper label in such a way that the corresponding ciphertext is 0. Note that the eliminated ciphertext will always be the top one, as determined by the select bits.

<p align="center">
  <img src="https://hackmd.io/_uploads/rksmcIXqA.png" />
</p>
<p style="text-align: center;"><sub>Garbled XOR gate by using GRR3 + free-XOR optimization.</sub></p>

This optimization can combine perfectly with the free-XOR to reduce size and reduce times to calls to key derivarion function $H$ per gate, therefore increase performance of the protocol.

### Garbled Row reduction (GRR2) [[PSSW09]](#6)

This second form of garbled row reduction allows the elimination of two ciphertexts instead of one. In GRR2, instead of recovering the output label by decrypting the ciphertext, the evaluator uses polynomial interpolation over a quadratic curve. 

In this optimization, the output label is encoded as the $y$-intercept. One point on the polynomial is revealed in the usual way - as $y = H(W_i^{v_i}, W_j^{v_j})$, wich the select bits determining $x \in \{1, 2, 3, 4\}$. Two more (the ones at $x = 5$ and $x = 6$) are included in the garbled gate. With three points, Eve can interpolate a unique polynomial $f$ and use it to calculate output label at $f(0)$.

Because there are two possible output labels, there are two different quadratic polynomials to consider. They are designed to intersect exactly in the two points included in the garbled gate.

<p align="center">
  <img src="https://hackmd.io/_uploads/Hyex4oK9C.png" />
</p>
<p style="text-align: center;"><sub>GRR2 Garbled Gate Values for an AND gate, image taken from "A Gentle Introduction to Yao’s Garbled Circuits - Sophia Yakoubov" </sub></p>

Note that GRR2 uses a finite field, not in real field.

### FleXOR [[KMR14]](#6)

FleXOR is a combination of the free-XOR technique with AND gate optimizations by translating wire label to have a constant distance $R$ on the fly. Depending on whether this translation is needed, XOR garbled gates contain between 0 and 2 ciphertexts.

### Half Gates [[ZRE15]](#7)

This technique only requires two ciphertexts per garbled AND gate and is compatible with the free-XOR optimization. They use the fact that $v_i \land v_j = (v_i \land (v_j \oplus b)) \oplus (v_i \land b)$ for any $b \in \{0, 1\}$.

In the half gates technique, $b$ is determined to be the random value $r_j \in \{0, 1\}$ used to compute the select bit $p_j = v_j \oplus r_j$. $b = r_j$ is chosen by the garbler, and $v_j \oplus b = p_j$ is revealed to the evaluator. 

Because of knowing $b$, garbler can efficiently garble the "garbler half gate" $v_i \land b$ using a single ciphertext. Using the fact that the evaluator knows $v_j \oplus b$, and can this behave differently based on that value, the garbler can similarly efficiently garble the "evaluator half gate" $v_i \land (v_j \oplus b)$ using a singler ciphertext. Taking the XOR of these two AND operations is free, so only two ciphertexts are required.

### Summary table

<p align="center">
  <img src="https://hackmd.io/_uploads/HJldwv7c0.png" />
</p>
<p style="text-align: center;"><sub>Optimizations of garbled circuits, table from "Two halves make a whole
- reducing data transfer in garbled circuits using half gates" - Zahur et al.</sub></p>


## Example implementation

The implementation of this protocol can be found at https://github.com/Giapppp/toy-garbled-circuit. Note that it's still be updated.

## References

<a id="1">**[FOCS'86]**</a>. Yao, Andrew Chi-Chih (1986). "How to generate and exchange secrets". 27th Annual Symposium on Foundations of Computer Science (SFCS 1986). pp. 162–167.

<a id="2">**[STOC'87]**</a>. Goldreich, Oded; Micali, Silvio; Wigderson, Avi (1987). "How to play ANY mental game". Proceedings of the nineteenth annual ACM conference on Theory of computing - STOC '87. pp. 218–229.

<a id="3">**[IEEE'82]**</a>. A. C. Yao, Protocols for secure computations (Extended Abstract), 23rd annual
symposium on foundations of computer science (Chicago, Ill., 1982), 160–164, IEEE, New York, 1982.

<a id="4">**[KS08]**</a>. Vladimir Kolesnikov and Thomas Schneider. Improved garbled circuit: Free XOR gates and applications. In Luca Aceto, Ivan Damgård, Leslie Ann Goldberg, Magnús M. Halldórsson, Anna Ingólfsdóttir, and Igor Walukiewicz, editors, ICALP 2008, Part II, volume 5126 of LNCS, pages 486–498. Springer,Heidelberg, July 2008.

<a id="5">**[NPS99]**</a>. Moni Naor, Benny Pinkas, and Reuban Sumner. Privacy preserving auctions and mechanism design. In Proceedings of the 1st ACM Conference on Electronic Commerce, EC ’99, pages 129–139, New York, NY, USA, 1999. ACM.

<a id="6">**[PSSW09]**</a>. Benny Pinkas, Thomas Schneider, Nigel P. Smart, and Stephen C. Williams. Secure two-party computation is practical. In Mitsuru Matsui, editor, ASIACRYPT 2009, volume 5912 of LNCS, pages 250–267. Springer, Heidelberg, December 2009.

<a id="7">**[KMR14]**</a>. Vladimir Kolesnikov, Payman Mohassel, and Mike Rosulek. FleXOR: Flexible garbling for XOR gates that beats free-XOR. In Juan A. Garay and Rosario Gennaro, editors, CRYPTO 2014, Part II, volume 8617 of LNCS, pages 440–457. Springer, Heidelberg, August 2014.

<a id="8">**[ZRE15]**</a>. Samee Zahur, Mike Rosulek, and David Evans. Two halves make a whole - reducing data transfer in garbled circuits using half gates. In Elisabeth Oswald and Marc Fischlin, editors, EUROCRYPT 2015, Part II, volume 9057 of LNCS, pages 220–250. Springer, Heidelberg, April 2015.