---
author: "Giap"
title: "KalmarCTF 2024"
date: "2024-03-17"
categories: ["Writeup"]
tags: ["Pedersen Commitment", "Discrete Log", "PRNG"]
---

Last weekend, I played KalmarCTF 2024 with my team @1337%Yogurt. The cryptography category is very hard this year, so I could only manage to solve some of them. Here is my writeup for challenges that are solved by me.

## Cracking The Casino

`casino.py`
```py
#!/usr/bin/python3
from Pedersen_commitments import gen, commit, verify


# I want to host a trustworthy online casino!
# To implement blackjack and craps in a trustworthy way i need verifiable dice and cards!
# I've used information theoretic commitments to prevent players from cheating.
# Can you audit these functionalities for me ?

from random import randint
# Verifiable Dice roll
def roll_dice(pk):
    roll = randint(1,6)
    comm, r = commit(pk,roll)
    return comm, roll, r

# verifies a dice roll
def check_dice(pk,comm,guess,r):
    res = verify(pk,comm, r, int(guess))
    return res

# verifiable random card:
def draw_card(pk):
    idx = randint(0,51)
    # clubs spades diamonds hearts
    suits = "CSDH"
    values = "234567890JQKA"
    value = values[idx%13]
    suit = suits[idx//13]
    card = value + suit
    comm, r = commit(pk, int(card.encode().hex(),16))
    return comm, card, r

# take a card (as two chars, fx 4S = 4 of spades) and verifies it was the committed card
def check_card(pk, comm, guess, r):
    res = verify(pk, comm, r, int(guess.encode().hex(),16))
    return res


# Debug testing values for larger values
def debug_test(pk):
    dbg = randint(0,2**32-2)
    comm, r = commit(pk,dbg)
    return comm, dbg, r

# verify debug values
def check_dbg(pk,comm,guess,r):
    res = verify(pk,comm, r, int(guess))
    return res


def audit():
    print("Welcome to my (beta test) Casino!")
    q,g,h = gen()
    pk = q,g,h
    print(f'public key for Pedersen Commitment Scheme is:\nq = {q}\ng = {g}\nh = {h}')
    chosen = input("what would you like to play?\n[D]ice\n[C]ards")

    if chosen.lower() == "d":
        game = roll_dice
        verif = check_dice
    elif chosen.lower() == "c":
        game = draw_card
        verif = check_card
    else:
        game = debug_test
        verif = check_dbg

    correct = 0
    # If you can guess the committed values more than i'd expect, then
    for _ in range(1337):
        if correct == 100:
            print("Oh wow, you broke my casino??!? Thanks so much for finding this before launch so i don't lose all my money to cheaters!")
            with open("flag.txt","r") as f:
                flag = f.read()
            print(f"here's that flag you wanted, you earned it! {flag}")
            exit()

        comm, v, r = game(pk)
        print(f'Commitment: {comm}')
        g = input(f'Are you able to guess the value? [Y]es/[N]o')
        if g.lower() == "n":
            print(f'commited value was {v}')
            print(f'randomness used was {r}')
            print(f'verifies = {verif(pk,comm,v,r)}')
        elif g.lower() == "y":
            guess = input(f'whats your guess?')
            if verif(pk, comm, guess, r):
                correct += 1
                print("Oh wow! well done!")
            else:
                print("That's not right... Why are you wasting my time if you haven't broken anything?")
                exit()

    print(f'Guess my system is secure then! Lets go ahead with the launch!')
    exit()

if __name__ == "__main__":
    audit()
```

`Pedersen_commitments.py`
```py
from Crypto.Util.number import getStrongPrime
from Crypto.Random.random import randint

## Implementation of Pedersen Commitment Scheme
## Computationally binding, information theoreticly hiding

# Generate public key for Pedersen Commitments
def gen():
    q = getStrongPrime(1024)

    g = randint(1,q-1)
    s = randint(1,q-1)
    h = pow(g,s,q)

    return q,g,h

# Create Pedersen Commitment to message x
def commit(pk, m):
    q, g, h = pk
    r = randint(1,q-1)

    comm = pow(g,m,q) * pow(h,r,q)
    comm %= q

    return comm,r

# Verify Pedersen Commitment to message x, with randomness r
def verify(param, c, r, x):
    q, g, h = param
    if not (x > 1 and x < q):
        return False
    return c == (pow(g,x,q) * pow(h,r,q)) % q
```

Basically, you need to guess the message which is used for commitment. Because we have lots of rounds to try and Python `random` can be predictable if collect enough samples, so we can use `debug` mode to collect 624 32-bits messages, then we will be able to guess next message

`solve.py`
```py
from pwn import *
from mt19937predictor import MT19937Predictor #https://github.com/kmyk/mersenne-twister-predictor

#target = process(["python3", "casino.py"])
target = remote("chal-kalmarc.tf", 9)
target.recvline()
target.recvline()
q = int(target.recvline().decode()[3:])
g = int(target.recvline().decode()[3:])
h = int(target.recvline().decode()[3:])

predictor = MT19937Predictor()

target.recvuntil(b"[C]ards")
target.send(b"N\n")

guess = 0
game = 0
for _ in range(1337):
    comm = int(target.recvline().decode()[len("Commitment:"):])
    if guess < 625:
        guess += 1
        target.sendlineafter(b"[Y]es/[N]o", b"N")
        v = int(target.recvline().decode()[len("commited value was "):])
        r = int(target.recvline().decode()[len("randomness used was "):])
        target.recvline()
        predictor.setrandbits(v, 32)
    else:
        target.sendlineafter(b"[Y]es/[N]o", b"Y")
        target.sendlineafter(b"whats your guess?", (str(predictor.randint(0, 2**32-2))).encode())
        target.recvline()
        game += 1
    if game == 100:
        target.interactive()
```
>Flag: Kalmar{First_Crypto_Down!}
## Re-Cracking The Casino *

`casino.py`
```py
#!/usr/bin/python3
from Pedersen_commitments import gen, commit, verify


# I want to host a trustworthy online casino!
# To implement blackjack and craps in a trustworthy way i need verifiable dice and cards!
# I've used information theoretic commitments to prevent players from cheating.
# Can you audit these functionalities for me ?

# Thanks for the feedback, I'll use secure randomness then!
from Crypto.Random.random import randint
# Verifiable Dice roll
def roll_dice(pk):
    roll = randint(1,6)
    comm, r = commit(pk,roll)
    return comm, roll, r

# verifies a dice roll
def check_dice(pk,comm,guess,r):
    res = verify(pk,comm, r, int(guess))
    return res

# verifiable random card:
def draw_card(pk):
    idx = randint(0,51)
    # clubs spades diamonds hearts
    suits = "CSDH"
    values = "234567890JQKA"
    value = values[idx%13]
    suit = suits[idx//13]
    card = value + suit
    comm, r = commit(pk, int(card.encode().hex(),16))
    return comm, card, r

# take a card (as two chars, fx 4S = 4 of spades) and verifies it was the committed card
def check_card(pk, comm, guess, r):
    res = verify(pk, comm, r, int(guess.encode().hex(),16))
    return res


# Debug testing values for larger values
def debug_test(pk):
    dbg = randint(0,2**32-2)
    comm, r = commit(pk,dbg)
    return comm, dbg, r

# verify debug values
def check_dbg(pk,comm,guess,r):
    res = verify(pk, comm, r, int(guess))
    return res


def audit():
    print("Welcome to my (Launch day!) Casino!")
    q,g,h = gen()
    pk = q,g,h
    print(f'public key for Pedersen Commitment Scheme is:\nq = {q}\ng = {g}\nh = {h}')
    chosen = input("what would you like to play?\n[D]ice\n[C]ards")

    if chosen.lower() == "d":
        game = roll_dice
        verif = check_dice
    elif chosen.lower() == "c":
        game = draw_card
        verif = check_card
    else:
        game = debug_test
        verif = check_dbg

    correct = 0

    # Should be secure now :)
    for _ in range(256):
        if correct == 250:
            print("Oh wow, you broke my casino again??!? That's impossible!")
            with open("flag.txt","r") as f:
                flag = f.read()
            print(f"here's that flag you wanted, you earned it! {flag}")
            exit()

        comm, v, r = game(pk)
        print(f'Commitment: {comm}')
        g = input(f'Are you able to guess the value? [Y]es/[N]o')
        if g.lower() == "n":
            print(f'commited value was {v}')
            print(f'randomness used was {r}')
            print(f'verifies = {verif(pk,comm,v,r)}')
        elif g.lower() == "y":
            guess = input(f'whats your guess?')
            if verif(pk, comm, guess, r):
                correct += 1
                print("Oh wow! well done!")
            else:
                print("That's not right... Why are you wasting my time if you haven't broken anything?")
                exit()

    print(f'Guess my system is secure then! Lets go ahead with the launch!')
    exit()

if __name__ == "__main__":
    audit()
```

(`Pedersen_commitments.py` is the same as first version's one)

This time, server use more secure random function, and we need to guess correct 250/256 times, so we need to find different method to solve instead of crack random like the first version

In this challenge, I chose `card` mode to reduce space to search. We can convert card to number that server uses, and save its prime factor into a list `factor`

So why we need to do that ? We will solve discrete logarithm problem:

$$comm = g^x * h^r \mod q = g^{(x + rs)} \mod q$$(1)

When connect to the server, we will have a chance to have $(s, q - 1) = p > 1$ where $p$ is a small prime. If $p$ doesn't exist in `factor`, then we can change the equation (1) to $comm = g^x \mod q$ and solve dlog over $\mathbb{F}_q$, and now we can bruteforce $x$ to satisfy the commitment function.

`solve.py`
```py
from pwn import *
from Crypto.Random.random import randint
from Crypto.Util.number import sieve_base

card_values = [12867, 13123, 13379, 13635, 13891, 14147, 14403, 14659, 12355, 19011, 20803, 19267, 16707, 12883, 13139, 13395, 13651, 13907, 14163, 14419, 14675, 12371, 19027, 20819, 19283, 16723, 12868, 13124, 13380, 13636, 13892, 14148, 14404, 14660, 12356, 19012, 20804, 19268, 16708, 12872, 13128, 13384, 13640, 13896, 14152, 14408, 14664, 12360, 19016, 20808, 19272, 16712]

factor = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 43, 47, 53, 61, 71, 73, 89, 97, 101, 103, 107, 109, 131, 137, 139, 151, 191, 193, 223, 239, 277, 293, 353, 359, 479, 487, 547, 587, 733, 743, 787, 991, 1193, 1609, 1753, 1801, 1877, 2089, 2377, 2389, 3089, 3217, 4177, 4289, 4721, 4801, 4817, 5569, 6337, 13907, 14419, 19267]

while True:
    try:
        target = process(["python3", "casino.py"])
        #target = remote("chal-kalmarc.tf", 13337)
        target.recvline()
        target.recvline()
        q = int(target.recvline().decode()[3:])
        g = int(target.recvline().decode()[3:])
        h = int(target.recvline().decode()[3:])
        target.recvuntil(b"[C]ards")
        target.send(b"C\n")
        divs = 1
        for p in sieve_base:
            if (q - 1) % p == 0 and p not in factor:
                divs *= p
        d = (q - 1) // divs
        hd = pow(h, d, q)
        assert hd == 1
        gd = pow(g, d, q)
        assert gd != 1
        print("OK")
        gds = [pow(gd, value, q) for value in card_values]
        assert len(set(gds)) == len(card_values)
        for _ in range(256):
            comm = int(target.recvline().decode()[len("Commitment:"):])
            commd = pow(comm, d, q)
            for idx, value in enumerate(card_values):
                if pow(gd, value, q) == commd:
                    suits = "CSDH"
                    values = "234567890JQKA"
                    value = values[idx%13]
                    suit = suits[idx//13]
                    card = value + suit
            target.sendlineafter(b"[Y]es/[N]o", b"Y")
            target.sendlineafter(b"whats your guess?", card.encode())
            target.recvline()
        target.interactive()
    except:
        target.close()
```
>flag: Kalmar{Why_call_it_strong_if_its_so_weak...}

## MathGolf-Warmup

`chal-warmup.py`
```py
#!/usr/bin/env python3

# MathGolf-Warmup challenge by shalaamum for KalmarCTF 2024

import signal
import sys
import time
import sage.all

def out_of_time(signum, frame):
    print("\nTime is up!")
    sys.exit(1)

signal.signal(signal.SIGALRM, out_of_time)
signal.alarm(60)


def sequence_slow(n, b, c, a0, a1, p):
    if n == 0:
        return a0
    elif n == 1:
        return a1
    else:
        return (b*sequence(n - 1, b, c, a0, a1, p) + c*sequence(n - 2, b, c, a0, a1, p)) % p

# sequence = sequence_slow
from lib import sequence_fast
sequence = sequence_fast
# sequence_fast has the same return value as sequence_slow, it is just ...
# faster.


#from Crypto.Util.number import getPrime
#from Crypto.Random.random import randrange
#class ProblemGenerator:
#    def get(self):
#        p = getPrime(64)
#        n = randrange(1, 1<<64)
#        b, c, a0, a1 = [randrange(0, p) for _ in range(4)]
#        return n, b, c, a0, a1, p
from lib import ProblemGenerator
generator = ProblemGenerator()
# You can assume that ProblemGenerator acts as the above commented snippet.
# It just makes some tweaks that are intended to reduce the variance of the
# run times. Trying to guess those tweaks is unlikely to be helpful to solve
# the challenge.
# Note: The reason in the comment above are for the non-warmup version of the
# challenge.


def get_number():
    return int(input().strip()[2:], 16)


def sequence_from_parameters(n, b, c, a0, a1, p, parameters):
    poly = parameters[0:2]
    phi = parameters[2:4]
    psi = parameters[4:6]
    const_phi = parameters[6:8]
    const_psi = parameters[8:10]

    Fp = sage.all.GF(p)
    RFp = sage.all.PolynomialRing(Fp, ['t'])
    F = sage.all.GF(p**2, name='t', modulus=RFp(poly + [1]))
    phi = F(phi)
    psi = F(psi)
    const_phi = F(const_phi)
    const_psi = F(const_psi)

    answer = list(phi**n * const_phi - psi**n * const_psi)
    if answer[1] != 0:
        print("That can't be right...")
        sys.exit(1)
    return int(answer[0])

for i in range(100):
    print(f'Solved {i} of 100')
    n, b, c, a0, a1, p  = generator.get()
    print(f'b  = 0x{b:016x}')
    print(f'c  = 0x{c:016x}')
    print(f'a0 = 0x{a0:016x}')
    print(f'a1 = 0x{a1:016x}')
    print(f'p  = 0x{p:016x}')

    parameters = []
    print('Polynomial: ')
    parameters.append(get_number())
    parameters.append(get_number())
    print('phi: ')
    parameters.append(get_number())
    parameters.append(get_number())
    print('psi: ')
    parameters.append(get_number())
    parameters.append(get_number())
    print('const_phi: ')
    parameters.append(get_number())
    parameters.append(get_number())
    print('const_psi: ')
    parameters.append(get_number())
    parameters.append(get_number())

    print('Checking...')
    answer = sequence_from_parameters(n, b, c, a0, a1, p, parameters)
    correct = sequence(n, b, c, a0, a1, p)
    if answer != correct:
        print(f'Incorrect! Correct answer was 0x{correct:016x}')
        sys.exit(1)

print(open('flag.txt', 'r').read())
```

In this challenge, we are asked to calculate nth element of the sequence:

$$\begin{aligned} a _ n = b * a _ {n - 1} + c * a _ {n - 2} \mod p \end{aligned}$$

I will explain how to find general term of $(a_n)$. First, we need to solve the quadratic equation (it is called __characteristic equation__):

$$x^2 - bx - c = 0 \mod p$$(1)

Our delta will be $\Delta = \sqrt{b^2 + 4c}$, and because we are working in $\mathbb{F}_p$, we have two scenarios

__Case 1:__ $\Delta$ is a quadratic residue modulo $p$

If $\Delta$ is a quadratic residue modulo $p$, so we can calculate two roots of (1) like normal. Suppose that our roots are $x_1$ and $x_2$, so the general term of our sequence will be $$a_n = u * x _ 1 ^ n + v * x _ 2 ^ n$$

Because server gives us $a_0$ and $a_1$, so we can calculate $u$ and $v$ easily, which are `const_phi` and `const_psi`

__Case 2:__ $\Delta$ is a nonquadratic residue modulo $p$

Now, we can't work over $\mathbb{F} _ p$ because $\sqrt{\Delta}$ doesn't exist, so we need to work over $\mathbb{F} _ {p^2}$, and it is equivalent to $\mathbb{F} _ p[x]/(x^2 - \Delta)$. After extend the field, we can do the same as Case 1

Because server requires polynomial modulo in all cases, so for case 1, I bruteforce to find a number which is a quadratic nonresidue modulo $p$.

`solve.py`
```py
from sage.all import *
from pwn import *

def sequence_fast(b, c, a0, a1, p):
    Fp = GF(p)
    RFp = PolynomialRing(Fp, 't')
    t = RFp.gen()
    delta = Fp(b**2 + 4 * c)
    if kronecker(delta, p) == 1: 
        phi = (b + delta.sqrt()) * pow(2, -1, p) % p
        psi = (b - delta.sqrt()) * pow(2, -1, p) % p
        cpsi = (a1 - a0 * phi) * pow(phi - psi, -1, p) % p
        cphi = (a0 + cpsi) % p
        while True:
            coeff = randint(1, p)
            if (t**2 + coeff).is_irreducible():
                break
        return [coeff, 0, phi, 0, psi, 0, cphi, 0, cpsi, 0]
    else:
        F = GF(p**2, name="t", modulus = RFp([-delta, 0, 1]))
        W = F.gen()
        phi = (b + W) / F(2)
        psi = (b - W) / F(2)
        cpsi = F(a1 - a0 * phi) / F(phi - psi)
        cphi = a0 + cpsi
        ans = [-delta, 0] + list(phi) + list(psi) + list(cphi) + list(cpsi)
        return ans


target = remote("mathgolf.chal-kalmarc.tf", "3470")
for _ in range(100):
    target.recvline()
    b = int(target.recvline().decode()[len("b  = "):], 16)
    c = int(target.recvline().decode()[len("c  = "):], 16)
    a0 = int(target.recvline().decode()[len("a0 = "):], 16)
    a1 = int(target.recvline().decode()[len("a1 = "):], 16)
    p = int(target.recvline().decode()[len("p  = "):], 16)
    ans = sequence_fast(b, c, a0, a1, p)
    for i in range(5):
        target.recvline()
        request = str(hex(ans[2 * i])) + "\n" + str(hex(ans[2 * i + 1])) + "\n"
        target.send(request.encode())
    target.recvline()

target.interactive()
```

>flag: kalmar{generalized_fibonacci_sequence_in_a_finite_field__did_you_implement_everything_yourself_for_this__for_non-warmup_you_might_have_to}

