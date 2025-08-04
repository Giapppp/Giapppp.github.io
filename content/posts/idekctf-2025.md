---
author: "Giap"
title: "idekCTF 2025"
date: 2025-08-03
description: My writeup for all challenges I created for idekctf 2025, and some lessons i learned.
tags: ["CTF-Writeup"]
---

idekCTF 2025 is one of the most memorable events for me — not only because I was the author of many challenges in this prestigious CTF, but also because of the bunch of dumb mistakes I made. Therefore, it’s worth having its own post. A huge thanks to all the idek team members for organizing and hosting it, especially @es3n1n for all the effort he put into making this CTF — truly a king!

All solve scripts can be found at [my repository](https://github.com/Giapppp/my-ctf-challenges/tree/main/idekCTF-2025).

## Catch

```python
from Crypto.Random.random import randint, choice
import os

# In a realm where curiosity roams free, our fearless cat sets out on an epic journey.
# Even the cleverest feline must respect the boundaries of its world—this magical limit holds all wonders within.
limit = ...

# Through cryptic patterns, our cat deciphers its next move.
def walking(x, y, part):
    # Each step is guided by a fragment of the cat's own secret mind.
    epart = [int.from_bytes(part[i:i+2], "big") for i in range(0, len(part), 2)]
    xx = epart[0] * x + epart[1] * y
    yy = epart[2] * x + epart[3] * y
    return xx, yy

# Enter the Cat: curious wanderer and keeper of hidden paths.
class Cat:
    def __init__(self):
        # The cat's starting position is born of pure randomness.
        self.x = randint(0, 2**256)
        self.y = randint(0, 2**256)
        # Deep within, its mind holds a thousand mysterious fragments.
        while True:
            self.mind = os.urandom(1000)
            self.step = [self.mind[i:i+8] for i in range(0, 1000, 8)]
            if len(set(self.step)) == len(self.step):
                break

    # The epic chase begins: the cat ponders and strides toward the horizon.
    def moving(self):
        for _ in range(30):
            # A moment of reflection: choose a thought from the cat's endless mind.
            part = choice(self.step)
            self.step.remove(part)
            # With each heartbeat, the cat takes a cryptic step.
            xx, yy = walking(self.x, self.y, part)
            self.x, self.y = xx, yy
            # When the wild spirit reaches the edge, it respects the boundary and pauses.
            if self.x > limit or self.y > limit:
                self.x %= limit
                self.y %= limit
                break

    # When the cosmos beckons, the cat reveals its secret coordinates.
    def position(self):
        return (self.x, self.y)

# Adventurer, your quest: find and connect with 20 elusive cats.
for round in range(20):
    try:
        print(f"👉 Hunt {round+1}/20 begins!")
        cat = Cat()

        # At the start, you and the cat share the same starlit square.
        human_pos = cat.position()
        print(f"🐱✨ Co-location: {human_pos}")
        print(f"🔮 Cat's hidden mind: {cat.mind.hex()}")

        # But the cat, ever playful, dashes into the unknown...
        cat.moving()
        print("😸 The chase is on!")

        print(f"🗺️ Cat now at: {cat.position()}")

        # Your turn: recall the cat's secret path fragments to catch up.
        mind = bytes.fromhex(input("🤔 Path to recall (hex): "))

        # Step by step, follow the trail the cat has laid.
        for i in range(0, len(mind), 8):
            part = mind[i:i+8]
            if part not in cat.mind:
                print("❌ Lost in the labyrinth of thoughts.")
                exit()
            human_pos = walking(human_pos[0], human_pos[1], part)

        # At last, if destiny aligns...
        if human_pos == cat.position():
            print("🎉 Reunion! You have found your feline friend! 🐾")
        else:
            print("😿 The path eludes you... Your heart aches.")
            exit()
    except Exception:
        print("🙀 A puzzle too tangled for tonight. Rest well.")
        exit()

# Triumph at last: the final cat yields the secret prize.
print(f"🏆 Victory! The treasure lies within: {open('flag.txt').read()}")
```

In this challenge, we need to find subset $S$ of matrices $M_i$ of length 30 from given matrices in `cat.mind` so that $$c = \prod M_i * h$$ where $c, h$ is position of cat and human, respectively.

To solve this challenge, players need to notice that each matrix has small entries — about 16 bits out of the 1024-bit `limit` value. Therefore, the product of these matrices will also be small. Using this property, we can multiply the inverse of each matrix in `cat.mind` and check whether all entries remain small; otherwise, it is not in 
𝑆
S. Repeat this process, and we will get the flag.

> This idea came from https://eprint.iacr.org/2023/1745.pdf, and I found its a very cool trick.

> Flag: idek{Catch_and_cat_sound_really_similar_haha}

## Diamond Ticket

```python
from Crypto.Util.number import *

#Some magic from Willy Wonka
p = 170829625398370252501980763763988409583
a = 164164878498114882034745803752027154293
b = 125172356708896457197207880391835698381

def chocolate_generator(m:int) -> int:
    return (pow(a, m, p) + pow(b, m, p)) % p

#The diamond ticket is hiding inside chocolate
diamond_ticket = open("flag.txt", "rb").read()
assert len(diamond_ticket) == 26
assert diamond_ticket[:5] == b"idek{"
assert diamond_ticket[-1:] == b"}"
diamond_ticket = bytes_to_long(diamond_ticket[5:-1])

flag_chocolate = chocolate_generator(diamond_ticket)
chocolate_bag = []

#Willy Wonka are making chocolates
for i in range(1337):
    chocolate_bag.append(getRandomRange(1, p))

#And he put the golden ticket at the end
chocolate_bag.append(flag_chocolate)

#Augustus ate lots of chocolates, but he can't eat all cuz he is full now :D
remain = chocolate_bag[-5:]

#Compress all remain chocolates into one
remain_bytes = b"".join([c.to_bytes(p.bit_length()//8, "big") for c in remain])

#The last chocolate is too important, so Willy Wonka did magic again
P = getPrime(512)
Q = getPrime(512)
N = P * Q
e = bytes_to_long(b"idek{this_is_a_fake_flag_lolol}")
d = pow(e, -1, (P - 1) * (Q - 1))
c1 = pow(bytes_to_long(remain_bytes), e, N)
c2 = pow(bytes_to_long(remain_bytes), 2, N) # A small gift

#How can you get it ?
print(f"{N = }")
print(f"{c1 = }")
print(f"{c2 = }") 

"""
N = ...
c1 = ...
c2 = ...
"""
```

This is a revenge from my challenge [Golden Ticket](https://github.com/idekctf/idekctf-2024/tree/main/crypto/goldenticket) last year. From feedbacks of some friends in idek, we have the revenge version of this challenge. 

> Because `e` can be anything, I just wanted to find a special value — but I don’t know why I ended up choosing a value that has the flag format, lol. Sorry for this confusing moment!

### Get value `remain_bytes`

We have two equations related to `remain_bytes`: $$\begin{aligned} c_1 &= rb^e \mod N \newline c_2 &= rb^2 \mod N \end{aligned}$$
where `rb = bytes_to_long(remain_bytes)`

To find $rb$, we can consider two polynomials $f_1 = rb^e - c_1$ and $f_2 = rb^2 - c_2$, therefore if we calculate $f_1 \mod f_2$, we will get a univariate polynomial with unknown $rb$, which is easy to solve. Because the degree of $f_1$ is really big, so we can use quotient ring with modulo $f_2$ instead.

> I overcomplicated this part a lot 🥲, since we can actually just do a common modulus attack to get the value `remain_bytes`. Maybe that’s because I was thinking from the author’s perspective, not the player’s perspective, lol.

After got `remain_bytes`, we can easily get value `flag_chocolate`.

### Get "diamond-ticket"-th power of $a$

Now we need to solve this equation: $$a^x + b^x = fc \mod p$$

A good thing to notice is that we have both values $a$ and $b$, therefore a natural way to think is find the relationship between these values. Because $p - 1$ is really smooth, so we can calculate $j$ such that $b=a^j \mod p$. Combine with the equation above, we can set $s = a^x \mod p$ and our equation will become: $$P(s) = s^j + s - fc = 0 \mod p$$

In this challenge, I set the value $j = 73331$, therefore it will be very long if we find roots of $P(s)$ via `.roots()` in Sagemath. A good trick to know is finding roots of $H(s) = gcd(P(s), G(s))$ where $G(s) = s^p - s \mod P(s)$, and we will get the root very fast.

> I learned this trick from https://adib.au/2025/lance-hard/#speedup-by-using-gcd and met it again at MaltaCTF 2025 Quals - grammar-nazi. Really cool trick to know !

When we get $s$, we can get the value $m \mod p-1$ easily, as $p$ is smooth as we said above.

### Get flag

Notice that our flag is 160 bits when we only have 128 bits, therefore we need to do little work. Two options you can think about is:
- **Bruteforce 32 bits**: 32 bits is totally doable in modern machine, you can write a bruteforce script in C/C++/Rust/... and wait to get flag.
- **Lattice**: I prefer this option. Basically you can consider each character of flag is variable, then LLL and enumerate to get real flag based on the fact that flag is printable. The idea is inspired from [SEETF 2023 - 🤪onelinecrypto](https://adib.au/2023/onelinecrypto/). Feel like this challenge have too many tricks from Neobeo posts xD.

> Maybe I should give player hash of flag, therefore it's easier to check and avoid confusion, as there are lots of solutions we can have when doing enumerate.

> flag: idek{tks_f0r_ur_t1ck3t_xD}

## Sadness ECC - Revenge

```python
from Crypto.Util.number import *
from secret import n, xG, yG
import ast

class DummyPoint:
    O = object()

    def __init__(self, x=None, y=None):
        if (x, y) == (None, None):
            self._infinity = True
        else:
            assert DummyPoint.isOnCurve(x, y), (x, y)
            self.x, self.y = x, y
            self._infinity = False

    @classmethod
    def infinity(cls):
        return cls()

    def is_infinity(self):
        return getattr(self, "_infinity", False)

    @staticmethod
    def isOnCurve(x, y):
        return pow(y - 1337, 3, n) == pow(x, 2, n) 

    def __add__(self, other):
        if other.is_infinity():
            return self
        if self.is_infinity():
            return other

        # ——— Distinct‑points case ———
        if self.x != other.x or self.y != other.y:
            dy    = self.y - other.y
            dx    = self.x - other.x
            inv_dx = pow(dx, -1, n)
            prod1 = dy * inv_dx
            s     = prod1 % n

            inv_s = pow(s, -1, n)
            s3    = pow(inv_s, 3, n)

            tmp1 = s * self.x
            d    = self.y - tmp1

            d_minus    = d - 1337
            neg_three  = -3
            tmp2       = neg_three * d_minus
            tmp3       = tmp2 * inv_s
            sum_x      = self.x + other.x
            x_temp     = tmp3 + s3
            x_pre      = x_temp - sum_x
            x          = x_pre % n

            tmp4       = self.x - x
            tmp5       = s * tmp4
            y_pre      = self.y - tmp5
            y          = y_pre % n

            return DummyPoint(x, y)

        dy_term       = self.y - 1337
        dy2           = dy_term * dy_term
        three_dy2     = 3 * dy2
        inv_3dy2      = pow(three_dy2, -1, n)
        two_x         = 2 * self.x
        prod2         = two_x * inv_3dy2
        s             = prod2 % n

        inv_s         = pow(s, -1, n)
        s3            = pow(inv_s, 3, n)

        tmp6          = s * self.x
        d2            = self.y - tmp6

        d2_minus      = d2 - 1337
        tmp7          = -3 * d2_minus
        tmp8          = tmp7 * inv_s
        x_temp2       = tmp8 + s3
        x_pre2        = x_temp2 - two_x
        x2            = x_pre2 % n

        tmp9          = self.x - x2
        tmp10         = s * tmp9
        y_pre2        = self.y - tmp10
        y2            = y_pre2 % n

        return DummyPoint(x2, y2)

    def __rmul__(self, k):
        if not isinstance(k, int) or k < 0:
            raise ValueError("Choose another k")
        
        R = DummyPoint.infinity()
        addend = self
        while k:
            if k & 1:
                R = R + addend
            addend = addend + addend
            k >>= 1
        return R

    def __repr__(self):
        return f"DummyPoint({self.x}, {self.y})"

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

if __name__ == "__main__":
    G = DummyPoint(xG, yG)
    print(f"{n = }")
    stop = False
    while True:
        print("1. Get random point (only one time)\n2. Solve the challenge\n3. Exit")
        try:
            opt = int(input("> "))
        except:
            print("❓ Try again."); continue

        if opt == 1:
            if stop:
                print("Only one time!")
            else:
                stop = True
                k = getRandomRange(1, n)
                P = k * G
                print("Here is your point:")
                print(P)

        elif opt == 2:
            ks = [getRandomRange(1, n) for _ in range(2)]
            Ps = [k * G for k in ks]
            Ps.append(Ps[0] + Ps[1])

            ans = sum([[P.x, P.y] for P in Ps], start=[])
            print("Sums (x+y):", [P.x + P.y for P in Ps])
            try:
                check = ast.literal_eval(input("Your reveal: "))
            except:
                print("Couldn't parse."); 

            if ans == check:
                print("Correct! " + open("flag.txt").read())
            else:
                print("Wrong...")
            break

        else:
            print("Farewell.") 
            break
```

In this challenge, we need to detect the curve that challenge use, then recover three random points based on the sum of coordinates of each points.

### Why revenge ?

In the first version, there is a bug in how to get input:

```python
try:
    ans = ast.literal_eval(input("Your reveal: "))
except:
    print("Couldn't parse."); continue

if all(P == DummyPoint(*c) for P, c in zip(Ps, ans)):
    print("Correct! " + open("flag.txt").read())
else:
    print("Wrong...")
break
```

Player can send `[]` and bypass the condition line `all(P == DummyPoint(*c) for P, c in zip(Ps, ans))`, and therefore get flag ! This is a bad unintended way where the cause is from my coding issue, so I need to release the revenge version to not make my challenge wasteful xD.

Anyways, here is the flag for first version:
> idek{the_idea_came_from_a_Vietnamese_high_school_Mathematical_Olympiad_competition_xD}

### Let's solve the revenge version

#### Recover the curve 

By reading the source code carefully, we can see how the curve generate new point:
- Construct the line between two points (or the tangent of one point when doubling).
- Find the intersect between the line and the curve.
- From the intersect above, we can get new point.

Notice the doubling algorithm, we can see the suspicious part:
```python
dy_term       = self.y - 1337
dy2           = dy_term * dy_term
three_dy2     = 3 * dy2
inv_3dy2      = pow(three_dy2, -1, n)
two_x         = 2 * self.x
prod2         = two_x * inv_3dy2
s             = prod2 % n
```
as its calculate the slope $$s = \frac{dx}{dy} = \frac{2 x}{3 (y - 1337)^2}$$ therefore, we can consider our curve will have the form $(y - 1337)^2 = x^3 + c \mod n$. 

From option one, we can get one point on the curve, therefore we can plug to equation above and get $c$. With that, our curve will be $$(y - 1337)^2 = x^3 \mod n$$.

#### Recover each points

After recovered the curve, we will have six equations: three equations of form $x_i + y_i$, and three equations of form $(y_i - 1337)^2 = x_i^3$, but this is not enough. Because the last point is the sum of two points, therefore we can choose one option from these options:
- **Symbolic the addition function**: I think many players will do this, as its straightforward to do, then use groebner basis to get all coordinates.
- **Use the mapping**: From the curve $(y - 1337)^2 = x^3$, we can construct a map $$\begin{aligned} E(\mathbb{Z}_n) &\to \mathbb{Z}_n \newline (x, y) &\mapsto \frac{y-1337}{x} \end{aligned}$$. Therefore, because three points are on the same line, then we will have $$\sum P_i = 0 \to \sum \frac{y_i - 1337}{x_i} = 0$$ and we can get all coordinates by using groebner basis.

> The second one is intended, and the flag is related to it, as I get this idea from a Vietnamese's facebook group. The mapping is really cool in my opinion but maybe I should use it smarter.

> flag: idek{the_idea_came_from_a_Vietnamese_high_school_Mathematical_Olympiad_competition_xD_sorry_for_unintended_:sob:_75f492115a34ff4324212e09e24aa5bd}

## Happy ECC - Revenge

```python
from sage.all import *
from Crypto.Util.number import *

# Edited a bit from https://github.com/aszepieniec/hyperelliptic/blob/master/hyperelliptic.sage
class HyperellipticCurveElement:
    def __init__( self, curve, U, V ):
        self.curve = curve
        self.U = U
        self.V = V

    @staticmethod
    def Cantor( curve, U1, V1, U2, V2 ):
        # 1.
        g, a, b = xgcd(U1, U2)   # a*U1 + b*U2 == g
        d, c, h3 = xgcd(g, V1+V2) # c*g + h3*(V1+V2) = d
        h2 = c*b
        h1 = c*a
        # h1 * U1 + h2 * U2 + h3 * (V1+V2) = d = gcd(U1, U2, V1-V2)

        # 2.
        V0 = (U1 * V2 * h1 + U2 * V1 * h2 + (V1*V2 + curve.f) * h3).quo_rem(d)[0]
        R = U1.parent()
        V0 = R(V0)

        # 3.
        U = (U1 * U2).quo_rem(d**2)[0]
        U = R(U)
        V = V0 % U

        while U.degree() > curve.genus:
            # 4.
            U_ = (curve.f - V**2).quo_rem(U)[0]
            U_ = R(U_)
            V_ = (-V).quo_rem(U_)[1]

            # 5.
            U, V = U_.monic(), V_
        # (6.)

        # 7.
        return U, V

    def parent( self ):
        return self.curve

    def __add__( self, other ):
        U, V = HyperellipticCurveElement.Cantor(self.curve, self.U, self.V, other.U, other.V)
        return HyperellipticCurveElement(self.curve, U, V)

    def inverse( self ):
        return HyperellipticCurveElement(self.curve, self.U, -self.V)

    def __rmul__(self, exp):
        R = self.U.parent()
        I = HyperellipticCurveElement(self.curve, R(1), R(0))

        if exp == 0:
            return HyperellipticCurveElement(self.curve, R(1), R(0))
        if exp == 1:
            return self

        acc = I
        Q = self
        while exp:
            if exp & 1:
                acc = acc + Q
            Q = Q + Q
            exp >>= 1
        return acc
    
    def __eq__( self, other ):
        if self.curve == other.curve and self.V == other.V and self.U == other.U:
            return True
        else:
            return False

class HyperellipticCurve_:
    def __init__( self, f ):
        self.R = f.parent()
        self.F = self.R.base_ring()
        self.x = self.R.gen()
        self.f = f
        self.genus = floor((f.degree()-1) / 2)
    
    def identity( self ):
        return HyperellipticCurveElement(self, self.R(1), self.R(0))
    
    def random_element( self ):
        roots = []
        while len(roots) != self.genus:
            xi = self.F.random_element()
            yi2 = self.f(xi)
            if not yi2.is_square():
                continue
            roots.append(xi)
            roots = list(set(roots))
        signs = [ZZ(Integers(2).random_element()) for r in roots]

        U = self.R(1)
        for r in roots:
            U = U * (self.x - r)

        V = self.R(0)
        for i in range(len(roots)):
            y = (-1)**(ZZ(Integers(2).random_element())) * sqrt(self.f(roots[i]))
            lagrange = self.R(1)
            for j in range(len(roots)):
                if j == i:
                    continue
                lagrange = lagrange * (self.x - roots[j])/(roots[i] - roots[j])
            V += y * lagrange

        return HyperellipticCurveElement(self, U, V)
 
p = getPrime(40)
R, x = PolynomialRing(GF(p), 'x').objgen()

f = R.random_element(5).monic()
H = HyperellipticCurve_(f)

print(f"{p = }")
if __name__ == "__main__":
    cnt = 0
    while True:
        print("1. Get random point\n2. Solve the challenge\n3. Exit")
        try:
            opt = int(input("> "))
        except:
            print("❓ Try again."); continue

        if opt == 1:
            if cnt < 3:
                G = H.random_element()
                k = getRandomRange(1, p)
                P = k * G
                print("Here is your point:")
                print(f"{P.U = }")
                print(f"{P.V = }")
                cnt += 1
            else:
                print("You have enough point!")
                continue

        elif opt == 2:
            G = H.random_element()
            print(f"{(G.U, G.V) = }")
            print("Give me the order !")
            odr = int(input(">"))
            if (odr * G).U == 1 and odr > 0:
                print("Congratz! " + open("flag.txt", "r").read())
            else:
                print("Wrong...")
            break

        else:
            print("Farewell.") 
            break
```

### Why revenge ? Again ?

In the older version, we have:
```python
G = H.random_element()
print(f"{(G.U, G.V) = }")
print("Give me the order !")
odr = int(input(">"))
if (odr * G).U == 1:
```
Therefore, just send `odr=0` is enough, and we can easily get flag. Lol I don't know why I cant see this when coding, and that make challenge trivial 🥲.

Here is the flag:
> flag: idek{find_the_order_of_hyperelliptic_curve_is_soooo_hard:((}

### Solution 

#### Recover the curve

We are working with the hyperelliptic curve $y^2 = f(x) \mod p$, where $deg(f) = 5$. The coordinate of each point are in Mumford representation $(u(x), v(x))$, and from the definition of Mumford representation we will have: $$f(x) = v(x)^2 \mod u(x)$$

Therefore, we can use CRT to recover the curve and we are done !

We can recover the curve by another property of Mumford representation, which is the roots of $u(x)$ polynomial are $x$-coordinate of the points in the formal sum in the divisor. And with each root $x_i$, $v(x_i)$ is $y$-coordinate of the points. From this one, we can find the roots and recover each pair $(x_i, y_i)$, and combine together with Lagrange's interpolation to get the curve.

#### Find the order

From [this paper](https://inria.hal.science/inria-00512403/document), we can calculate the order of hyperelliptic curve of genus 2 with the formula: 
$$|\mathcal{J}(\mathbb{F}_p)| = \frac{1}{2}(|\mathcal{C}( \mathbb{F} _ {p^2} )| + |\mathcal{C}(\mathbb{F}_p)|^2) - p$$
which is from the relationship between the cardinalities of the corresponding sets of rational points on the hyperelliptic curve and its Jacobian. We can calculate $|\mathcal{C}( \mathbb{F} _ {p^2} )|$ and $|\mathcal{C}( \mathbb{F} _ {p} )|$ easily in Sagemath with this script:

```python
C = HyperellipticCurve(f)
J = Jacobian(C)
jac = J.point_set()
c1, c2 = C.count_points(2)
N = (c2+c1**2)/2 - p
N = ZZ(N)
```

and $N$ will be the order of the curve based on the paper above.

> flag: idek{find_the_order_of_hyperelliptic_curve_is_soooo_hard_if_its_not_zero:((_75f492115a34ff4324212e09e24aa5bd}

---

If you’ve reached this line, thank you for reading, and I hope you learned something from my write-up!