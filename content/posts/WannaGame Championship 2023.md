---
author: "Giap"
title: "WannaGame Championship 2023"
date: "2023-12-03"
categories: ["Writeup"]
tags: ["Lattice", "ECC"]
---
# WannaGame Championship 2023

I played __WannaGame Championship 2023__ with my team @1337%_Yogurt and ended up with 8th place. To get a better rank in next year, I should learn more :((. Here is my writeup for 2 challenges i solved in the competition: __cossin__ and __ezcurve__

## Cossin 

In this challenge, we have `ans = sin(flag)*cos(flag)` and `ans` has `1337` bits after decimal point. With a little trigonometry, we will have: 

$$2 * flag + small = arcsin(2*ans) + k * 2\pi$$

(We have $small$ due to floating-point)

Now, we can use LLL to find flag with this basis: $$\begin{bmatrix} \arcsin(2*ans) & 0 & 1 \newline -1 & 1 & 0 \newline \pi & 0 & 0\end{bmatrix}$$

and we should have a vector $v = (small, 2 * flag, 1)$

We also need to make the number bigger to make lattice reduction can produce the vector we want. The matrix i use in this challenge is: $$\begin{bmatrix} [(\arcsin(2*ans))*2^{1200}] & 0 & 2^{480} \newline -2^{1200} & 1 & 0 \newline \pi * 2^{1200}& 0 & 0\end{bmatrix}$$

So we will have a small vector $v = (a, 2 * flag * {a \over b}, b )$ due to scale matrix and we will have flag

`solve.sage`
```python
from Crypto.Util.number import *

RR = RealField(4000)

x = RR("-0.4852...")
ax = asin(RR(2*x))
rpi = RR(pi)
M = Matrix(ZZ, [[(ax * 2**1200).round(), 0, 2**480],
                [-2**1200,   1, 0 ], 
                [(rpi * 2**1200).round(), 0, 0],])
print(M.LLL())
for r in M.LLL().rows(): 
    if r[-1]: 
        flag = int(r[1] * M[0,2] // r[-1])
        print(long_to_bytes(abs(flag)//2))
```

> flag: W1{B4by_m4th_f0r_LLL_0dbb94edb18d7cba7b2bb20f9e}

The idea for this challenge maybe come from [imaginaryCTF 2023 - Tan](https://github.com/maple3142/My-CTF-Challenges/tree/master/ImaginaryCTF%202023/Tan)
And I have a first blood in this challenge <3

## ezcurve

`chall.py`
```python
from sage.all import *
from Crypto.Util.number import bytes_to_long
from secrets import SystemRandom
from secret import flag

class Point:
    def __init__(self, x, y) -> None:
        self.x = int(x)
        self.y = int(y)
    def __str__(self) -> str:
        return f"({self.x},{self.y})"

class Curve:
    def __init__(self) -> None:
        self.generate_parameters()

    def generate_parameters(self) -> None:
        rng = SystemRandom()

        self.p = random_prime(2**512-1, False, 2**511)
        self.k = rng.randint(1, self.p - 1)
        while True:
            x = rng.randint(1, self.p - 1)
            D = (self.k + (1 - self.k)*x**2) % self.p

            if legendre_symbol(D, self.p) == 1:
                r = rng.choice(GF(self.p)(D).nth_root(2, all=True))
                y = (1 + rng.choice([-1, 1])*r) * inverse_mod(x * (self.k - 1), self.p) % self.p
                self.G = Point(x, y)
                break

    def get_parameters(self):
        return self.G, self.k, self.p

    def add(self, P: Point, Q: Point) -> Point:
        x = ((1 + P.x*P.y + Q.x*Q.y)*inverse_mod(P.x*Q.x, self.p) + (1 + self.k)*P.y*Q.y) % self.p
        y = (P.y*(inverse_mod(Q.x, self.p) + Q.y) + (inverse_mod(P.x, self.p) + P.y)*Q.y) % self.p
        # so weirddd :<
        return Point(inverse_mod(x - y, self.p), y)

    def mult(self, G: Point, k: int) -> Point:
        R = Point(1, 0)
        while k:
            if k&1:
                R = self.add(R, G)
            G = self.add(G, G)
            k >>= 1
        return R

curve = Curve()
G, k, p = curve.get_parameters()

print(f"G = {G}")
print(f"k = {k}")
print(f"p = {p}")
print(f"H = {curve.mult(G, bytes_to_long(flag))}")
```

We'll see that the group we are dealing with in the challenge is the set of points on some hyperbola over $\mathbb{F}_p$. When dealing with this kind of challenge, we should know what hyperbola is used, and finding an isomorphism to solve the DLP. In this writeup, I will use operator $*$ instead of `add` to denote the addition, and $.$ instead of `mult` for multiplication

 
### Finding the hyperbola

Now we should look to `generate_parameters` and see how the point $G(x,y)$ is generated. Look at the equation of $y$ and notice that we are working in $\mathbb{F}_p$: 

$$\begin{aligned} D &= k + (1 - k)x^2 \newline y &= {1 + \sqrt{k + (1 - k)x^2} \over x*(k-1)}\end{aligned}$$

($y$ also can be equal to $1 - \sqrt{k + (1 - k)x^2} \over x*(k-1)$, but it doesn't affect too much)

With some algebra, we can lead to the equation: $$(y + {1 \over x})^2 - k*y^2 = 1 \mod p \ (1)$$ 

And this one look like Pell's equation!

### Finding the group order

Working with Pell's equation is a good choice to find the group order. We will call set of all points $G$ that satisfy $(1)$ is $\mathcal{H} \subset \mathbb{F}_p \times \mathbb{F}_p$.

In this challenge, ${k \choose p} = -1$, 
so $\mathcal{H} \cong \mathcal{S}$ where 
$\mathcal{S} \le \mathbb{F}_{p^2}$ 

is the cyclic subgroup of $\mathbb{F}_{p^2}$ of order $p+1$

Let $f(W) = W^2 - k$,     note that ${k \choose p} = -1$ so $f(W)$ is irreducible over $\mathbb{F}_p$. 

Therefore, $\mathbb{F}_{p^2} \cong \mathbb{F}_p[W]/f(W)$. Let $\alpha \in \mathcal{S}$, we will have            $\alpha^{p+1} = 1$ (since $\mathcal{S}$ has order $p + 1$). But we can write $\alpha = r + sW$ for $r, s \in \mathbb{F}_p$. So: $$\begin{aligned} \alpha^{p+1} &= (r + sW)^{p}(r + sW) \newline &= (r^p + s^pW^p)(r + sW) \ \text{(Freshman's Dream)} \newline &= (r - sW)(r+sW) \ \text{(Fermat's little theorem)} \newline &= r^2 - ks^2 \ (W^2 = k)\end{aligned}$$

$(W^p = W * W^{p-1} = W * W^{2 * \frac{p-1}{2}}=W*(-k)^{\frac{p-1}{2}}=-W)$


So, if we take $r = {1 \over x} + y$, $s = y$, we will have $\alpha^{p + 1} = 1 = (y + {1 \over x})^2 - k*y^2$. Therefore, we have the bijection $\varphi:\mathcal{H} \to \mathcal{S}, (x, y) \mapsto (y + {1 \over x}) + yW$. To see that this is an isomorphism, let $(x_1, y_1), (x_2, y_2) \in \mathcal{H}$, then: 

$$\begin{aligned} 
\varphi((x_1, y_1)) * \varphi((x_2, y_2)) &= (y_1 + {1 \over x_1} + y_1W)(y_2 + {1 \over x_2} + y_2W) \newline &= ((y_1 + {1 \over x_1})(y_2 + {1 \over x_2}) + ky_1y_2) + (({1 \over x_1}+y_1)*y_2 + ({1 \over x_2}+y_2)*y_1)W 
\end{aligned}$$

$$\begin{aligned} 
\varphi((x_1, y_1)*(x_2, y_2)) &= \varphi(({1 \over X-Y}, Y)) \newline &= X + YW  \newline &= ((y_1 + {1 \over x_1})(y_2 + {1 \over x_2}) + ky_1y_2) + (({1 \over x_1}+y_1)*y_2 + ({1 \over x_2}+y_2)*y_1)W
\end{aligned}$$


With $X, Y$ are using in `add` function.

So we will have $\varphi((x_1, y_1)*(x_2, y_2)) = \varphi((x_1, y_1)) * \varphi((x_2, y_2))$.


Therefore $\varphi$ is isomorphism, and we have $\mathcal{H} \cong \mathcal{S}$.

### Solving DLP

We can convert from solving DLP over $\mathcal{H}: H = flag.G$ to solving DLP over $\mathcal{S}: \varphi(H) = \varphi(G)^{flag} \mod p+1$. In this challenge, $p+1$ is smooth, so we can use Pohlig-Hellman algorithm and BSGS to get the flag. The script takes about
5 minutes to run

`solve.sage`
```python
from Crypto.Util.number import *
from sage.all import *
from tqdm import tqdm

G = (1607839310176493294577353252762003557221546105757870506381340801134253239376966744205427298664590763576740881572639607384799487951979779696144987477886421,1546749547518777239980509968598193601633396498557542394168100420202891576769741394183857889526837213932582824502124357549905169585573747409557599621838564)
k = 175806172363518431677991045199437670764180356876889297661164788697180717989119773022617665480637013518977586886854217110565695010685506018921813356910662
p = 5338840643981528656349879965316693353037572951085003676090767888721759017683550934207418173641013210787674901617992492337769850068363888321691530955051293
H = (552851895574391510222065278797325133695471300278396325740646639459534389667059010831628455078831526160904926692351570571639949524130986399437322683710262,695603652246255799710910441634342904537480443249396978184960366135064878749959654747187361028053230898467803441940859671759866661306050316241278578859544)

assert legendre_symbol(k, p) == -1

F.<x> = GF(p)[]
R.<W> = GF(p**2, modulus=x**2-k)

def convert(G): #Isomorphism
    x, y = G
    r = (y + inverse_mod(x, p)) % p
    s = y % p
    return (r - s * W)

g = convert(G)
ng = convert(H)

primes_list = list(factor(p+1))

#Because flag is always odd
dlogs = [1]
mods = [2]

def bsgs(g, h, p):
    N = ceil(sqrt(p))
    tbl = {g**i:i for i in range(N)}
    c = g**(N * (p-1))
    for j in range(N):
        y = h * c**j
        if y in tbl:
            return j * N + tbl[y]

for prime, _ in primes_list[1:]:
    t = (p + 1)//prime
    gg = g**t
    ngg = ng**t
    dlog = bsgs(gg, ngg, prime)
    print(dlog, prime)
    dlogs.append(dlog)
    mods.append(prime)

from functools import reduce
def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * inverse_mod(p, n_i) * p
    return sum % prod

flag = chinese_remainder(mods, dlogs)
print(long_to_bytes(flag))
```

>flag: W1{P3ll_Curv3_1s_fun_r1ght?_532e3a90d802f4a3e3ce25b5f72d93d4}

**P/s.** This challenge took me nearly 12 hours to solve :((

![Image alt](https://raw.githubusercontent.com/Giapppp/Giapppp.github.io/main/static/images/wgc2023/wgc2023_1.png)

And it isn't a game.