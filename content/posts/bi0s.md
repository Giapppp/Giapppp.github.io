---
author: "Giap"
title: "bi0sCTF 2024"
date: "2024-02-26"
categories: ["Writeup"]
tags: ["Linear Algebra", "RSA", "Coppersmith", "ECC", "ECDSA", "Dual_EC_DRBG"]
---
Last weekend, I played bi0sCTF with my team @1337%Yogurt. Here is my writeup for all crypto challenges.

My first CTF writeup in 2024!

## lalala

`chall.sage`
```python
from random import randint
from re import search

flag = "bi0sctf{%s}" % f"{randint(2**39, 2**40):x}"

p = random_prime(2**1024)
unknowns = [randint(0, 2**32) for _ in range(10)]
unknowns = [f + i - (i%1000)  for i, f in zip(unknowns, search("{(.*)}", flag).group(1).encode())]

output = []
for _ in range(100):
    aa = [randint(0, 2**1024) for _ in range(1000)]
    bb = [randint(0, 9) for _ in range(1000)]
    cc = [randint(0, 9) for _ in range(1000)]
    output.append(aa)
    output.append(bb)
    output.append(cc)
    output.append(sum([a + unknowns[b]^2 * unknowns[c]^3 for a, b, c in zip(aa, bb, cc)]) % p)

print(f"{p = }")
print(f"{output = }")
```

In this challenge, flag's characters are hidden in $unknowns$ variables, so we need to find it.

Lets take a look at this line:

```py
output.append(sum([a + unknowns[b]^2 * unknowns[c]^3 for a, b, c in zip(aa, bb, cc)]) % p)
```

We can get lots of equations contain only $unknowns_i^2 * unknowns_j^3$ by subtract $a$ from this. Then we will treat $unknowns_i^2 * unknowns_j^3$ as a variable and solve systems of linear equations. After that, we can find $unknown_i$ from $unknowns_i^2 * unknowns_i^3$ by calculate 5th-roots. When we have $unknowns_i$, we can find flag !

```py
from Crypto.Util.number import *
from out import output, p
from tqdm import *

aas = []
bbs = []
ccs = []
ss = []

for i in range(0, 400, 4):
    out = output[i:i+4]
    aa, bb, cc, s = out   
    aas.append(aa)
    bbs.append(bb)
    ccs.append(cc)
    ss.append(s)

remains = [(s - sum(aa)) % p for s, aa in zip(ss, aas)]

#(s[0]^2*s[0]^3, s[0]^2*s[1]^3,..) s[i]^2*s[j]^3, i <= j
mt = []

for bb, cc in zip(bbs, ccs):
    equation = [0 for _ in range(100)]
    for b, c in zip(bb, cc):
        idx = 10 * b + c
        equation[idx] += 1
    mt.append(equation)

from sage.all import *

M = Matrix(mt)
v = vector(remains)

ans = list(M.solve_right(v))

flag = []
for i in range(100):
    try:
        u = ans[i].nth_root(5)
        flag.append(u)
        print(i)
    except:
        continue

print("".join([bytes([c%1000]).decode() for c in flag]))
```

## rr

`chall.py`
```py
from Crypto.Util.number import *
from FLAG import flag
from random import randint

flag = bytes_to_long(flag)
n = ..
rr = ..
ks = [randint(0, rr**(i+1)) for i in range(20)]
c1 = pow(sum(k*flag**i for i, k in enumerate(ks)), (1<<7)-1, n)
c2 = pow(flag, (1<<16)+1, n)
ks = [pow(69, k, rr**(i+2)) for i, k in enumerate(ks)]
print(f"{ks = }")
print(f"{c1 = }")
print(f"{c2 = }")
```



### Recover coefficients

To recover coefficient $coeff_i$, we need to solve this discrete logarithm problem:

$$
69^{coeff_i} = ks_i \mod rr^{i+2}
$$

After google, I found [this link](https://math.stackexchange.com/questions/1863037/discrete-logarithm-modulo-powers-of-a-small-prime) and I will explain what I did

The main idea to solve are the isomormophism

$$\mathbb{Z}^\ast _{p^s} \cong \mathbb{Z}^\ast _{p^{s-1}} \times \mathbb{Z}^\ast _{p-1}$$

and the homomorphism 

$$\theta: \mathbb{Z}^\ast _{p^s} \to \mathbb{Z}^+ _{p^{s-1}}$$

where $\theta(k) = \left[ \frac{k^{(p-1)p^{s-1}} - 1}{p^s} \right] \bmod p^{s-1}$, and note that we compute numerator inside the bracket modulo $p^{2s-1}$

Now, because $coeff_i < rr^{i + 1}$, so we only need to calculate discrele logarithm over $\mathbb{Z}^\ast _{p^{s-1}}$. To compute discrete logarithm, we use the homomorphism $\theta$ and our problem will become

$$coeff_i * \theta(69) = \theta(ks_i) \mod rr^{i+1}$$

And we can find $coeff_i$ easily !

```py
def omega(x, p, e):
    numerator = (pow(x, (p - 1) * p**(e-1), p**(2 * e - 1)) - 1) % p**(2 * e - 1)
    denominator = pow(p, e)
    ans = (numerator // denominator) % p**(e-1)
    return ans

coeffs = []
for i, k in enumerate(ks):
    base = omega(69, rr, i+2)
    target = omega(k, rr, i+2)
    coeff = target * inverse_mod(base, rr**(i + 1)) % rr**(i+1)
    coeffs.append(coeffs)
```

### Finding flag

After recovered all coefficients, now we can construct two polynomials:

$$
f(x) = (\sum_{i=0}^{19}coeff_i * x^i)^{127} - c_1 \mod n \newline
g(x) = x^{65537} - c_2 \mod n
$$

We can see both $f(x)$ and $g(x)$ have the same root $flag$, it means that they have the same factor $(x - flag)$, and we can calculate $GCD(f(x), g(x))$ to get this factor. To speed up, I use half-GCD, which was implemented at [jvdsn's repository](https://github.com/jvdsn/crypto-attacks/blob/master/shared/polynomial.py) 

### Script

```py
from sage.all import *
from Crypto.Util.number import *
from data import n, rr, ks, c1, c2
import sys
sys.path.append("../../../Tools/crypto-attacks") #https://github.com/jvdsn/crypto-attacks
from shared.polynomial import fast_polynomial_gcd
import logging

logging.basicConfig(level=logging.DEBUG)

#https://math.stackexchange.com/questions/1863037/discrete-logarithm-modulo-powers-of-a-small-prime
def omega(x, p, e):
    numerator = (pow(x, (p - 1) * p**(e-1), p**(2 * e - 1)) - 1) % p**(2 * e - 1)
    denominator = pow(p, e)
    ans = (numerator // denominator) % p**(e-1)
    return ans

coeff = []
for i, k in enumerate(ks):
    base = omega(69, rr, i+2)
    target = omega(k, rr, i+2)
    kk = target * inverse_mod(base, rr**(i + 1)) % rr**(i+1)
    coeff.append(kk)

x = PolynomialRing(Zmod(n), 'x').gen()

f1 = 0
for i, k in enumerate(coeff):
    f1 += k*x**i

f1 = f1**127 - c1
f2 = x**65537 - c2
h = fast_polynomial_gcd(f1, f2)
m = -h[0] / h[1]
print(long_to_bytes(int(m)))
```

## Challengename

`chall.py`
```py
from ecdsa.ecdsa import Public_key, Private_key
from ecdsa import ellipticcurve
from hashlib import md5
import random
import os
import json

flag = open("flag", "rb").read()[:-1]

magic = os.urandom(16)

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = ###REDACTED###
b = ###REDACTED###
G = ###REDACTED###

q = G.order()

def bigsur(a,b):
    a,b = [[a,b],[b,a]][len(a) < len(b)]
    return bytes([i ^ j for i,j in zip(a,bytes([int(bin(int(b.hex(),16))[2:].zfill(len(f'{int(a.hex(), 16):b}'))[:len(a) - len(b)] + bin(int(b.hex(),16))[2:].zfill(len(bin(int(a.hex(), 16))[2:]))[:len(bin(int(a.hex(), 16))[2:]) - len(bin(int(b.hex(), 16))[2:])][i:i+8], 2) for i in range(0,len(bin(int(a.hex(), 16))[2:]) - len(bin(int(b.hex(), 16))[2:]),8)]) + b)])

def bytes_to_long(s):
    return int.from_bytes(s, 'big')

def genkeys():
    d = random.randint(1,q-1)
    pubkey = Public_key(G, d*G)
    return pubkey, Private_key(pubkey, d)

def sign(msg,nonce,privkey):
    hsh = md5(msg).digest()
    nunce = md5(bigsur(nonce,magic)).digest()
    sig = privkey.sign(bytes_to_long(hsh), bytes_to_long(nunce))
    return json.dumps({"msg": msg.hex(), "r": hex(sig.r), "s": hex(sig.s)})

def enc(privkey):
    x = int(flag.hex(),16)
    y = pow((x**3 + a*x + b) % p, (p+3)//4, p)
    F = ellipticcurve.Point('--REDACTED--', x, y)
    Q = F * privkey.secret_multiplier
    return (int(Q.x()), int(Q.y()))

pubkey, privkey = genkeys()
print("Public key:",(int(pubkey.point.x()),int(pubkey.point.y())))
print("Encrypted flag:",enc(privkey))

nonces = set()

for _ in '01':
    try:
        msg = bytes.fromhex(input("Message: "))
        nonce = bytes.fromhex(input("Nonce: "))
        if nonce in nonces:
            print("Nonce already used")
            continue
        nonces.add(nonce)
        print(sign(msg,nonce,privkey))
    except ValueError:
        print("No hex?")
        exit()
```

This challenge using ECDSA to sign messages, we are given two points in a hidden curve, and one of them contains information about flag. We can also provide our nonce and messages to sign.

### Recover curve's parameters

Because we have two points $P$ and $Q$, which are public key and multiply of another point in curve $(E)$, we will have two equations with unknown $a, b$:

$$
y_P^2 = x_P^3 + a * x_P + b \mod p \newline
y_Q^2 = x_Q^3 + a * x_Q + b \mod p
$$

Then we can solve system of linear equations to get $a$ and $b$:

### Recover privkey

Note that we can provide `nonce` to server to sign a message, we will find a way to make server use same nonce with different messages. We need to know how server generate `nunce` and use it to sign message

```py
magic = os.urandom(16)

def bigsur(a,b):
    a,b = [[a,b],[b,a]][len(a) < len(b)]
    return bytes([i ^ j for i,j in zip(a,bytes([int(bin(int(b.hex(),16))[2:].zfill(len(f'{int(a.hex(), 16):b}'))[:len(a) - len(b)] + bin(int(b.hex(),16))[2:].zfill(len(bin(int(a.hex(), 16))[2:]))[:len(bin(int(a.hex(), 16))[2:]) - len(bin(int(b.hex(), 16))[2:])][i:i+8], 2) for i in range(0,len(bin(int(a.hex(), 16))[2:]) - len(bin(int(b.hex(), 16))[2:]),8)]) + b)])

...

def sign(msg,nonce,privkey):
    hsh = md5(msg).digest()
    nunce = md5(bigsur(nonce,magic)).digest()
    sig = privkey.sign(bytes_to_long(hsh), bytes_to_long(nunce))
    return json.dumps({"msg": msg.hex(), "r": hex(sig.r), "s": hex(sig.s)})
```

We can see that server provides bytearray `magic` and calculate `nunce` from it. The vulnerable here is the function `bigsur`. If we choose `nonce_1 = b"\x00"` and `nonce_2 = b"\x00\x00"`, we can get the same `nunce` - the nonce that server use to sign a message.

### Recover private key

In ECDSA, if we use the same nonce with different messages, we can recover private key. Specifically, we will have $r_1 = r_2 = R$, where $(r_1, s_1)$ is the signature of message $m_1$, and $(r_2, s_2)$ is the signature of message $m_2$. Now, based on equation to calculate $s$, we have

$$
\begin{aligned}
s_1 * k - H(m_1) &= s_2 * k - H(m_2) ( = R * privkey) \newline
k &= \frac{s_1 - s_2}{H(m_1) - H(m_2)}
\end{aligned}
$$

Then we can calculate $privkey = \frac{s_1 * k - H(m_1)}{R}$

Note that all computation are under modulo $q$, which is the order of the curve

### Find flag

When we have `privkey`, we can easily recover $F$, which is the point that contains flag by calculate `pow(privkey, -1, q) * Q`

```py
from sage.all import *
from Crypto.Util.number import *
from pwn import *
from ast import literal_eval
import json
from hashlib import md5
from ecdsa.curves import NIST256p

p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
target = remote("13.201.224.182", int(30474))
dG = literal_eval(target.recvline().decode()[len("Public key: "):])
fG = literal_eval(target.recvline().decode()[len("Encrypted flag: "):])

dGx, dGy = (99122053878685444817852582103585646482441799670468212049632161370423019963573, 49681263796445807694244738028189208770171168855624587289690892802435841601423)
fGx, fGy = (22455982735997721923198309515515820680837002550923840212531066823876108860098, 49955453626898315794129063911602706078234097783588068635922441060010795905908)

target.sendlineafter(b"Message: ", b"1337")
target.sendlineafter(b"Nonce: ", b"00")
resp1 = json.loads(target.recvline().decode())
msg1, r1, s1 = resp1.values()
h1 = bytes_to_long(md5(bytes.fromhex("1337")).digest())

target.sendlineafter(b"Message: ", b"133700")
target.sendlineafter(b"Nonce: ", b"0000")
resp2 = json.loads(target.recvline().decode())
msg2, r2, s2 = resp2.values()
h2 = bytes_to_long(md5(bytes.fromhex("133700")).digest())


M = Matrix(GF(p), [[dGx, 1], [fGx, 1]])
v = vector(GF(p), [dGy**2 - dGx**3, fGy**2 - fGx**3])

a, b = M.solve_right(v)

assert dGy**2 % p == (dGx**3 + a * dGx + b) % p
assert fGy**2 % p == (fGx**3 + a * fGx + b) % p

E = EllipticCurve(GF(p), [a, b])
n = int(E.order())

k = ((h1 - h2) * pow(s1 - s2, -1, n)) % n

privkey = ((s2 * k - h2) * pow(r2, -1, n)) % n

fG = E(fGx, fGy)
dG = E(dGx, dGy)

privkey_ = pow(privkey, -1, n)
F = privkey_ * fG
print(long_to_bytes(int(F.xy()[0])))
```

## daisy_bell

`chall.py`
```py
from Crypto.Util.number import *
from FLAG import flag

p = getPrime(1024)
q = getPrime(1024)
n = p*q
c = pow(bytes_to_long(flag), 65537, n)

print(f"{n = }")
print(f"{c = }")
print(f"{p>>545 = }")
print(f"{pow(q, -1, p) % 2**955 = }")

"""
n = 13588728652719624755959883276683763133718032506385075564663911572182122683301137849695983901955409352570565954387309667773401321714456342417045969608223003274884588192404087467681912193490842964059556524020070120310323930195454952260589778875740130941386109889075203869687321923491643408665507068588775784988078288075734265698139186318796736818313573197531378070122258446846208696332202140441601055183195303569747035132295102566133393090514109468599210157777972423137199252708312341156832737997619441957665736148319038440282486060886586224131974679312528053652031230440066166198113855072834035367567388441662394921517
c = 7060838742565811829053558838657804279560845154018091084158194272242803343929257245220709122923033772911542382343773476464462744720309804214665483545776864536554160598105614284148492704321209780195710704395654076907393829026429576058565918764797151566768444714762765178980092544794628672937881382544636805227077720169176946129920142293086900071813356620614543192022828873063643117868270870962617888384354361974190741650616048081060091900625145189833527870538922263654770794491259583457490475874562534779132633901804342550348074225239826562480855270209799871618945586788242205776542517623475113537574232969491066289349
p>>545 = 914008410449727213564879221428424249291351166169082040257173225209300987827116859791069006794049057028194309080727806930559540622366140212043574
pow(q, -1, p) % 2**955 = 233711553660002890828408402929574055694919789676036615130193612611783600781851865414087175789069599573385415793271613481055557735270487304894489126945877209821010875514064660591650207399293638328583774864637538897214896592130226433845320032466980448406433179399820207629371214346685408858
"""
```

This is a RSA challenge. In this one, we are given MSB of $p$ and LSB of $u = q^{-1} \mod p$, and we need to factor $n$.

### Construct the equation

$$
\begin{aligned}
u &= q^{-1} \mod p \newline
uq &= 1 + kp \newline
uq^2 &= q + kpq \newline
uq^2 - q &= 0 \mod n
\end{aligned}
$$

From the information we have, we will have bivariate polynomial

$$P(x, y) = (u_{hi} * 2^{955} + u_{low}) * (q_{hi} * 2**545 + q_{low})^2 - (q_{hi} * 2^{545} + q_{low}) = 0 \mod n$$

and we can use bivariate coppersmith to find roots $(q_{low}, u_{hi})$. I use [kiona's implementation](https://github.com/kionactf/coppersmith) to solve.

When we found roots, we can recover $q$, and everything is trivial

```py
from sage.all import *
from Crypto.Util.number import *
import itertools
import sys
sys.path.append("../../../Tools/coppersmith")
from coppersmith_multivariate_heuristic import coppersmith_multivariate_heuristic
from lll import *

lllopt = {'algorithm':FPLLL}

n = 13588728652719624755959883276683763133718032506385075564663911572182122683301137849695983901955409352570565954387309667773401321714456342417045969608223003274884588192404087467681912193490842964059556524020070120310323930195454952260589778875740130941386109889075203869687321923491643408665507068588775784988078288075734265698139186318796736818313573197531378070122258446846208696332202140441601055183195303569747035132295102566133393090514109468599210157777972423137199252708312341156832737997619441957665736148319038440282486060886586224131974679312528053652031230440066166198113855072834035367567388441662394921517
c = 7060838742565811829053558838657804279560845154018091084158194272242803343929257245220709122923033772911542382343773476464462744720309804214665483545776864536554160598105614284148492704321209780195710704395654076907393829026429576058565918764797151566768444714762765178980092544794628672937881382544636805227077720169176946129920142293086900071813356620614543192022828873063643117868270870962617888384354361974190741650616048081060091900625145189833527870538922263654770794491259583457490475874562534779132633901804342550348074225239826562480855270209799871618945586788242205776542517623475113537574232969491066289349

msb_p = 914008410449727213564879221428424249291351166169082040257173225209300987827116859791069006794049057028194309080727806930559540622366140212043574
lsb_u = 233711553660002890828408402929574055694919789676036615130193612611783600781851865414087175789069599573385415793271613481055557735270487304894489126945877209821010875514064660591650207399293638328583774864637538897214896592130226433845320032466980448406433179399820207629371214346685408858
msb_q = (n // (msb_p << 545)) #calculate msb_q * 2**545

x, y = PolynomialRing(Zmod(n), "x, y").gens()

qq = msb_q + x
uu = y * 2**955 + lsb_u
f = uu*qq**2 - qq 

ans = coppersmith_multivariate_heuristic(f, [2**545, 2**68], 1.0, **lllopt)
lsb_q, msb_u = ans[0]

q = int(qq(lsb_q))
p = n // q
d = pow(65537, -1, (p - 1) * (q - 1))
m = pow(c, d, n)
print(long_to_bytes(m))
```

P/s: I also use kiona's implementation to solve campervan. Really surprise that the implementation works in both challenges

## Katyusha’s Campervan

`chall.py`
```py
from Crypto.Util.number import *
from random import randint
from FLAG import flag

p = getPrime(1024)
q = getPrime(1024)
e = getPrime(132)
n = p*q
hint = pow(e, -1, (p-1)*(q-1))
hint %= p-1
hint %= 2**892
c = pow(3, int.from_bytes(flag), n**5) * pow(randint(0, n**5), n**4, n**5) % n**5

print(f"{n = }")
print(f"{e = }")
print(f"{c = }")
print(f"{hint = }")

"""
n = 9722343735487336242847355367175705096672092545117029199851527087227001665095112331406581010290318957921703096325328326862768861459201224096506317060919486835667369908780262880850949861734346363939614200227301344831209845565227637590016962469165064818450385339408084789219460490771570003649248250098125549751883777385917121014908647963900636814694225913533250242569263841750262192296795919177720443516042006972193940464844059718044438878017817432336475087436031866077325402373438547950481634275773767410248698596974769981162966656910136575149455523084473445761780201089182021418781347413453726696240548842411960178397
e = 5323153428600607366474827268153522064873
c = 9128106076400211790302891811252824557365859263295914819806672313027356017879597156259276057232557597614548050742418485365280305524694004426832069896531486671692562462063184624416012268348059935087037828161901243824582067161433586878141008884976330185561348052441637304755454643398179479215116505856245944555306345757777557395022121796068140566220391012921030768420736902592726104037200041403396506760483386523374366225161516294778224985920562226457769686733422726488624795847474711454397538514349555958637417188665977095558680525349235100286527905789576869572972662715040982208185436819557790062517857608731996417066519220133987864808243896151962316613504271341630230274953625158957103434031391582637694278277176886221304131078005240692954168656292222792833722555464070627220306776632641544334188357810067577550784029449834217848676080193960627138929032912578951880151284003878323853182114030012207949896373695734783631698004600675811512726913649141626146115066425891236975554237158682938964099745220780884079884347052906073216530490633243676915134831324804418410566989306886192743687590855529757605789691981493863292029273401139254934543448966341439303948513266699261650278938684067402860913507689842621595391519090227639907684629841162983852454124546030986411283762938101536264676221777904450717178547838152674410566294280937400196290368544481636850750666313771438253636667634601122561235018292316232335633111595474772273810349284893171480302604833719250453453781210093266339454843926482821341993360016434693250661347303203216948599305102121353574445652764255573536572077762409837628479280331295047290459975370026620838169978316921035609492162085052786943829915442906137063599836720584533200385074702683101049336194258783047318183521466098437420153628598968954236332678203275614402446435216223033804260963642393142002417568855964535316709986640977596845897721671783670070696907220894520837335160816494605130683705587464386202643385688263935088026204614056121745160246499509455752793089324629215884008499726564579763845757062068182946721730306128755414268910929410742220199282343421146810430121947827801171056425435942640932150535954546458772114121498557119913825127286832860975814307160175273154886250581960709573672488119996389986116735407178214281982766051391618187878672106737928646489671994503814871652107136752677107398141842179907758909246276653861569864776043204134345135427118784118473462309509988521112691717301811627018054555866015966545532047340607162395739241626423495285835953128906640802690450118128515355353064004001500408400502946613169130088974076348640048144323898309719773358195921400217897006053213222160549929081452233342133235896129215938411225808985658983546168950790935530147276940650250749733176085747359261765601961315474656996860052862883712183817510581189564814317141703276878435707070103680294131643312657511316154324112431403040644741385541670392956841467233434250239028068493523495064777560338358557481051862932373791428839612299758545173203569689546354726917373906408317003812591905738578665930636367780742749804408217333909091324486584514813293
hint = 27203100406560381632094006926903753857553395157680133688133088561775139188704414077278965969307544535945156850786509365882724900390893075998971604081115196824585813017775953048912421386424701714952968924065123981186929525951094688699758239739587719869990140385720389865
"""
```

Another RSA challenge in this competition! We are given LSB of $d_p = d \mod p - 1$ and the flag was encrypted like [Damgard-Jurik cryptosystem](https://en.wikipedia.org/wiki/Damg%C3%A5rd%E2%80%93Jurik_cryptosystem#Encryption)

### Factor n

We have:

$$
\begin{aligned}
d_p &= d \mod p - 1 \newline
e * d_p &= 1 \mod p - 1 \newline
e * d_p &= 1 + k * (p - 1) \newline
e * (d_{hi} * M + d_{low}) &= 1 + k * (p - 1) \newline
e * d_{hi} * M + e * d_{low} &= 1 + k * (p - 1) (1)
\end{aligned}
$$

Let $E = (eM)^{-1} \mod p-1$, then there exists $c \in \mathbb{N}$ such that $E * eM = 1 + cN$, than we can transform $(1)$ to:

$$d_{hi} + E * (ed_{low} + k - 1) = (Ek - cqd_{hi})*p$$

So we can construct a bivariate polynomial:

$$P(x, y) = x + E * (ed_{low} + y - 1) \mod n$$

and our roots will be $$(d_{hi}, k)$$

When we found the roots, we can find factor $p$ of $n$ by calculate $GCD(P(d_{hi}, k), n)$

### How to decrypt ?

When we have $p$, we can calculate private key $d$. Now to decrypt, we will follow [this paper](https://www.brics.dk/RS/00/45/BRICS-RS-00-45.pdf) to decrypt. 

```py
from sage.all import *
from Crypto.Util.number import *
import itertools
sys.path.append("../../../Tools/coppersmith")
from coppersmith_multivariate_heuristic import coppersmith_multivariate_heuristic
from lll import *

lllopt = {'algorithm':FPLLL}

n = 9722343735487336242847355367175705096672092545117029199851527087227001665095112331406581010290318957921703096325328326862768861459201224096506317060919486835667369908780262880850949861734346363939614200227301344831209845565227637590016962469165064818450385339408084789219460490771570003649248250098125549751883777385917121014908647963900636814694225913533250242569263841750262192296795919177720443516042006972193940464844059718044438878017817432336475087436031866077325402373438547950481634275773767410248698596974769981162966656910136575149455523084473445761780201089182021418781347413453726696240548842411960178397
e = 5323153428600607366474827268153522064873
c = 9128106076400211790302891811252824557365859263295914819806672313027356017879597156259276057232557597614548050742418485365280305524694004426832069896531486671692562462063184624416012268348059935087037828161901243824582067161433586878141008884976330185561348052441637304755454643398179479215116505856245944555306345757777557395022121796068140566220391012921030768420736902592726104037200041403396506760483386523374366225161516294778224985920562226457769686733422726488624795847474711454397538514349555958637417188665977095558680525349235100286527905789576869572972662715040982208185436819557790062517857608731996417066519220133987864808243896151962316613504271341630230274953625158957103434031391582637694278277176886221304131078005240692954168656292222792833722555464070627220306776632641544334188357810067577550784029449834217848676080193960627138929032912578951880151284003878323853182114030012207949896373695734783631698004600675811512726913649141626146115066425891236975554237158682938964099745220780884079884347052906073216530490633243676915134831324804418410566989306886192743687590855529757605789691981493863292029273401139254934543448966341439303948513266699261650278938684067402860913507689842621595391519090227639907684629841162983852454124546030986411283762938101536264676221777904450717178547838152674410566294280937400196290368544481636850750666313771438253636667634601122561235018292316232335633111595474772273810349284893171480302604833719250453453781210093266339454843926482821341993360016434693250661347303203216948599305102121353574445652764255573536572077762409837628479280331295047290459975370026620838169978316921035609492162085052786943829915442906137063599836720584533200385074702683101049336194258783047318183521466098437420153628598968954236332678203275614402446435216223033804260963642393142002417568855964535316709986640977596845897721671783670070696907220894520837335160816494605130683705587464386202643385688263935088026204614056121745160246499509455752793089324629215884008499726564579763845757062068182946721730306128755414268910929410742220199282343421146810430121947827801171056425435942640932150535954546458772114121498557119913825127286832860975814307160175273154886250581960709573672488119996389986116735407178214281982766051391618187878672106737928646489671994503814871652107136752677107398141842179907758909246276653861569864776043204134345135427118784118473462309509988521112691717301811627018054555866015966545532047340607162395739241626423495285835953128906640802690450118128515355353064004001500408400502946613169130088974076348640048144323898309719773358195921400217897006053213222160549929081452233342133235896129215938411225808985658983546168950790935530147276940650250749733176085747359261765601961315474656996860052862883712183817510581189564814317141703276878435707070103680294131643312657511316154324112431403040644741385541670392956841467233434250239028068493523495064777560338358557481051862932373791428839612299758545173203569689546354726917373906408317003812591905738578665930636367780742749804408217333909091324486584514813293
hint = 27203100406560381632094006926903753857553395157680133688133088561775139188704414077278965969307544535945156850786509365882724900390893075998971604081115196824585813017775953048912421386424701714952968924065123981186929525951094688699758239739587719869990140385720389865
M = 2**892
E = pow(e * M, -1, n)

x, y = PolynomialRing(Zmod(n), "x, y").gens()
f = x + E * (e * hint + y - 1)


ans = coppersmith_multivariate_heuristic(f, [2**132, e], 1.0, **lllopt)[0]
#ans = (1364278824202792998093019636227517188336, 2238131335516129175817357831521181270929)
d_hi, k = ans

p = GCD(int(f(d_hi, k)), n)
assert n % p == 0
q = n // p
d = lcm(p - 1, q - 1)

#From https://github.com/p4-team/ctf/tree/master/2016-09-09-asis-final/dam
def decrypt(ct, d, n, s):
    ns1 = pow(n, s + 1)
    a = pow(ct, d, ns1)
    i = 0
    for j in range(1, s + 1):
        t1 = ((a % pow(n, j + 1))-1) // n
        t2 = i
        for k in range(2, j + 1):
            i -= 1
            t2 = (t2 * i) % pow(n, j)
            factorial = 1
            factorial = int(gmpy2.factorial(k))
            up = (t2 * pow(n, k - 1))
            down = gmpy2.invert(factorial, pow(n, j))
            t1 = (t1 - up * down) % pow(n, j)
        i = t1
    return i

jmd = decrypt(c, d, n, 5)
jd = decrypt(3, d, n, 5)
print(long_to_bytes((jmd * pow(jd, -1, n**4)) % (n**4)))
```

## * Predictable

A blackbox cryptography challenge! We are not given the source code, we only know this is a [Dual_EC_DRBG](https://en.wikipedia.org/wiki/Dual_EC_DRBG) system to generate random number, and we need to predict the next output.

I couldn't solved this challenge when the competition happened. After competition, I ask the author and know my idea was right, just only my coding issue :((

### Timing attack

The description of this challenge mentioned about [Dual_EC_DRBG backdoor](https://en.wikipedia.org/wiki/Dual_EC_DRBG#Weakness:_a_potential_backdoor). After researched about it, I found that I need to find $d$ such that $P = d * Q$. Because server uses safe curves like secp192k1 or secp256k1, so calculate discrete logarithm is impossible, but a loading part to generate parameter is really suspicious. Sometimes it's long, and sometimes it's not. It reminds me about timing attack.

If we choose option 1 and calculate time between two "\r" appear (We can know it by `recvuntil("\r")` in pwntools library in Python), our result will be ~0.5s or ~3s, and this reminds me to double-and-add algorithm. [This video](https://www.youtube.com/watch?v=oQfBj7YWu_M) explains the algorithm well.

We can guess that server are calculating $P = d * Q$ by double-and-add algorithm, it means that i-th bit of $d$ will be `1` if the time between two "\r" appear is ~3s, otherwises it's `0`

### Dual_EC_DRBG Backdoor

When we have `d`, we can calculate the next output of random generator. This was described at [here](https://www.projectbullrun.org/dual-ec/documents/dual-ec-20150731.pdf) 

### Solve script

This is my solve script after competition end. Thanks @ctfguy to help me fix

Caveat: My code only work when server using secp192k1. For secp256k1, you need to bruteforce 16 bits to get correct x-coordinate.

```py
from sage.all import *
from pwn import *
import time

target = remote("13.201.224.182", int(32553))
target.recvline()
target.sendlineafter(b">", b"1")
target.recvline()

loading = ""
d = ""

while check + 0.7 < 100:
    start = time.time()
    loading = target.recvuntil("\r").decode()
    end = time.time()
    check = float(loading[:-2])
    if "%" in loading:
        t = end - start
        if t > 2:
            d += "1"
        else:
            d += "0"

d = int(d, 2)
p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
K = GF(p)
a = K(0xfffffffffffffffffffffffffffffffefffffffffffffffc)
b = K(0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1)
E = EllipticCurve(K, (a, b))
curve = target.recvline().decode()
if "secp192k1" in curve:
    Px, Py = [int(c) for c in target.recvline().decode()[1:-2].split(",")]
    Qx, Qy = [int(c) for c in target.recvline().decode()[1:-2].split(",")]
    P = E(Px, Py)
    Q = E(Qx, Qy)
    assert P == d * Q
    for _ in range(4):
        target.recvline()
    target.sendline(b"1")
    r = int(target.recvline().decode()[1:-1])
    R = E.lift_x(K(r))
    d_inv = inverse_mod(d, int(P.order()))
    s2 = int((d_inv*R).xy()[0])
    r2 = int((s2*Q).xy()[0])
    print(r2)
    target.interactive()
```

### My dumbest error

Why I can't solve this one ? Turn out, this is about my coding issue. Instead of this one

```py
d = ""
...
t = end - start
if t > 2:
    d += "1"
else:
    d += "0"
```

I code in another way

```py
d = 0
...

t = end - start
if t > 2:
    d *= 2
else:
    d += 1
```

and my code doesn't work because it calculates wrong $d$. How dumb am I :(((