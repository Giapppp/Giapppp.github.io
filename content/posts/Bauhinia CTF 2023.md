---
author: "Giap"
title: "Bauhinia CTF 2023"
date: "2023-08-22"
categories: ["Writeup"]
tags: ["RSA", "Coppersmith", "Lattice", "Discrete Log"]
---
Tuần vừa rồi, mình có chơi giải Bauhinia CTF với team @phis1Ng_. Mình thấy các challenge Crypto được đánh giá cao, với lại nhạc cũng hay nữa :))), mình có làm được một ~~vài~~ challenge về Crypto nên muốn chia sẻ với mọi người

## grhkm's babyRSA

`chall.py`
```python 
from math import gcd
from Crypto.Util.number import getPrime, getRandomNBitInteger, bytes_to_long
from secret import flag

lcm = lambda u, v: u*v//gcd(u, v)

bits = 1024
given = bits // 5
e_bits = bits // 12

mask = (1 << given) - 1

while True:
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    N = p * q

    if N.bit_length() != bits:
        continue

    l = lcm(p - 1, q - 1)
    e = getRandomNBitInteger(e_bits)

    if gcd(e, l) > 1:
        continue

    d = pow(e, -1, l)

    dp = int(d % (p - 1))
    dq = int(d % (q - 1))

    break

l_dp = dp & mask
l_dq = dq & mask

print(f'{N = }')
print(f'{e = }')
print(f'{l_dp = }')
print(f'{l_dq = }')

flag = bytes_to_long(flag)

ct = pow(flag, e, N)
print(f'{ct = }')
```

`output.txt`
```
N = 96446191626393604009054111437713980755082681332020571709789032122186639773874753631630024642568257679734714430483780317122960230235124140242511126339536047435591010087751700582288534654352742251068909342986464462021206713195415006300821397979265537607226612724482984235104418995222711966835565604156795231519
e = 21859725745573183363159471
l_dp = 5170537512721293911585823686902506016823042591640808668431139
l_dq = 2408746727412251844978232811750068549680507130361329347219033
ct = 22853109242583772933543238072263595310890230858387007784810842667331395014960179858797539466440641309211418058958036988227478000761691182791858340813236991362094115499207490244816520864518250964829219489326391061014660200164748055767774506872271950966288147838511905213624426774660425957155313284952800718636
```

Đây là một bài liên quan về RSA-CRT, challenge cho ta LSB của `dp` và `dq` và mục tiêu của ta sẽ là phân tích `n`. Nếu như các bạn không hiểu mục đích của `dp` và `dq` là gì thì có thể đọc qua về [RSA-CRT](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm) 

Bằng một chút osint, mình đã tìm ra một paper liên quan đến bài này: [Factoring with Only a Third of the Secret CRT-Exponents](https://eprint.iacr.org/2022/271.pdf). Mình sẽ giải thích chi tiết hơn về paper này

Ta có các equation sau: $$\begin{align} dp &= h_{dp} * 2^{given} + l_{dp} \newline dq &= h_{dq} * 2^{given} + l_{dp} \end{align} \newline e * dp = k * (p - 1) + 1 \newline e * dq = l * (q - 1) + 1$$

Với $k, l, h_{dp}, h_{dq}$ là các ẩn mà ta chưa biết

Đọc phần 3.2, ta có thể xây dựng được một đa thức 2 biến có nghiệm $(k, l)$ là:

$$\begin{aligned} 
A &= e * (l_{dp} + l_{dq}) - e^2 * l_{dp} * l_{dq} - 1
\end{aligned}$$

và

$$f(x, y) = (N-1)xy - (el_{dq}-1)x - (el_{dp}-1)y + A$$

Với chú ý rằng 2 giá trị $k, l < e$, ta sẽ tìm nghiệm của đa thức này bằng Coppersmith. Các bạn có thể kiếm python script của Coppersmith ở trên mạng khá nhiều. Ở đây, mình sử dụng code của [Defund](https://github.com/defund/coppersmith/blob/master/coppersmith.sage)

`find_k_l.sage`
```python
import itertools
import sys

bits = 1024
given = bits // 5
e_bits = bits // 12

mask = (1 << given) - 1

N = ..
e = ..
l_dp = ..
l_dq = ..
ct = ..

A = e*(l_dp + l_dq) - e**2 * l_dp * l_dq - 1
PR.<x, y> = PolynomialRing(Zmod(e * 2**given), 2)
f = (N-1)*x*y - (e*l_dq-1)*x - (e*l_dp-1)*y + A


def small_roots(f, bounds, m=1, d=None):
	if not d:
		d = f.degree()

	R = f.base_ring()
	N = R.cardinality()
	
	#f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)

	G = Sequence([], f.parent())
	for i in range(m+1):
		base = N^(m-i) * f^i
		for shifts in itertools.product(range(d), repeat=f.nvariables()):
			g = base * prod(map(power, f.variables(), shifts))
			G.append(g)

	B, monomials = G.coefficient_matrix()
	monomials = vector(monomials)

	factors = [monomial(*bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)

	B = B.dense_matrix().LLL()

	B = B.change_ring(QQ)
	for i, factor in enumerate(factors):
		B.rescale_col(i, 1/factor)

	H = Sequence([], f.parent().change_ring(QQ))
	for h in filter(None, B*monomials):
		H.append(h)
		I = H.ideal()
		if I.dimension() == -1:
			H.pop()
		elif I.dimension() == 0:
			roots = []
			for root in I.variety(ring=ZZ):
				root = tuple(R(root[var]) for var in f.variables())
				roots.append(root)
			return roots

	return []

k, l = small_roots(f, (e,e), m=3, d=4)[0]
print(k, l)
```

Ta sẽ tìm được $(k, l) = (12177905682444242771542873, 4277124735150641724212759)$

Theo phần 3.3 của paper, sau khi đã có $k, l$, ta có thể xây dựng một đa thức $g$ trên $Z_N$ có nghiệm là $h_{dp}$:
$$\begin{align} a &= (el_{dp} + k - 1) * (2^{-i}e \mod k*N) \newline g(x) &= x + a \end{align}$$

Ta tiếp tục dùng Coppersmith để tìm nghiệm của $g$, tuy nhiên, không hiểu sao script ở trên không tìm được nghiệm của $g$

Vì thế nên mình đã đọc kĩ hơn paper, và tìm được [script](https://github.com/juliannowakowski/crtrsa-small-e-pke/blob/main/implementation_new_attack.sage) của tác giả cái paper này. Ở đây, tác giả có xây dựng hàm [Coppersmith mở rộng](http://hyperelliptic.org/tanja/teaching/crypto20/20200922-lll.pdf) và nó hiệu quả nên mình đã sử dụng nó với một chút hiệu chỉnh

`find_h_dp.sage`
```py
m_2 = 40 #Parameter for 2nd Lattice
t_2 = 20 #Parameter for 2nd Lattice

k = 12177905682444242771542873
l = 4277124735150641724212759
n = 512
dSize = 512
alpha = 85
Unknown_MSB = 512 - given
LSB_dp = Integer(l_dp)

TWO_POWER = 2^(dSize - Unknown_MSB)

R.<x>=QQ[]


f = (e*(TWO_POWER*x+LSB_dp)-1+k)
IN_k = (e*TWO_POWER).inverse_mod(k*N)

f = x+IN_k*(e*LSB_dp-1+k) # Make f monic by inverting the coefficient of x
X = 2^Unknown_MSB


#Generate shift polynomials and store these polynomials in F. Store monomials of shift polynomials in S 
F = []
S = []
for i in range(m_2+1):
    h = f^i*k^(m_2-i)*N^(max(0,t_2-i))
    F.append(h)
    S.append(x^i)

  
"""
Form a matrix MAT. Entries of MAT are coming from the coefficient 
vector from shift polynomials which are stored in F
""" 

print('2nd lattice dimension', len(F))


MAT = Matrix(ZZ, len(F))

for i in range(len(F)):
   f = F[i]
   f = f(x*X)

   coeffs = (f.coefficients(sparse=False))
   for j in range(len(coeffs), len(F)):
       coeffs.append(0)
   coeffs = vector(coeffs)
   MAT[i] = coeffs


from time import process_time
TIME_Start = process_time()
tt = cputime()
MAT = MAT.LLL()
TIME_Stop = process_time()
print('2nd LLL time', TIME_Stop-TIME_Start)

#Get all polynomial 

A = []
for j in range(len(F)):
  f = 0
  for i in range(len(S)):
    cij = MAT[j,i]
    cij = cij/S[i](X)
    cj = ZZ(cij)
    f = f + cj*S[i]
    A.append(f)    
  else:
    break


for f in A:
    print(f.roots())
```

Ở đây, mình sẽ kiểm tra xem nghiệm $c$ của đa thức nào trong $A$ là $h_{dp}$ bằng cách tính $gcd(g(c), N) = d$. Nếu $d > 1$ thì đó chính là $p$ mà ta cần tìm

Ta tìm được 

$h_{dp} = 180951980763775058492815911873237082514145707000972099423553967985124001563643605807070492022$ 

Từ đó tìm được 

$p = 8351309129105229708154695602362829027250608775685390771007529034429910339403472223935574054850623494610995086524639065024717100915125468017775773884252621$

Khi đã có $p$, mọi chuyện là đơn giản:

`solve.py`
```py
from Crypto.Util.number import *
ct = ..
N = ..
p = ..
q = N // p
e = ..
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
flag = pow(ct, d, N)
print(long_to_bytes(flag))
```
> flag: b6actf{y0u_mu5t_b3_c0nv1nc3d_th4t_lgn/5_is_gr34t3r_th4n_lgn/4_n0w}

## * How to stop time
`chall.py`
```python
# Since the script is simple, I will just add a lot of useless information to
# distract you all. Good luck identifying whether one is a red herring!

# Although I am using the "os" package, I don't call "os.system". Now give up on
# that wacky thoughts.
import os

# I am using the `random` package, which is known to be using MT19937, a
# reversable pseudorandom number generator. Maybe you can make use of them?
import random

# I sometime receive complaints from players regarding installing random Python
# packages all around. I will refrain from using third-party packages for this
# challenge. Hope that helps!
from mathy import is_prime

def main():
    # Please do not submit "flag{this_is_a_fake_flag}" as the flag! This is only
    # a placeholder and this is not the REAL flag for the challenge. Go nc to
    # the actual server for the actual flag!
    flag = os.environ.get('FLAG', 'flag{this_is_a_fake_flag}')

    # "Once is happenstance. Twice is coincidence...
    #  Sixteen times is a recovery of the pseudorandom number generator."
    #                                       - "Maybe Someday" on Google CTF 2022
    #
    # But... How about 256 times? Prediction of pseudorandom number generator?
    for _ in range(256):
        # I will pregenerate those values ahead. Can you read that before
        # sending q?
        g = random.getrandbits(512)
        x = random.getrandbits(512)

        # Yeah, come send me a large-enough prime q!
        q = int(input('[<] q = '))

        # Told you I need a large-enough prime.
        assert q.bit_length() == 512 and is_prime(q)

        # I was going to set "p = 2*q + 1" to make p a safe prime... I will just
        # changing that to "p = 4*q + 1" to pretend that there is a bug. Let's
        # call that a... pseudo-safe prime?
        p = 4*q + 1
        assert is_prime(p)

        print(f'[>] {g = }')

        # I intentionally computes g^x mod p between printing g and h. Good luck
        # unleashing a timing attack!
        h = pow(g, x, p)

        print(f'[>] {h = }')

        # You have to recover me the "x". Quickly.
        _x = int(input('[<] x = '))
        assert x == _x

    # How should I innotate this? Go grab the flag!
    print(f'[*] {flag}')

if __name__ == '__main__':
    try:
        main()
    except:
        print('[!] Well played.')
```

`mathy.py`
```python
# Functions copied from "That-crete log" from UIUCTF 2022. Thanks!

def miller_rabin(bases, n):
    # I don't know how to annotate this because it involves of a bunch of
    # mathematics that I could not understand, but I still want to be verbose.
    # Maybe I should link you the wiki page so you could read that...
    # https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    if n == 2 or n == 3:
        return True

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for b in bases:
        x = pow(b, s, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n-1:
                break
        else:
            return False
    return True

def is_prime(n):
    # bases = [2, 3, 5, 7, 11, 13, 17, 19, 31337] are used by the challenge from
    # UIUCTF. That isn't good enough...
    # I learned from ICPC that those seven bases blocks every number below 2^64.
    bases = [2, 325, 9375, 28178, 450775, 9780504, 1795265022]
    # I will also add a bunch of random bases. Well, I really meant it. This is
    # how I generate those bases:
    #       sorted([random.randint(2, 1000000)*2+1 for _ in range(200)])
    bases += [
          20669,   48929,   57021,   63569,   73307,   86815,   93495,  101303,
         124851,  126617,  164415,  171811,  184653,  219385,  221067,  223499,
         229897,  234477,  251893,  264151,  295599,  299453,  308525,  316135,
         318467,  319081,  326169,  341721,  343699,  351743,  374223,  378375,
         387703,  387807,  390443,  417763,  430031,  438233,  440079,  441259,
         444591,  465613,  475205,  485841,  501341,  509761,  515577,  528775,
         533381,  536401,  558123,  562419,  583397,  606965,  617121,  619821,
         625787,  632805,  650751,  689307,  695181,  695725,  704809,  706557,
         720371,  729335,  737269,  741827,  743969,  745609,  750425,  764843,
         768725,  782945,  789713,  794851,  832829,  849477,  849917,  872481,
         880381,  880601,  882991,  891339,  892581,  897917,  900497,  902791,
         907839,  908069,  910733,  936747,  945849,  952533,  965837,  967739,
        1007573, 1018197, 1022845, 1027277, 1027963, 1044711, 1050091, 1050839,
        1053395, 1060643, 1070551, 1080385, 1087593, 1095565, 1111439, 1141847,
        1146745, 1168487, 1176229, 1180219, 1187279, 1203567, 1204739, 1207205,
        1212905, 1233043, 1252625, 1256889, 1272399, 1298475, 1302085, 1305033,
        1309991, 1325833, 1334399, 1340793, 1355737, 1365593, 1376389, 1381963,
        1390677, 1405539, 1421269, 1426487, 1433469, 1448275, 1458545, 1462879,
        1464553, 1482773, 1486655, 1504839, 1512277, 1517895, 1526807, 1532327,
        1543995, 1545351, 1553127, 1563397, 1572205, 1573891, 1583443, 1595567,
        1603263, 1609551, 1631223, 1633943, 1650589, 1677741, 1681935, 1696649,
        1713355, 1715365, 1730819, 1741045, 1745279, 1751007, 1758715, 1778157,
        1779521, 1785051, 1789451, 1789671, 1790781, 1791763, 1812959, 1823427,
        1824907, 1842549, 1846559, 1847019, 1865431, 1879215, 1895455, 1930981,
        1932295, 1940509, 1957911, 1976957, 1986973, 1992813, 1993333, 1994939
    ]
    # We should be able to find all composite numbers smaller than 65536 with
    # this sieve. Well, we don't do Miller-Rabin for every numbers; or it will
    # be too time-consuming.
    for i in range(2, min(256, n)):
        if n % i == 0:
            return False
    # Although I don't know why they used 256 (instead of 65536) here, I will
    # just stick to that.
    if n < 256:
        return True
    # Now we use Miller-Rabin for the large numbers.
    return miller_rabin(bases, n)
```

Trong bài này, ta được yêu cầu phải tính $log_g(h) \mod p$ 256 lần liên tiếp. Ta được phép nhập số $q$ sao cho `q.bit_length() = 512`, `is_prime(q)` và `is_prime(4*q - 1)`

Trong lúc giải đang diễn ra thì mình không giải được câu này :((. Với việc tác giả có nhắc đến một challenge trong `UIUCTF 2022` nên mình đã làm theo và bị mắc kẹt trong suốt giải

Sau giải, mình mới để ý dòng này ở trong file `mathy.py`
```python
# Although I don't know why they used 256 (instead of 65536) here, I will
# just stick to that.
if n < 256:
    return True
```

và:
```python
# Yeah, come send me a large-enough prime q!
q = int(input('[<] q = '))

# Told you I need a large-enough prime.
assert q.bit_length() == 512 and is_prime(q)
```

trong file `chall.py`

Ta có thể bypass hàm `is_prime()` bằng cách chọn ra số **nguyên** `x < 256`. Server không hề check xem số ta gửi có phải là một số âm không, vì thế ta hoàn toàn có thể chọn một số âm $p = 1 \mod 4$ và hàm `is_prime()` sẽ luôn trả về True. Từ đó, ta có thể tính $q = (p - 1)/4$

Để tính dlog cho đơn giản, ta nên chọn $p$ sao cho $p - 1$ có thể phân tích thành các số nguyên tố nhỏ hơn, và hàm `.log()` trong sage sẽ tính được `x` rất nhanh

Vì mình không làm được trong giải, với lại vừa xong giải thì tác giả gửi writeup luôn nên chắc là mình sẽ lấy [code của tác giả](https://github.com/blackb6a/blackb6a-ctf-2023-challenges/blob/main/01-how-to-stop-time/src/solve.sage) vậy:D

Trong code, tác giả cũng có giải thích cách tìm $p$ nên nếu không hiểu các bạn có thể đọc qua

`solve.sage`
```python
from pwn import *
from tqdm import trange

# context.log_level = 'debug'
# r = process(['python3', 'chall.py'])
r = remote('localhost', 28101)

for i in trange(256):
    log.info(f'=== Round {i+1}/256 ===')

    p = -97523^31
    assert p % 4 == 1
    q = (p - 1) // 4
    r.sendlineafter(b'[<] q = ', str(q).encode())

    r.recvuntil(b'[>] g = ')
    g = int(r.recvline().decode())

    r.recvuntil(b'[>] h = ')
    h = int(r.recvline().decode())

    # Note: p is not a prime!
    Zp = Zmod(p)
    g, h = Zp(g), Zp(h)

    log.info(f'order(g) = {g.multiplicative_order()}')
    log.info(f'2**512   = {2**512}')
    log.info(f'{g = }')
    log.info(f'{h = }')

    x = h.log(g)
    log.info(f'{x = }')
    r.sendlineafter(b'[<] x = ', str(x).encode())

r.interactive()
```

> flag: b6actf{h0w_c4n_y0u_c0mpu73_d109s_s00ooo_qu1ckly}

