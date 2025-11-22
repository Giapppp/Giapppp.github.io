---
author: "Giap"
title: "TJCTF 2023 - Keysmith"
date: "2023-05-28"
categories: ["Writeup"]
tags: ["RSA", "Discrete Log"]
---
**TL; DR:** We can generate smooth-prime p and choose q = 3; and then solve the d-log problem to find e:
$$ msg^e = s \ (mod\ p * q) $$
## Keysmith
> I lost my key... can you find it?
nc tjc.tf 31103

**Category:** Cryptography


### 1. First glance
```python
#!/usr/local/bin/python3.10 -u
from Crypto.Util.number import getPrime
flag = open("flag.txt", "r").read()

po = getPrime(512)
qo = getPrime(512)
no = po * qo
eo = 65537

msg = 762408622718930247757588326597223097891551978575999925580833
s = pow(msg,eo,no)

print(msg,"\n",s)

try:
    p = int(input("P:"))
    q = int(input("Q:"))
    e = int(input("E:"))
except:
    print("Sorry! That's incorrect!")
    exit(0)

n = p * q
d = pow(e, -1, (p-1)*(q-1))
enc = pow(msg, e, n)
dec = pow(s, d, n)
if enc == s and dec == msg:
    print(flag)
else:
    print("Not my keys :(")
```

This challenge using RSA cryptographic scheme, and we are given msg and s each time we connect to server. Our goal is to find another p, q and e which satisfy $msg^e = s \ (mod \ p * q)$

### 2. Dlog problem
With given msg and s, we can't find modulo n, so we need to find another way to solve this challenge. Fortunately, we can give our p, q and e, and I think convert it to a discrete logarithm problem to find e will be a good approach.

To solve a dlog problem, we have some popular way like [BSGS](https://en.wikipedia.org/wiki/Baby-step_giant-step), [Pollard p-1 theorem](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm) or [Pohlig-Hellman](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm). Because p is a big prime number, so BSGS isn't a good choice. I choose Pohlig-Hellman in this challenge, and to use this way, we need p-1 is smooth number

### 3. Generate smooth prime
```python
from Crypto.Util.number import *
import gmpy2
import random
original_P = getPrime(1024)

primes = [2]
for i in range(1000):
    primes.append(int(gmpy2.next_prime(primes[-1])))
primes=primes[100:]  #keep just big primes

# generate a weak prime (P) such that P>original_P
while True:
    N = 2
    factors=[]
    while (N<original_P):  
        prime=random.choice(primes)
        if prime not in factors:
            factors.append(prime)
            N*=prime
    if gmpy2.is_prime(N+1):
        break
P=N+1  
print(P)
```

After using above script, I found $p =186568598167193943150281947234168669596704325205505209777649543618597641044067064505029420823614201204893878223541219243439921202321026283084690808922606812050293056628966983533373688918552403630496105017229792051753611307092746707247441926556199861172063152250642647282842168483517111867342214536507807550207$ which is bigger than $s$, to ensure that $s \ mod \ p = s$. And then I choose $q = 3$ because I want $(p - 1) * (q - 1)$ can be factor in fastest time.

### 4. Finally
When we have $p$ and $q$, we just need to connect to server, get $s$ and $msg$ and solve the dlog problem:
$$ msg^e = s (mod\ p * q) $$
After found $e$, we will give it to server and get flag!
```python
from pwn import *

target = remote("http://tjc.tf", int(31103))
msg = Integer(int(target.recvline().decode()))
s = Integer(int(target.recvline().decode()))

p = Integer(186568598167193943150281947234168669596704325205505209777649543618597641044067064505029420823614201204893878223541219243439921202321026283084690808922606812050293056628966983533373688918552403630496105017229792051753611307092746707247441926556199861172063152250642647282842168483517111867342214536507807550207)

q = 3

target.sendlineafter(b":", str(p).encode())
target.sendlineafter(b":", str(q).encode())

n = p * q
K = Zmod(n)

msg = K(msg)
s = K(s)
e = s.log(msg)
print(e)
target.sendlineafter(b":", str(e).encode())
print(target.recvline().decode())
print(target.recvline().decode())
```
