---
author: "Giap"
title: "MiniCTF 22/7"
date: "2023-07-22"
categories: ["Writeup"]
tags: ["AES", "RSA"]
---
Mình xin trình bày một số bài mà mình làm được trong minictf tối 22/7 vừa qua

# Cryptography

## Flipping Login

`server.py`
```py
#!/usr/bin/env python3

import json
import os
import signal
from base64 import b64decode, b64encode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secret import flag

key = os.urandom(32)


def menu_choice() -> str:
    print(
        """Valid choices:
    1. Login
    2. Register
    3. Quit"""
    )
    return input(">> ").strip()


def handler(_signum, _frame):
    print("Time out!")
    exit(0)


def encrypt(msg):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return iv+cipher.encrypt(pad(msg, 16))


def decrypt(iv, msg):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(msg), 16)


def login():
    enc_token = b64decode(input("Login token: ").strip())
    token = decrypt(enc_token[:16], enc_token[16:])
    token = json.loads(token)
    return token['name'], token['admin']


def register():
    name = input("Nickname: ").strip()
    token = {
        "admin": False,
        "name": name
    }
    token = json.dumps(token).encode()
    enc_token = b64encode(encrypt(token)).decode()
    print("Here is your login token: " + enc_token)


def main():
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(60)
    name = 'N.A'
    is_admin = False
    print("Welcome to my under-development program. Who are you?")
    while True:
        choice = menu_choice()
        match choice:
            case '1':
                name, is_admin = login()
                break
            case '2':
                register()
                print('')
            case '3':
                print("Bye bye!")
                break
            case _:
                print("??????????????")
                raise RuntimeError("I found a hacker")
    if is_admin:
        print(f"Hello {name}! Here is your secret: " + flag)
    else:
        print(f"Hello {name}! Sorry, only admin can read my secret!")


try:
    main()
except Exception as E:
    print(str(E))

```
Trong bài này, một json token được mã hõa bằng phương thức AES-CBC với "admin": False. Ta cần phải tìm cách thay đổi sao cho "admin": True

Với tiêu đề bài đã gợi ý cho ta sử dụng Bits Flipping Attack trong AES-CBC, mình đã search trên google và tìm được một [tài liệu](https://tsublogs.wordpress.com/2015/07/18/bit-flipping-attack-on-cbc-mode/) liên quan đến nó. Chi tiết về cách tấn công thì các bạn có thể đọc trên link mình vừa gửi, nhưng mình có thể tóm gọn lại như sau:

Ta có công thức để mã hóa trong AES - CBC là:
$$\begin{aligned} C_0 &= E(P_0) \oplus IV \\ C_i &= E(P_i) \oplus C_{i-1} \ {với \ i > 0} \end{aligned}$$
Và công thức để giải mã là:
$$\begin{aligned} P_0 &= D(C_0) \oplus IV \\ P_i &= D(C_i) \oplus P_{i-1} \ {với \ i > 0} \end{aligned}$$

Như vậy, khi mã hóa cũng như giải mã, nó sẽ xor với ciphertext block / plaintext block trước đó (hoặc $IV$). Chính vì vậy, ta có thể thay đổi nội dung của block để có thể tạo ra nội dung theo ý muốn

Ở trong bài này, vị trí của '"admin": False, ' nằm đủ 1 block thứ hai nên ta sẽ chỉnh block thứ nhất là $IV$ để khi mà xor với block thứ hai sẽ có được '"admin": True , '. Các bạn có thể hiểu như thế này:
$$\begin{aligned}IV \oplus D(C_1) &= '"admin": False, ' \\ IV_{fake} \oplus D(C_1) &= '"admin": True , ' \\ IV_{fake} &= IV \oplus '"admin": False, ' \oplus '"admin": True , ' \end{aligned}$$
Sau khi có được $IV_{fake}$, ta chỉ cần gửi cho server $IV_{fake}+token[16:]$ (Token là thứ ta nhận được sau khi register, 16 bytes đầu của nó là IV) và sẽ có flag

Phần code chính:

`solve.py`
```py
from pwn import *
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import *

token = input() #Sau khi register ở server sẽ có một cái login token, bạn sẽ nhập nó ở đây
token = b64decode(token)

iv = token[:16]
s = token[16:]
plaintext = b'"admin": False, '
target    = b'"admin": True,, '
new_iv = bytes([x ^ y ^ z for (x, y, z) in zip(iv, plaintext, target)])

print(b64encode(new_iv+s)) #Gửi cái này lại cho server là được
```
> **Flag:** W1{CBC_bit_flipping_attack_can_flip_your_system_https://tsublogs.wordpress.com/2015/07/18/bit-flipping-attack-on-cbc-mode}

Đúng cái mình search ban đầu luôn :)))

## Anti Pollard p-1

`chall.py`
```py
from math import prod
from Crypto.Util.number import *
from secret import flag, init
import os

assert isPrime(init) and 2**20 < init < 2**24
e = 0x10001
DEBUG = os.getenv("DEBUG", False)


def gen_smooth(init: int, bits: int, smoothness: int = 16) -> int:
    q = 2*init
    k = (bits - q.bit_length())//smoothness + 1
    while True:
        p = q * prod(getPrime(smoothness) for _ in range(k))
        if GCD(e, p) == 1 and isPrime(p + 1):
            return p + 1


p = gen_smooth(init, 768, 20)
q = gen_smooth(init, 768, 20)
N = p*q
pt = bytes_to_long(flag)
ct = pow(pt, e, N)
print(f"{e = }")
print(f"{N = }")
print(f"{ct = }")
if DEBUG:
    print(f"{p = }")
    print(f"{q = }")
```

Trong bài này, $p-1$ và $q-1$ đều là tích của các số nguyên tố nhỏ hơn 20 bits, vì vậy ta có thể nghĩ đến thuật toán [Pollard p-1](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm). Lưu ý rằng đối với bài này, ta sẽ không tính tích từ 1 đến $2^{20}$ mà sẽ shuffle lên rồi sau đó nhân lại dần. 

Code để tìm $p$:
```py
import gmpy2
from tqdm import tqdm
import random

n = gmpy2.mpz(N)

ar = list(range(2, 2**20))
random.shuffle(ar)
a = gmpy2.mpz(2)
for p in tqdm(ar):
    a = gmpy2.powmod(a, 4 * init * init * p, n)
    p = gmpy2.gcd(a - 1, n)
    if 1 < p < n:
        print(p)
        break

#p = 2782649911045466726583702468234636496093912422560611231304084465742455791597284396733219895856691138873818553244424989101233983426332838798108072186621785877449683943964193663359691028105593053522429899787764095292535702906703651599
```

Sau khi đã có $p$, mọi chuyện còn lại là đơn giản:

`solve.py`

```py
from Crypto.Util.number import *
from sage.all import *

e = 65537
N = ..
ct = ..
p = ..
q = N // p
phi = (p -1) * (q - 1)
d = pow(e, -1, phi)
m = pow(ct, d, N)
print(long_to_bytes(m))
```
>**flag:** W1{tricked_Pollard_p-1_attack_7270278554bb1eebf73197e4c88099d9f636e1626a6fa124f6ae411bf171dd76}

## Weird Primes
`chall.py`

```py
import os

from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, isPrime, inverse
from Crypto.Cipher import PKCS1_OAEP
from random import choices
from math import ceil

DEBUG = os.getenv("DEBUG", False)
digits = list("0123456789")
flag = b"W1{??????????????????????????????????}"
def getWeirdPrime(bit_length: int) -> int:
    ndigits = ceil(bit_length/8)
    while True:
        p = ''.join(choices(digits, k=ndigits))
        if isPrime(bytes_to_long(p.encode())):
            return bytes_to_long(p.encode())

p = getWeirdPrime(1024)
q = getWeirdPrime(1024)
e = 0x10001
n = p*q
d = inverse(e, (p-1)*(q-1))
key = RSA.construct((n, e, d, p, q))
cipher = PKCS1_OAEP.new(key)
enc_flag = cipher.encrypt(flag).hex()
assert cipher.decrypt(bytes.fromhex(enc_flag)) == flag
print(f"{n = }")
print(f"{e = }")
print(f"{enc_flag = }")
if DEBUG:
    print(f"{p = }")
    print(f"{q = }")
```

Trong bài này, $p$ và $q$ là các số nguyên tố sao cho `long_to_bytes(p)` và `long_to_bytes(q)` đều chỉ có các kí tự số từ 0-9. Chính vì vậy, ta sẽ bruteforce dần các chữ số của `long_to_bytes(p)` và `long_to_bytes(q)` cho đến khi tìm được 2 số thỏa mãn, do chỉ có 128 bytes nên thời gian bruteforce sẽ rất nhanh:

`solve.py`
```py
n = ..
e = 65537
enc_flag = ..

from Crypto.PublicKey import RSA
from Crypto.Util.number import *
from Crypto.Cipher import PKCS1_OAEP
from random import choices
from math import ceil

digits = b'0123456789'
p = ''
q = ''
tempp = 0
tempq = 0

p = '' 
q = ''
for step in range(128):
    mod = 2**(8*step)
    for dp in digits:
        for dq in digits:
            testp = bytes_to_long(p.encode()) + dp*mod
            testq = bytes_to_long(q.encode()) + dq*mod
            if (testp * testq)%(mod*256) == n%(mod*256):
                p = long_to_bytes(dp).decode() + p
                q = long_to_bytes(dq).decode() + q
            else:
                testp -= dp*mod
                testq -= dq*mod
                
pp = bytes_to_long(p.encode())
qq = bytes_to_long(q.encode())
d = inverse(65537, (pp-1)*(qq-1))
key = RSA.construct((n, e, d, pp, qq))
cipher = PKCS1_OAEP.new(key)
#enc_flag = cipher.encrypt(flag).hex()
print(cipher.decrypt(bytes.fromhex(enc_flag)))
```
> **flag:** W1{branch_and_prune_is_sometime_very_useful!!!!}
