---
title: "Square Attack"
date: 2024-04-22
description: Square Attack on reduced-round AES, with examples for four and five rounds.
categories: ["Learning"]
tags: ["Cryptography", "AES"]
language: "Vietnamese"
---

Square Attack on reduced-round AES, with examples for four and five rounds.
<!--more-->

# Week 1: Square Attack

Square Attack là một kĩ thuật tấn công đối với Block Cipher khi khai thác vào các tính chất không đổi của các round encryption trong cipher đó. Kĩ thuật này được phát hiện lần đầu tiên đối với [Square Cipher](http://cse.iitkgp.ac.in/~debdeep/courses_iitkgp/Crypto/papers/square.pdf). Trong bài viết này, mình sẽ tập trung vào việc khai thác AES 4 round và giải một số bài liên quan đến kĩ thuật này. Ngoài ra, ta cũng sẽ thảo luận về áp dụng Square Attack cho 5 round AES

## Tài liệu

https://www.davidwong.fr/blockbreakers/square.html

## Chi tiết

### AES 3 round

Kí hiệu __$\varLambda$-set__ là tập hợp các bytearray phân biệt có độ dài 16 và khác nhau tại vị trí `idx`, được gọi là __active index__. Các active index này sẽ nhận toàn bộ các giá trị từ 0 đến 255 trong $\varLambda$-set. Lưu ý rằng $\varLambda$-set có thể có nhiều active index

Xét trường hợp $\varLambda$-set của chúng ta chỉ có 1 active index, giả sử `idx = 0`, ta sẽ phân tích output của từng phần tử khi trải qua các bước trong AES, gồm **SubBytes**, **ShiftRows**, **MixColumns** và **AddRoundKey**

- **AddRoundKey**

![image](/images/square-attack/square-attack_1.png)

Sau khi tất cả các phần tử trong $\varLambda$-set thực hiện bước này, ta vẫn sẽ thu được $\varLambda$-set với active index bằng 0

- **SubBytes**

![image](/images/square-attack/square-attack_2.png)

Do với mỗi giá trị `i` thì `SBOX[i]` sẽ có một giá trị duy nhất nên khi thực hiện bước này, các non-active index vẫn sẽ là các non-active index, còn các active index vẫn không thay đổi, chính vì vậy, ta vẫn sẽ thu được $\varLambda$-set

- **ShiftRow**

![image](/images/square-attack/square-attack_3.png)

Với bước này, các byte chỉ đổi chỗ cho nhau, vì thế ta vẫn sẽ thu được $\varLambda$-set (có thể với index không như trước do bị đổi chỗ, nhưng về bản chất vẫn là $\varLambda$-set)

- **MixColumns**

![image](/images/square-attack/square-attack_4.png)

Với bước này, ta cần nhắc lại cách mà hàm MixColumns hoạt động: Ta có thể tính được column sau khi biến đổi bằng công thức 

$$\begin{bmatrix}d_{0}\\d_{1}\\d_{2}\\d_{3}\end{bmatrix} =\begin{bmatrix}2&3&1&1\\1&2&3&1\\1&1&2&3\\3&1&1&2\end{bmatrix}\begin{bmatrix}b_{0}\\b_{1}\\b_{2}\\b_{3}\end{bmatrix}$$

Vì thế, với 1 bytes thay đổi, ta có thể gây ảnh hưởng đến 3 bytes còn lại trong cột đó. 

Sau bước này, ta sẽ có thêm 3 active index, do mỗi byte trong kết quả thu được là tổ hợp tuyến tính giữa 4 byte, gồm 3 byte cố định và 1 byte thay đổi. Ví dụ như $$d_0 = 2b_0 + 3b_1 + b_2 + b_3$$

Nếu ta cho $b_0$ chạy từ 0 đến 255, do các giá trị $b_1, b_2, b_3$ cố định nên $d_0$ cũng sẽ chạy từ 0 đến 255. Tương tự với $d_1, d_2, d_3$

Vậy qua 1 round, từ 1 active index, ta sẽ thu được $\varLambda$-set có 4 active index. Bây giờ, ta sẽ cho $\varLambda$-set chạy qua 3 round.

![image](/images/square-attack/square-attack_5.png)

Khi xong round thứ 3, ta không còn thu được $\varLambda$-set nữa. Nhưng ta có thể suy ra một tính chất như sau: Ta xor toàn bộ byte đầu của các phần tử sau khi trải qua bước __AddRoundKey__, ta sẽ có 

$$\begin{aligned} S_0 &= b_0 \oplus b_1 \oplus ... \oplus b_{255} \\ &= (2 a_{0, 0} \oplus 3 a_{0, 1} \oplus 1 a_{0, 2} \oplus 1 a_{0, 3}) \oplus (2 a_{1, 0} \oplus 3 a_{1, 1} \oplus 1 a_{1, 2} \oplus 1 a_{1, 3}) \oplus ...\oplus (2 a_{255, 0} \oplus 3 a_{255, 1} \oplus 1 a_{255, 2} \oplus 1 a_{255, 3}) \\ &= 2 (a_{0,0} \oplus .. \oplus a_{255, 0}) + 3(a_{0,1} \oplus .. \oplus a_{255, 1}) + 1 (a_{0,2} \oplus .. \oplus a_{255, 2}) + 1 (a_{0,3} \oplus .. \oplus a_{255, 3}) \\ &= 0\end{aligned}$$

Lưu ý rằng không chỉ byte đầu, mà toàn bộ các byte còn lại cũng sẽ có tính chất này. Ta gọi tính chất này là (*) và sẽ sử dụng nó để break AES 4 round.


### AES 4 Round

Ta hãy xem qua các bước của AES 4 round:

![image](/images/square-attack/square-attack_6.png)

Với tính chất thu được ở trên, ta có thể tìm được 1 byte ở vị trí `i` của roundKey thứ 4 bằng chiến thuật sau:

1. Generate $\varLambda$-set với active index là `i`, sau đó encrypt toàn bộ các phần tử trong set. Ta gọi tập các phần tử nhận được là **enc-$\varLambda$-set**

2. Đoán `roundKey[4][i] = guess` là một giá trị từ 0-255

3. Với mỗi `ciphertext` trong **enc-$\varLambda$-set**, ta sẽ thay đổi `ciphertext[i] = ciphertext[i] ^ roundKey[i]`. Sau đó, `ciphertext` mới của chúng ta sẽ đi qua 2 bước là `InvShiftRows` và `InvSubBytes`. Ta gọi tập các phần tử nhận được lúc này là **enc2-$\varLambda$-set**

4. Kiểm tra xem **enc2-$\varLambda$-set** của chúng ta có thỏa mãn tính chất (*) hay không. Nếu có, `guess` có thể chính là giá trị ta đang cần tìm.

5. Nếu có nhiều giá trị `guess` thỏa mãn, ta nên regenerate $\varLambda$-set cho đến khi chỉ tìm được duy nhất 1 giá trị thỏa mãn

Từ đó, ta có thể tìm được roundKey thứ 4 của Cipher, và có thể reverse được Key mà Cipher đang sử dụng.


### Ví dụ

#### aes4round1

`chall.py`
```python
import miniAES
import os,sys

FLAG = b"W1{test_e3d27b80b9a6595adc655c8518c4c0fd}"

print('''
=============================================================
|              Welcome to miniAES system!!!                 |
=============================================================
''')

key = os.urandom(16)

try:
    while True:
        pt = input("[-] plaintext(hex): ")
        if pt == '':
            break
        pt = bytes.fromhex(pt)
        ct = miniAES.encrypt(pt, key)
        print("[+] ciphertext(hex): %s" % ct.hex())
    guess = input("key(hex): ")
    if guess == key.hex():
        print("!!! %s\n" % FLAG.decode())
    else:
        print("???\n")
    sys.exit(0)
except:
    sys.exit(0)
```

(`miniAES` chỉ là cài đặt lại AES, vì thế mình sẽ không đề cập đến)

Đối với bài này, ta chỉ cần áp dụng lí thuyết mà mình đã đề cập ở trên.

Một số lưu ý với code của mình:

- Các bạn có thể download lib `aeskeyschedule` tại [đây](https://github.com/fanosta/aeskeyschedule)
- Ở đây, ta có thể thực hiện `A_set_dec ^= InvS_box[ele[idx] ^ i]` thay vì chạy tuần tự các bước trên do ta chỉ quan tâm đến giá trị chứ không quan tâm đến vị trí, vậy nên tính `A_set_dec` như vậy là đủ.


`solve.py`
```python
from pwn import *
from tqdm import *
import os
from miniAES import *
from aeskeyschedule import reverse_key_schedule

target = process(["python3", "chall.py"])

def encrypt(pt:bytes):
    target.sendlineafter(b"[-] plaintext(hex): ", pt.hex().encode())
    ct = target.recvline()[:-1][len("[+] ciphertext(hex): "):].decode()
    return bytes.fromhex(ct)

def find_key_bytes(idx:int):
    real_ans = set(list(range(256)))
    key_pos = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
    while True:
        ans = set()
        A_set = []
        init = os.urandom(16)
        for i in range(256):
            temp = bytearray(init)
            temp[idx] = i
            A_set += [encrypt(temp)]
        
        for i in range(256):
            A_set_dec = 0
            for ele in A_set:
                # temp = bytearray(ele)
                # temp[idx] ^= i
                # ele_dec_arr = list(temp)
                # InvShiftRows(ele_dec_arr)
                # InvSubBytes(ele_dec_arr)
                # A_set_dec ^= ele_dec_arr[key_pos[idx]]
                A_set_dec ^= InvS_box[ele[idx] ^ i]
            if A_set_dec == 0:
                ans.add(i)
        real_ans.intersection_update(ans)
        if len(real_ans) == 1:
            return real_ans.pop()

key = []
for i in tqdm(range(16)):
    ans = find_key_bytes(i)
    key.append(ans)

hexkey = reverse_key_schedule(bytes(key), 4).hex()
target.sendline(b"")
target.sendlineafter(b"key(hex): ", hexkey.encode())
print(hexkey)
target.interactive()
```

#### aes4rounds2

`main.py`
```python
from spiral import Spiral
from secret import flag
from os import urandom

menu = """Options:
1. Get encrypted flag
2. Encrypt message"""
key = urandom(16)
cipher = Spiral(key, rounds=4)


def main():
    print(menu)
    while True:
        try:
            option = int(input(">>> "))
            if option == 1:
                ciphertext = cipher.encrypt(flag)
                print(ciphertext.hex())
            elif option == 2:
                plaintext = bytes.fromhex(input())
                ciphertext = cipher.encrypt(plaintext)
                print(ciphertext.hex())
            else:
                print("Please select a valid option")

        except Exception:
            print("Something went wrong, please try again.")


if __name__ == "__main__":
    main()
```

`spiral.py`
```python
from utils import *

class Spiral:
    def __init__(self, key, rounds=4):
        self.rounds = rounds
        self.keys = [bytes2matrix(key)]
        self.BLOCK_SIZE = 16

        for i in range(rounds):
            self.keys.append(spiralLeft(self.keys[-1]))

    def encrypt(self, plaintext):
        if len(plaintext) % self.BLOCK_SIZE != 0:
            padding = self.BLOCK_SIZE - len(plaintext) % self.BLOCK_SIZE
            plaintext += bytes([padding] * padding)

        ciphertext = b""
        for i in range(0, len(plaintext), 16):
            ciphertext += self.encrypt_block(plaintext[i : i + 16])
        return ciphertext

    def encrypt_block(self, plaintext):
        self.state = bytes2matrix(plaintext)
        self.add_key(0)

        for i in range(1, self.rounds):
            self.substitute()
            self.rotate()
            self.mix()
            self.add_key(i)

        self.substitute()
        self.rotate()
        self.add_key(self.rounds)

        return matrix2bytes(self.state)

    def add_key(self, idx):
        for i in range(4):
            for j in range(4):
                self.state[i][j] = (self.state[i][j] + self.keys[idx][i][j]) % 255

    def substitute(self):
        for i in range(4):
            for j in range(4):
                self.state[i][j] = SBOX[self.state[i][j]]

    def rotate(self):
        self.state = spiralRight(self.state)

    def mix(self):
        out = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                for k in range(4):
                    out[i][j] += SPIRAL[i][k] * self.state[k][j]
                out[i][j] %= 255

        self.state = out
```

`utils.py`
```python
# rotate a 4x4 matrix clockwise
def spiralRight(matrix):
    right = []
    for j in range(4):
        for i in range(3, -1, -1):
            right.append(matrix[i][j])
    return bytes2matrix(right)


# rotate a 4x4 matrix counterclockwise
def spiralLeft(matrix):
    left = []
    for j in range(3, -1, -1):
        for i in range(4):
            left.append(matrix[i][j])
    return bytes2matrix(left)


# convert bytes to 4x4 matrix
def bytes2matrix(bytes):
    return [list(bytes[i : i + 4]) for i in range(0, len(bytes), 4)]


# convert 4x4 matrix to bytes
def matrix2bytes(matrix):
    return bytes(sum(matrix, []))

SBOX = [184, 79, 76, 49, 237, 28, 54, 183, 106, 24, 192, 7, 43, 111, 175, 44, 46, 199, 182, 115, 83, 227, 61, 230, 6, 57, 165, 137, 58, 14, 94, 217, 66, 120, 53, 142, 29, 150, 103, 75, 186, 39, 31, 196, 18, 207, 244, 16, 213, 243, 114, 251, 96, 4, 138, 197, 10, 176, 157, 91, 238, 155, 254, 71, 86, 37, 130, 12, 52, 162, 220, 56, 88, 188, 27, 208, 25, 51, 172, 141, 168, 253, 85, 193, 90, 35, 95, 105, 200, 127, 247, 21, 93, 67, 13, 235, 84, 190, 225, 119, 189, 81, 250, 117, 231, 50, 179, 22, 223, 26, 228, 132, 139, 166, 210, 23, 64, 108, 212, 201, 99, 218, 160, 240, 129, 224, 233, 242, 159, 47, 126, 125, 146, 229, 0, 252, 161, 98, 30, 63, 239, 164, 36, 80, 151, 245, 38, 107, 3, 65, 73, 204, 8, 205, 82, 78, 173, 112, 219, 136, 123, 149, 118, 32, 215, 163, 74, 134, 248, 68, 110, 45, 59, 145, 178, 156, 100, 177, 221, 2, 92, 20, 40, 144, 101, 140, 169, 116, 143, 202, 1, 113, 209, 104, 133, 128, 70, 89, 216, 147, 122, 131, 9, 249, 121, 109, 191, 77, 124, 246, 55, 198, 187, 185, 17, 60, 180, 203, 19, 158, 97, 206, 148, 5, 87, 170, 236, 222, 194, 15, 214, 241, 211, 234, 42, 41, 153, 62, 102, 152, 69, 181, 34, 48, 226, 11, 195, 154, 174, 167, 135, 232, 72, 171, 33]

SPIRAL = [
    [1, 19, 22, 23],
    [166, 169, 173, 31],
    [149, 212, 176, 38],
    [134, 94, 59, 47],
]
```

Với bài này, ta cần tìm được `secret` để có thể giải mã được flag. Với chú ý rằng Cipher của chúng ta có hình dạng khá giống với AES, cộng với việc có 4 round, ta có thể nghĩ ngay đến Square Attack

Ta có thể viết lại hàm `mix()` của server theo cách đại số như sau

$$\begin{bmatrix}out_{0}\\out_{1}\\out_{2}\\out_{3}\end{bmatrix} =\begin{bmatrix}1&19&22&23\\166&169&173&31\\149&212&176&38\\134&94&59&47\end{bmatrix}\begin{bmatrix}s_{0}\\s_{1}\\s_{2}\\s_{3}\end{bmatrix}$$

Ta có thể hình dung Cipher của bài theo hình vẽ:
(Xin lỗi vì hình vẽ hơi xấu :(( )

![Screenshot 2024-04-20 000157](/images/square-attack/square-attack_7.png)

Để ý rằng Cipher của chúng ta làm việc trên mod 255, nên với mỗi $\varLambda$-set có active index `idx`, ta sẽ xây dựng được tính chất sau với `idx = 0`

$$\begin{aligned} Sum_0 &= b_0 + b_1 + ... + b_{254} \\ &= (a_{0,0} + 19 * a_{0, 1} + 22 * a_{0, 2} + 23 * a_{0, 3}) + ... + (a_{254,0} + 19 * a_{254, 1} + 22 * a_{254, 2} + 23 * a_{254, 3}) \\ &= (a_{0, 0} + ... + a_{254, 0}) + 19 * (a_{0, 1} + ... + a_{254, 1}) + 22 * (a_{0, 2} + ... + a_{254, 2}) + 23 * (a_{0, 3} + ... + a_{254, 3}) \\ &= \sum_{i=0}^{254}i + 19 * \sum_{i=0}^{254}i + 22 * \sum_{i=0}^{254}i + 23 * \sum_{i=0}^{254}i \\ &= 0 \mod 255 \end{aligned}$$

Từ đó áp dụng Square Attack, ta sẽ tìm được key để decrypt

Một số lưu ý về code của mình:

- Các hàm decrypt và inverse không được cung cấp, nên ta cần tự code lại. Việc cài đặt các hàm này khá đơn giản nên mình sẽ không đề cập
- Chú ý rằng `roundKey` được tạo bằng cách xoay block theo chiều ngược kim đồng hồ, vì vậy `roundKey[4]` chính là `key` mà ta đang cần tìm.

`solve.py`
```python
from pwn import *
import os
from utils import *
from tqdm import *
from spiral import *

target = process(["python3", "main.py"])

target.recvline()
target.recvline()

def getEncryptedFlag():
    target.sendlineafter(b">>> ", b"1")
    encFlag = target.recvline()[:-1].decode()
    return bytes.fromhex(encFlag)

def encryptMsg(hexmsg:str):
    target.sendlineafter(b">>> ", b"2")
    target.sendline(hexmsg.encode())
    encMsg = target.recvline()[:-1].decode()
    return bytes.fromhex(encMsg)

def find_key_bytes(idx:int):
    real_ans = set(list(range(256)))
    while True:
        ans = set()
        A_set = []
        init = os.urandom(16)
        for i in range(255):
            temp = bytearray(init)
            temp[idx] = i
            A_set += [encryptMsg(temp.hex())]
        
        for j in range(255):
            A_set_dec = 0
            for ele in A_set:
                A_set_dec += INV_SBOX[(ele[idx] - j) % 255]
            if A_set_dec % 255 == 0:
                ans.add(j)
        real_ans.intersection_update(ans)
        if len(real_ans) == 1:
            return real_ans.pop()


key = []
for i in tqdm(range(16)):
    key.append(find_key_bytes(i))

print(bytes(key).hex())
cipher = Spiral(key = bytes(key))
print(cipher.decrypt(getEncryptedFlag()))
```

### AES 5 Round

![image](/images/square-attack/square-attack_8.png)

Về bản chất, ta vẫn có thể thực hiện được Square Attack với 5 round bằng việc đoán 4 bytes ở `roundKey` cuối và 4 bytes ở `roundKey` thứ 4, tuy nhiên, việc đoán 8 bytes để tìm được 1 bytes ở `roundKey` thứ 5 tốn quá nhiều thời gian. Vì thế, ta có thể sử dụng ý tưởng sau: Do **MixColumns** là hàm tuyến tính dựa trên các cột của input, nên ta có thể viết lại `ciphertext` khi vừa hoàn thành round 4 như sau

$$\begin{aligned} Ciphertext &= MixColumns(s) \oplus RoundKey[4] \\ &= MixColumns(s) \oplus MixColumns(InvMixColumns(RoundKey[4])) \\ &= MixColumns(s \oplus InvMixColumns(RoundKey[4]))\end{aligned}$$

Do đó, ta chỉ cần đoán 4 bytes ở `roundKey` cuối, cùng với 1 bytes ở `roundKey` thứ 4 để tìm được 1 byte ở `roundKey` thứ 5, tổng cộng là 5 bytes. Việc này giúp giảm đáng kể khối lượng công việc cần làm để recover key, nhưng vẫn tốn khá nhiều thời gian.

![image](/images/square-attack/square-attack_9.png)


Trong CTF, thỉnh thoảng sẽ có một số bài yêu cầu break 5 round AES (hoặc 1 cái block cipher nào đó), tuy nhiên sẽ có một số thay đổi ở cách cài đặt, hoặc sẽ cho ta một số hint nào đó về Key để xử lí.

#### Ví dụ

- __Blocky5 - pbctf 2023__
https://github.com/m1dm4n/CTF-WriteUp/tree/main/2023/pbctf/Blocky5
- __Jenga - ACSC 2024__

`task.py`
```python
from Jenga import Jenga
import os
import signal

TIMEOUT = 30

key = os.urandom(9)
cipher = Jenga(key)

def timeout(signum, frame):
    print("Timeout!!!")
    signal.alarm(0)
    exit(0)

signal.signal(signal.SIGALRM, timeout)
signal.alarm(TIMEOUT)

for i in range(256):
    pt = bytes.fromhex(input("> ").strip())
    ct = cipher.encrypt(pt)
    print(f"ct: {ct.hex()}")

pt = os.urandom(9)
ct = cipher.encrypt(pt)
print(f"ct: {ct.hex()}")
user_pt = bytes.fromhex(input("pt? ").strip())

if pt == user_pt:
    print("Congratz!")
    flag = open('flag', 'r').read()
    print(f"Here is the flag: {flag}")
else:
    print("Wrong :(")
```

`Jenga.py`
```python
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]
SBOX_inv = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
]

def gf_mul(a, b):
    v = 0
    for i in range(8):
        v <<= 1
        if v & 0x100:
            v ^= 0x11b

        if (b >> (7 - i)) & 1:
            v ^= a
    return v

ROUND = 5

class Jenga:
    
    def __init__(self, key: bytes):
        assert len(key) == 9
        subkeys = list(key)

        for i in range( 9 * (ROUND - 1) ):
            subkeys.append(SBOX[subkeys[-9] ^ subkeys[-1]])
        
        self.subkeys = [ subkeys[i:i+9] for i in range(0, 9 * ROUND, 9) ]
    
    @staticmethod
    def hori(b):
        for i in range(0, 9, 3):
            x, y, z = b[i:i+3]
            b[i:i+3] = (
                gf_mul(x, 4) ^ gf_mul(y, 2) ^ z,
                gf_mul(y, 4) ^ gf_mul(z, 2) ^ x,
                gf_mul(z, 4) ^ gf_mul(x, 2) ^ y,
            )
    
    @staticmethod
    def vert(b):
        for i in range(3):
            x, y, z = b[i], b[i + 3], b[i + 6]
            b[i], b[i + 3], b[i + 6] = (
                gf_mul(x, 4) ^ gf_mul(y, 2) ^ z,
                gf_mul(y, 4) ^ gf_mul(z, 2) ^ x,
                gf_mul(z, 4) ^ gf_mul(x, 2) ^ y,
            )

    @staticmethod
    def hori_inv(b):
        for i in range(0, 9, 3):
            x, y, z = b[i:i+3]
            b[i:i+3] = (
                gf_mul(x, 0x9e) ^ gf_mul(y, 0x4f),
                gf_mul(y, 0x9e) ^ gf_mul(z, 0x4f),
                gf_mul(z, 0x9e) ^ gf_mul(x, 0x4f),
            )
    
    @staticmethod
    def vert_inv(b):
        for i in range(3):
            x, y, z = b[i], b[i + 3], b[i + 6]
            b[i], b[i + 3], b[i + 6] = (
                gf_mul(x, 0x9e) ^ gf_mul(y, 0x4f),
                gf_mul(y, 0x9e) ^ gf_mul(z, 0x4f),
                gf_mul(z, 0x9e) ^ gf_mul(x, 0x4f),
            )
    
    def xor(self, b, rnd):
        for i in range(9):
            b[i] ^= self.subkeys[rnd][i]
    
    @staticmethod
    def sbox(b):
        for i in range(9):
            b[i] = SBOX[b[i]]
    
    @staticmethod
    def sbox_inv(b):
        for i in range(9):
            b[i] = SBOX_inv[b[i]]

    def encrypt(self, block: bytes):
        b = list(block)
        for rnd in range(ROUND + 1):
            self.vert(b) if rnd % 2 else self.hori(b)
            if rnd == ROUND:
                break
            self.xor(b, rnd)
            self.sbox(b)
        return bytes(b)
    
    def decrypt(self, block: bytes):
        b = list(block)
        for rnd in reversed(range(ROUND + 1)):
            self.vert_inv(b) if rnd % 2 else self.hori_inv(b)
            if rnd == 0:
                break
            self.sbox_inv(b)
            self.xor(b, rnd - 1)
        return bytes(b)

if __name__ == "__main__":
    import os
    for _ in range(10):
        key = os.urandom(9)
        cipher = Jenga(key)

        for _ in range(100):
            pt = os.urandom(9)
            assert cipher.decrypt(cipher.encrypt(pt)) == pt
            assert cipher.encrypt(cipher.decrypt(pt)) == pt
```
- __blocky 4.5 lite - 0CTF/TCTF 2023__
https://github.com/sea0h7e/My-Public-CTF-Challenges/tree/main/0CTF-TCTF-2023/blocky-4.5-lite