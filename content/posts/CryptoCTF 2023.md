---
author: "Giap"
title: "CryptoCTF 2023"
date: "2023-07-10"
categories: ["Writeup"]
tags: ["RSA", "ECC"]
---
Tuần vừa rồi, mình có chơi giải CryptoCTF 2023 với team @Wanna.W1n. Đúng như cái tên, giải này toàn Crypto không à :)). Sau đây là lời giải của một vài bài mà mình ~~osint~~ làm được.

## Derik

> Detective [Derik](https://github.com/Giapppp/CTF/tree/main/CryptoCTF/2023/Derik/public) possessed an uncanny ability to unravel complex puzzles, his razor-sharp mind weaving through the intricate threads of mystery with effortless precision

`derik.py`
```python=
#!/usr/bin/env python3

from Crypto.Util.number import *
from secret import C, e, d, p, q, r, flag

O = [1391526622949983, 2848691279889518, 89200900157319, 31337]

assert isPrime(e) and isPrime(d) and isPrime(p) and isPrime(q) and isPrime(r)
assert C[0] * p - C[1] * q >= 0
assert C[2] * q - C[3] * r >= 0
assert C[4] * r - C[5] * p >= 0
assert (C[0] * p - C[1] * q) ** e + (C[2] * q - C[3] * r) ** e + (C[4] * r - C[5] * p) ** e == d * (C[0] * p - C[1] * q) * (C[2] * q - C[3] * r) * (C[4] * r - C[5] * p)
assert C[6] * e - C[7] * d == O[3]

n = e * d * p * q * r
m = bytes_to_long(flag)
c = pow(m, 65537, n)
print(f'C = {C}')
print(f'c = {c}')
```

Với rất nhiều điều kiện cho trước, ta nghĩ ngay đến tìm các số d, e, p, q, r thỏa mãn các điều kiện đó. 
Ta sẽ tìm d và e trước, vì các số d, e có vẻ sẽ rất nhỏ. Mình sử dụng z3 để tìm các số này:
```python=
from z3 import *
C = [5960650533801939766973431801711817334521794480800845853788489396583576739362531091881299990317357532712965991685855356736023156123272639095501827949743772, 6521307334196962312588683933194431457121496634106944587943458360009084052009954473233805656430247044180398241991916007097053259167347016989949709567530079, 1974144590530162761749719653512492399674271448426179161347522113979158665904709425021321314572814344781742306475435350045259668002944094011342611452228289, 2613994669316609213059728351496129310385706729636898358367479603483933513667486946164472738443484347294444234222189837370548518512002145671578950835894451, 8127380985210701021743355783483366664759506587061015828343032669060653534242331741280215982865084745259496501567264419306697788067646135512747952351628613, 5610271406291656026350079703507496574797593266125358942992954619413518379131260031910808827754539354830563482514244310277292686031300804846114623378588204, 10543, 4]
c = 80607532565510116966388633842290576008441185412513199071132245517888982730482694498575603226192340250444218146275844981580541820190393565327655055810841864715587561905777565790204415381897361016717820490400344469662479972681922265843907711283466105388820804099348169127917445858990935539611525002789966360469324052731259957798534960845391898385316664884009395500706952606508518095360995300436595374193777531503846662413864377535617876584843281151030183895735511854
O = [1391526622949983, 2848691279889518, 89200900157319, 31337]

d, e = Ints('d e')
s = Solver()
s.add(d > 0)
s.add(e > 0)
s.add(C[6]*e - C[7]*d == O[3])
print(s.check())
print(s.model())
```
Ta tìm được $d = 73, e = 3$. Tiếp theo, ta sẽ tìm các số p, q, r
Ta chú ý đến điều kiện thứ 5:
$$(C[0] * p - C[1] * q)^e + (C[2] * q - C[3] * r)^e + (C[4] * r - C[5] * p)^e = d * (C[0] * p - C[1] * q) * (C[2] * q - C[3] * r) * (C[4] * r - C[5] * p)$$
Đặt 
$$\begin{align}C[0] * p - C[1] * q &= a  \newline C[2] * q - C[3] * r &= b  \newline C[4] * r - C[5] * p &= c \end{align}$$

Điều kiện thứ 5 trở thành:
$$a^3 + b^3 + c^3 = 73abc$$

Sau một hồi osint, mình tìm được một cái pdf nói về dạng $a^3 + b^3 + c^3 = kabc$: http://matwbn.icm.edu.pl/ksiazki/aa/aa73/aa7331.pdf

Với $k = 71$, ta tìm được 

$a = 1391526622949983, b = 2848691279889518, c = 89200900157319$

Sau khi có $a, b, c$, ta chỉ cần giải hệ phương trình để tìm ra các số p, q, r. Ở đây, mình tiếp tục sử dụng z3 để giải hệ:

```python=
from z3 import *

C = [5960650533801939766973431801711817334521794480800845853788489396583576739362531091881299990317357532712965991685855356736023156123272639095501827949743772, 6521307334196962312588683933194431457121496634106944587943458360009084052009954473233805656430247044180398241991916007097053259167347016989949709567530079, 1974144590530162761749719653512492399674271448426179161347522113979158665904709425021321314572814344781742306475435350045259668002944094011342611452228289, 2613994669316609213059728351496129310385706729636898358367479603483933513667486946164472738443484347294444234222189837370548518512002145671578950835894451, 8127380985210701021743355783483366664759506587061015828343032669060653534242331741280215982865084745259496501567264419306697788067646135512747952351628613, 5610271406291656026350079703507496574797593266125358942992954619413518379131260031910808827754539354830563482514244310277292686031300804846114623378588204, 10543, 4]
c = 80607532565510116966388633842290576008441185412513199071132245517888982730482694498575603226192340250444218146275844981580541820190393565327655055810841864715587561905777565790204415381897361016717820490400344469662479972681922265843907711283466105388820804099348169127917445858990935539611525002789966360469324052731259957798534960845391898385316664884009395500706952606508518095360995300436595374193777531503846662413864377535617876584843281151030183895735511854

O = [1391526622949983, 2848691279889518, 89200900157319, 31337]

d = 73
e = 3
assert C[6] * e - C[7] * d == O[3]

#assert (C[0] * p - C[1] * q) ** e + (C[2] * q - C[3] * r) ** e + (C[4] * r - C[5] * p) ** e == d * (C[0] * p - C[1] * q) * (C[2] * q - C[3] * r) * (C[4] * r - C[5] * p)
p, q, r = Ints('p q r')
s = Solver()
s.add(C[0] * p - C[1] * q == 1391526622949983)
s.add(C[2] * q - C[3] * r == 2848691279889518)
s.add(C[4] * r - C[5] * p == 89200900157319)
print(s.check())
print(s.model())
```

Với z3, ta tìm được $$\begin{align} p &= 9758621034843917661145412977193922808892309951663464821517963113005483457886774294910761723767526582514514505278091600074371768233672585649562672245905811 \newline q &= 8919642442779618620315315582249815126044061421894622037450496385178083791083142991676417756698881509754110765444929271564991855378540939292428839562446571 \newline r &= 6736304432663651651650099104581016800112378771266600017972326085742513966258250417227421932482058281545032658577816441378170466639375931780967727070265551\end{align}$$

Khi đã có đủ $d, e, p, q, r$, việc còn lại là đơn giản:
```python=
from Crypto.Util.number import *
c = ..
d = 73
e = 3
p = ..
q = ..
r = ..
n = e * d * p * q * r 
phi = (e - 1) * (d - 1) * (p - 1) * (q - 1) * (r - 1)
d = pow(65537, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```
>**Flag:** CCTF{____Sylvester____tHE0r3m_Of_D3r!va7i0n!}
## Barak
> In a display of uncanny brilliance, [Barak](https://github.com/Giapppp/CTF/tree/main/CryptoCTF/2023/Barak/public) effortlessly unraveled the perplexing web of a bizarre elliptic curve cryptography system, leaving even the most seasoned cryptographers in awe of his formidable talent.

`Barak.sage`
```python=
#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag

def on_barak(P, E):
	c, d, p = E
	x, y = P
	return (x**3 + y**3 + c - d*x*y) % p == 0

def add_barak(P, Q, E):
	if P == (0, 0):
		return Q
	if Q == (0, 0):
		return P
	assert on_barak(P, E) and on_barak(Q, E)
	x1, y1 = P
	x2, y2 = Q
	if P == Q:
		x3 = y1 * (c - x1**3) * inverse(x1**3 - y1**3, p) % p
		y3 = x1 * (y1**3 - c) * inverse(x1**3 - y1**3, p) % p
	else:

		x3 = (y1**2*x2 - y2**2*x1) * inverse(x2*y2 - x1*y1, p) % p
		y3 = (x1**2*y2 - x2**2*y1) * inverse(x2*y2 - x1*y1, p) % p
	return (x3, y3)

def mul_barak(m, P, E):
	if P == (0, 0):
		return P
	R = (0, 0)
	while m != 0:
		if m & 1:
			R = add_barak(R, P, E)
		m = m >> 1
		if m != 0:
			P = add_barak(P, P, E)
	return R

def rand_barak(E):
	c, d, p = E
	while True:
		y = randint(1, p - 1)
		K = Zmod(p)
		P.<x> = PolynomialRing(K) 
		f = x**3 - d*x*y + c + y^3
		R = f.roots()
		try:
			r = R[0][0]
			return (r, y)
		except:
			continue

p = 73997272456239171124655017039956026551127725934222347
d = 68212800478915688445169020404812347140341674954375635
c = 1
E = (c, d, p)

P = rand_barak(E)

FLAG = flag.lstrip(b'CCTF{').rstrip(b'}')
m = bytes_to_long(FLAG) 
assert m < p
Q = mul_barak(m, P, E)
print(f'P = {P}')
print(f'Q = {Q}')
```

Một bài ECC với cái curve khá là lạ. Sau một hồi osint thì mình phát hiện ra đây là [Hessian Curve](https://en.wikipedia.org/wiki/Hessian_form_of_an_elliptic_curve):

$$x^3+y^3+1=3dxy\ (mod p)$$
Từ đó, ta sẽ có Weierstrass curve của curve này sẽ là:
$$y^2 = x^3 - 27d(d^3 + 8)*x + 54(d^6 - 20d^3 - 8) \ (1)$$

Công thức để chuyển điểm $P(u, v)$ trên Hessian Curve về điểm $Q(x, y)$ trên Weierstrass curve:
$$\begin{align} (x, y) &= (-9d^2 + \varepsilon u, 3\varepsilon (v - 1)) \newline \varepsilon &= \frac{12(d^3 - 1)}{du + v + 1}\end{align}$$

Khi đã chuyển được về dạng (1), ta chỉ cần tìm dlog của điểm $Q$ so với $P$. Do $p-1$ smooth nên hàm `discrete_log` của sagemath sẽ chạy rất nhanh và cho ta giá trị của $m$
Do order của Hessian curve lớn hơn so với order của Weierstrass curve tương ứng nên khì tìm được kết quả ở trên, ta cần phải bruteforce để tìm được giá trị chính xác của $m$
`solve.py`
```python=
from sage.all import *
#!/usr/bin/env sage
from Crypto.Util.number import *
#from flag import flag

p = 73997272456239171124655017039956026551127725934222347
d = (68212800478915688445169020404812347140341674954375635 * pow(3, -1, p))%p
c = 1

K = GF(p)

def Xi(x, y):
    a = K(12 * (d^3 - 1))
    b = K(d*x + y + 1)
    return K(a/b)

P = (71451574057642615329217496196104648829170714086074852, 69505051165402823276701818777271117086632959198597714)
Q = (40867727924496334272422180051448163594354522440089644, 56052452825146620306694006054673427761687498088402245)

def Convert(P):
    x, y = P
    xi = Xi(x, y)
    u = K(-9 * d^2 + xi * x)
    v = K(3 * xi * (y - 1))
    return u, v

#print(Convert(P))
#print(Convert(Q))
#P' = (7510140411942493384157242498032002096511502301379654, 56511377329312508608058301874238377653069935863599778)
#Q' = (50040023007719632673740549563829968866810139780495447, 33643082088231430078653063923447931936878420785106730)

a = K(-27 * d * (d^3 + 8))
b = K(54 * (d^6 - 20 * d^3 - 8))
E = EllipticCurve(K, [a, b])

P = E(7510140411942493384157242498032002096511502301379654, 56511377329312508608058301874238377653069935863599778)
Q = E(50040023007719632673740549563829968866810139780495447, 33643082088231430078653063923447931936878420785106730)

m1 = discrete_log(Q, P, P.order(), operation='+')
print(m1)
assert m1 * P == Q
for i in range(m1, p-1, P.order()):
    flag = long_to_bytes(i)
    print(flag)
```

```
1780694557271320552511299360138314441283923223949197
b'\x04\xc2f\x91\x8d\x9b\x14&lt;\n\xc8\x97\x10\xd3wm\xd4\xe9 \newlineS\xc2\xaf\x8d'
b'\r\x00\x06q\xe5at@\x9e\x1c\xbcH;\xa3\xc5S\x96\xfb\x80\xce \newline\xc9'
b"\x15=\xa6R='\xd4E1p\xe1\x7f\xa3\xd0\x1c\xd2D\x9a\xad\xda\n\x05"
b'\x1d{F2\x94\xee4I\xc4\xc5\x06\xb7\x0b\xfctP\xf29\xda\xe5\xb7A'
b'%\xb8\xe6\x12\xec\xb4\x94NX\x19+\xeet(\xcb\xcf\x9f\xd9\x07\xf1d}'
b'-\xf6\x85\xf3Dz\xf4R\xebmQ%\xdcU#NMx4\xfd\x11\xb9'
b'64%\xd3\x9cATW~\xc1v]D\x81z\xcc\xfb\x17b\x08\xbe\xf5'
b'&gt;q\xc5\xb3\xf4\x07\xb4 \newline\x12\x15\x9b\x94\xac\xad\xd2K\xa8\xb6\x8f\x14l1'
b'F\xafe\x94K\xce\x14`\xa5i\xc0\xcc\x14\xda)\xcaVU\xbc \x19m'
b'N\xed\x05t\xa3\x94te8\xbd\xe6\x03}\x06\x81I\x03\xf4\xe9+\xc6\xa9'
b'W*\xa5T\xfbZ\xd4i\xcc\x12\x0b:\xe52\xd8\xc7\xb1\x94\x167s\xe5'
b'_hE5S!4n_f0rM_0F_3CC!!' <= Đây nè :D
b'g\xa5\xe5\x15\xaa\xe7\x94r\xf2\xbaU\xa9\xb5\x8b\x87\xc5\x0c\xd2pN\xce]'
b'o\xe3\x84\xf6\x02\xad\xf4w\x86\x0ez\xe1\x1d\xb7\xdfC\xbaq\x9dZ{\x99'
b'x!$\xd6ZtT|\x19b\xa0\x18\x85\xe46\xc2h\x10\xcaf(\xd5'
b'\x80^\xc4\xb6\xb2:\xb4\x80\xac\xb6\xc5O\xee\x10\x8eA\x15\xaf\xf7q\xd6\x11'
b'\x88\x9cd\x97\n\x01\x14\x85@\n\xea\x87V&lt;\xe5\xbf\xc3O$}\x83M'
b'\x90\xda\x04wa\xc7t\x89\xd3_\x0f\xbe\xbei=&gt;p\xeeQ\x890\x89'
b'\x99\x17\xa4W\xb9\x8d\xd4\x8ef\xb34\xf6&amp;\x95\x94\xbd\x1e\x8d~\x94\xdd\xc5'
b'\xa1UD8\x11T4\x92\xfa\x07Z-\x8e\xc1\xec;\xcc,\xab\xa0\x8b\x01'
b'\xa9\x92\xe4\x18i\x1a\x94\x97\x8d[\x7fd\xf6\xeeC\xbay\xcb\xd8\xac8='
b"\xb1\xd0\x83\xf8\xc0\xe0\xf4\x9c \xaf\xa4\x9c_\x1a\x9b9'k\x05\xb7\xe5y"
b'\xba\x0e#\xd9\x18\xa7T\xa0\xb4\x03\xc9\xd3\xc7F\xf2\xb7\xd5\n2\xc3\x92\xb5'
b'\xc2K\xc3\xb9pm\xb4\xa5GW\xef\x0b/sJ6\x82\xa9_\xcf?\xf1'
```
>**Flag:** CCTF{_hE5S!4n_f0rM_0F_3CC!!}
## Keymoted
>Combining RSA and ECC in a cryptographic system does not necessarily guarantee security equivalent to that of the individual RSA or ECC systems. What about [keymoted](https://github.com/Giapppp/CTF/tree/main/CryptoCTF/2023/keymoted/public)

`keymoted.sage`
```python=
#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag

def gen_koymoted(nbit):
	p = getPrime(nbit)
	a, b = [randint(1, p - 1) for _ in '__']
	Ep = EllipticCurve(GF(p), [a, b])
	tp = p + 1 - Ep.order()
	_s = p ^^ ((2 ** (nbit - 1)) + 2 ** (nbit // 2))
	q = next_prime(2 * _s + 1)
	Eq = EllipticCurve(GF(q), [a, b])
	n = p * q
	tq = q + 1 - Eq.order()
	e = 65537
	while True:
		if gcd(e, (p**2 - tp**2) * (q**2 - tq**2)) == 1:
			break
		else:
			e = next_prime(e)
	pkey, skey = (n, e, a, b), (p, q)
	return pkey, skey

def encrypt(msg, pkey, skey):
	n, e, a, b = pkey
	p, q = skey
	m = bytes_to_long(msg)
	assert m < n
	while True:
		xp = (m**3 + a*m + b) % p
		xq = (m**3 + a*m + b) % q
		if pow(xp, (p-1)//2, p) == pow(xq, (q-1)//2, q) == 1:
			break
		else:
			m += 1
	eq1, eq2 = Mod(xp, p), Mod(xq, q)
	rp, rq = sqrt(eq1), sqrt(eq2)
	_, x, y = xgcd(p, q)
	Z = Zmod(n)
	x = (Z(rp) * Z(q) * Z(y) + Z(rq) * Z(p) * Z(x)) % n
	E = EllipticCurve(Z, [a, b])
	P = E(m, x)
	enc = e * P
	return enc

nbit = 256
pkey, skey = gen_koymoted(nbit)
enc = encrypt(flag, pkey, skey)

print(f'pkey = {pkey}')
print(f'enc = {enc}')
```

Một bài kết hợp giữa RSA và ECC. Do khi làm việc trên $\mathbb{Z}_n$ sẽ có một số điểm không tồn tại. Chính vì vậy, ta sẽ làm việc trên $\mathbb{Z}_p$ và $\mathbb{Z}_q$, và nhiệm vụ đầu tiên sẽ là phân tích n.

Bằng một cách thần kì nào đó, ta có thể sử dụng z3 để phân tích n! Với chú ý rằng `q = next_prime(2*_s + 1)` với `_s = p ^^ ((2 ** (nbit - 1)) + 2 ** (nbit // 2))` (Dấu `^^` trong sagemath có nghĩa là phép xor), ta sẽ có công thức:
$$p*(2*(p \oplus (2^{nbit - 1} + 2^{nbit // 2}) + 3) = n$$
(+3 do $q$ là next_prime, cái này mình đoán thôi nhưng mà ra thật :D)
Do $p$ là số nguyên tố 256 bit nên ta sẽ có đoạn code sau:
```python=
#!/usr/bin/env python

from z3 import *
nbit = 256
k = 2**(nbit - 1) + 2**(nbit//2)
p = BitVec('p', nbit)
s = Solver()
n = 6660938713055850877314255610895820875305739186102790477966786501810416821294442374977193379731704125177528590285016474818841859956990486067573436301232301
s.add(p*(2*(p^k) + 3) == n)
print(s.check())
print(s.model())
```

Ta tìm được 

$p = 93511613846272978051774379195449772332692693333173612296021789501865098047641$

Sau khi đã phân tích được $n$, ta sẽ đi tìm $d$ sao cho $d*e = 1 \ (mod\ E.order())$ với $(E)\ y^2 = x^3 + ax + b \ (mod\ n)$ 
Ta có thể tìm $d$ bằng cách tính $dp = pow(e, -1, E_1.order())$ và $dq = pow(e, -1, E_2.order())$, trong đó:
$$\begin{align} (E_1)\ y^2 = x^3 + ax + b \ (\ mod \ p)  \newline (E_2) \ y^2 = x^3 + ax + b \ (\ mod \ q) \end{align}$$
rồi dùng CRT để tìm $d \mod E.order()$

```python
from Crypto.Util.number import *
from sage.all import *
pkey = (6660938713055850877314255610895820875305739186102790477966786501810416821294442374977193379731704125177528590285016474818841859956990486067573436301232301, 65537, 5539256645640498184116966196249666621079506508209770360679460869295427007578, 20151017657582479433586370393795140515103572865771721775868586710594524816458)
#enc = (6641320679869421443758875467781930795132746694454926965779628505713445486895274490835545942727970688359873955019634877304270220728625521646208912044469433 : 2856872654927815636828860866843721158889474116106462420201092148493803550131351543372740950198853438539317164093538508795630146854596724019329887894933972 : 1)

p = 93511613846272978051774379195449772332692693333173612296021789501865098047641
q = 71231138455229760679977773382211636812795966734548537479512744210680602878261
n = pkey[0]
a = pkey[2]
b = pkey[3]
assert n == p * q
print('true')

e = 65537
d = pow(e, -1, (p-1)*(q-1))
E = EllipticCurve(Zmod(n), [a, b])
P = E(6641320679869421443758875467781930795132746694454926965779628505713445486895274490835545942727970688359873955019634877304270220728625521646208912044469433, 2856872654927815636828860866843721158889474116106462420201092148493803550131351543372740950198853438539317164093538508795630146854596724019329887894933972)

phip = int(EllipticCurve(GF(p), [a, b]).order())
phiq = int(EllipticCurve(GF(q), [a, b]).order())

dp = pow(e, -1, phip)
dq = pow(e, -1, phiq)
dn = crt([dp, dq], [phip, phiq])
m = (dn * P).xy()[0]
print(long_to_bytes(int(m)))
```
>**Flag:** CCTF{a_n3W_4t7aCk_0n_RSA_a9ain!?}
