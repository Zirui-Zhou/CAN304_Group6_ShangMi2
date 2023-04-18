# -*- coding: UTF-8 -*-
"""
# @Author:  CAN304 Group 6
# @Date:    2023/4/18 13:25:11
"""
import hashlib
import math
import random

from DebugTimer import DebugTimer


class ec:
    p = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', base=16)
    a = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', base=16)
    b = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', base=16)
    n = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', base=16)
    Gx = int('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', base=16)
    Gy = int('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', base=16)


class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __neg__(self):
        return Point(self.x, -self.y % ec.p)

    def __add__(self, other):
        """
        .. math::
                \begin{aligned}
                \lambda & =\frac{y_{q}-y_{p}}{x_{q}-x_{p}} \\
                x_{r} & =\lambda^{2}-x_{p}-x_{q} \\
                y_{r} & =\lambda\left(x_{p}-x_{r}\right)-y_{p}
                \end{aligned}
        """
        if self.is_inf():
            return other
        elif other.is_inf():
            return self
        elif self == -other:
            return InfPoint()

        x1, x2 = self.x, other.x
        y1, y2 = self.y, other.y

        inv_x = pow(x2 - x1, -1, ec.p)
        lbd = ((y2 - y1) * inv_x) % ec.p
        x3 = (lbd ** 2 - x1 - x2) % ec.p
        y3 = (lbd * (x1 - x3) - y1) % ec.p
        return Point(x3, y3)

    def double(self):
        if self.is_inf():
            return InfPoint()

        x1, y1 = self.x, self.y

        # Refer to https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
        # In Python 3.8+ Modular multiplicative inverse function can use `pow()`.
        # Here imports modular multiplicative inverse to avoid division operation.

        inv_y = pow(2 * y1, -1, ec.p)
        lbd = ((3 * (x1 ** 2) + ec.a) * inv_y) % ec.p
        x3 = (lbd ** 2 - 2 * x1) % ec.p
        y3 = (lbd * (x1 - x3) - y1) % ec.p
        return Point(x3, y3)

    def multiply(self, k):
        k = bin(k)[2:]
        Q = InfPoint()
        for j in range(len(k)):
            Q = Q.double()
            if k[j] == '1':
                Q += self
        return Q

    def is_inf(self):
        return False

    def is_in_Fp(self):
        return (0 < self.x < ec.p - 1) and (0 < self.y < ec.p - 1)

    def is_in_curve(self):
        x, y = self.x, self.y
        return (y ** 2) % ec.p == (x ** 3 + ec.a * x + ec.b) % ec.p

    def to_bits(self, mode="pcxy"):
        PC = '00000100'
        bits_x = self.elem_to_bits(self.x)
        bits_y = self.elem_to_bits(self.y)
        return mode \
            .replace("pc", PC) \
            .replace("x", bits_x) \
            .replace("y", bits_y)

    @staticmethod
    def elem_to_bits(elem):
        t = math.ceil(math.log(ec.p, 2))
        fmt = f"{{0:0{t}b}}"
        s = fmt.format(elem)
        return s

    @staticmethod
    def bits_to_elem(bits):
        return int(bits, base=2)


class InfPoint(Point):
    def __init__(self):
        super().__init__(None, None)

    def is_in_Fp(self):
        return True

    def is_in_curve(self):
        return True

    def is_inf(self):
        return True


def hash_bits(c):
    hashed = hashlib.sha256(bytearray((int(c[i:i + 8], 2)) for i in range(0, len(c), 8))).digest()
    return "".join(format(x, "b") for x in hashed)


# 按位异或
def Xor(a, b):
    y = int(a, 2) ^ int(b, 2)
    fmt = f"{{0:0{len(a)}b}}"
    return fmt.format(y)


def key_verify(P: Point):
    return (
            not P.is_inf()
            and P.is_in_Fp()
            and P.is_in_curve()
            and P.multiply(ec.n).is_inf()
    )


# 产生公钥
def generate_key():
    while True:
        d = random.randint(1, ec.n - 1)
        G = Point(ec.Gx, ec.Gy)
        P = G.multiply(d)
        if key_verify(P):
            return d, P


# 消息字符串转比特串
def msg2bit(msg):
    return ''.join('{0:08b}'.format(ord(x), 'b') for x in msg)


# 比特串转消息字符串
def bit2msg(b):
    return "".join([chr(int(b[i:i + 8], 2)) for i in range(0, len(b), 8)])


#  KDF密钥派生函数 调用已有的SM3实现  
def KDF(Z, klen):
    v = 256
    Ha = {}
    upper = math.ceil(klen / v)
    for ct, i in enumerate(range(1, upper + 1)):
        Ha[i] = hash_bits(Z + "{0:016b}".format(ct))

    # klen/v is integer
    if upper == klen / v:
        Ha_exclamation = Ha[upper]  # Ha!
    else:
        Ha_exclamation = Ha[upper][:klen - (v * math.floor(klen / v))]
    K = ''
    for i in range(1, math.ceil(klen / v)):
        K += Ha[i]
    K += Ha_exclamation
    return K


def SM2_encrypt(M, P: Point):
    klen = len(M)
    # Step 1
    k = random.randint(1, ec.n - 1)
    # Step 2
    C1 = Point(ec.Gx, ec.Gy).multiply(k).to_bits()
    # Step 3
    h = math.floor(((math.sqrt(ec.p) + 1) ** 2) / ec.n)  # 1+p+ε
    if P.multiply(h).is_inf():
        return False
    # Step 4
    kP = P.multiply(k)
    # Step 5
    t = KDF(kP.to_bits("xy"), klen)
    if int(t, base=2) == 0:
        return False
    # Step 6
    C2 = Xor(M, t)
    # Step 7
    C3 = hash_bits(kP.to_bits("x") + M + kP.to_bits("y"))
    # Step 8
    C = [C1, C2, C3]
    return C


def SM2_decrypt(C, d):
    C1, C2, C3 = C

    klen = len(C2)
    # Step 1
    PC = C1[:8]  # PC=04
    C1 = C1[8:]
    C1 = Point(
        Point.bits_to_elem(C1[:len(C1) // 2]),
        Point.bits_to_elem(C1[len(C1) // 2:])
    )
    if not C1.is_in_curve():
        return False
    # Step 2
    h = math.floor(((math.sqrt(ec.p) + 1) ** 2) / ec.n)
    S = C1.multiply(h)
    if S.is_inf():
        return False
    # Step 3
    dC = C1.multiply(d)
    # Step 4
    t = KDF(dC.to_bits("xy"), klen)
    if int(t, base=2) == 0:
        return False
    # Step 5
    MM = Xor(C2, t)
    # Step 6
    u = hash_bits(dC.to_bits("x") + MM + dC.to_bits("y"))
    if u != C3:
        return False
    # Step 7
    return MM


if __name__ == "__main__":

    # print("初始数据:")
    # print("p:", str(hex(p)))
    # print("a:", str(hex(a)))
    # print("b:", str(hex(b)))
    # print("n:", str(hex(n)))
    # print("Gx:", str(hex(Gx)))
    # print("Gy:", str(hex(Gy)))
    # print("\n")
    # # 产生公私钥对
    print("Key Generation:")
    with DebugTimer("Key generation"):
        d, P = generate_key()
    print('d:', hex(d), '\nPx:', hex(P.x), '\nPy:', hex(P.y))
    print("\n")

    msg = input("Please input the plaintext: ")
    # SM2_Encrpytion
    with DebugTimer("SM2 Encrpytion"):
        plain_text = msg2bit(msg)
        cipher_text = SM2_encrypt(plain_text, P)
        hexresult = ''
        for c in cipher_text:
            hexresult += hex(int(c, base=2))
    print('The ciphertext is :', hexresult)

    # SM2_Decryption
    with DebugTimer("SM2 Decrpytion"):
        decrypt_text = SM2_decrypt(cipher_text, d)
        decrypt_text = bit2msg(decrypt_text)
    print('The plaintext is ', decrypt_text)
