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
    """A simple class to define an ellipse curve with system parameters.

    Here uses an example on F_P 256 curve.

    Refer to GB/T 32918.1-2016
    C.2 Elliptic curves over F_P
    https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf
    """
    p = int('8542D69E 4C044F18 E8B92435 BF6FF7DE 45728391 5C45517D 722EDB8B 08F1DFC3'.replace(" ", ""), base=16)
    a = int('787968B4 FA32C3FD 2417842E 73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498'.replace(" ", ""), base=16)
    b = int('63E4C6D3 B23B0C84 9CF84241 484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A'.replace(" ", ""), base=16)
    n = int('8542D69E 4C044F18 E8B92435 BF6FF7DD 29772063 0485628D 5AE74EE7 C32E79B7'.replace(" ", ""), base=16)
    Gx = int('421DEBD6 1B62EAB6 746434EB C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D'.replace(" ", ""), base=16)
    Gy = int('0680512B CBB42C07 D47349D2 153B70C4 E5D7FDFC BFA36EA1 A85841B9 E46E09A2'.replace(" ", ""), base=16)


class Point:
    """A simple class for points on an ellipse curve in affine coordinate.

    Attributes:
        x: An integer of x-coordinate value.
        y: An integer of y-coordinate value.
    """
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __eq__(self, other):
        """Get whether two `Point` equal.

        Args:
            other: A `Point` object to compare.

        Returns:
            A boolean of whether two `Point` equal.
        """
        return self.x == other.x and self.y == other.y

    def __neg__(self):
        """Get the inverse element of P.

        Refer to GB/T 32918.1-2016
        3.2.3.1 Elliptic curve group over F_p
        https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf

        Returns:
            A `Point` object of inversion result.
        """
        # The inverse element of P is -P=(x, -y)
        return Point(self.x, -self.y % ec.p)

    def __add__(self, other):
        """Addition of two points.

        Refer to GB/T 32918.1-2016
        3.2.3.1 Elliptic curve group over F_p
        https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf

        Args:
            other: A `Point` object to add.

        Returns:
            A `Point` object of addition result.
        """
        # a) O+O=O.
        # b) ∀P=(x, y)∈E(F_p)\{O}, P+O=O+P=P.
        if self.is_inf():
            return other
        elif other.is_inf():
            return self
        # c) ∀P=(x, y)∈E(F_p)\{O}, the inverse element of P is -P=(x, -y), and P+(-P)=O.
        elif self == -other:
            return InfPoint()
        # d) The rule for addition of two points which are not inverse to each other:
        # Suppose P_1=(x_1, y_1)∈E(F_p)\{O}, P_2=(x_2, y_2)∈E(F_p)\{O}, and x_1!=x_2.
        # Let P_3=(x_3, y_3)=P_1+P_2, then:
        # .. math:
        #   \left\{\begin{array}{l}
        #   x_{3}=\lambda^{2}-x_{1}-x_{2} \\
        #   y_{3}=\lambda\left(x_{1}-x_{3}\right)-y_{1}
        #   \end{array}\right.
        #   where
        #   \lambda=\frac{y_{2}-y_{1}}{x_{2}-x_{1}}
        x1, x2 = self.x, other.x
        y1, y2 = self.y, other.y
        # Refer to https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
        # In Python 3.8+ Modular multiplicative inverse function can use `pow()`.
        # Here introduces modular multiplicative inverse to avoid division operation.
        inv_x = pow(x2 - x1, -1, ec.p)
        lbd = ((y2 - y1) * inv_x) % ec.p
        x3 = (lbd ** 2 - x1 - x2) % ec.p
        y3 = (lbd * (x1 - x3) - y1) % ec.p
        return Point(x3, y3)

    def double(self):
        """Doubling of one point.

        Refer to GB/T 32918.1-2016
        3.2.3.1 Elliptic curve group over F_p
        https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf

        Returns:
            A `Point` object of doubling result.
        """
        # Refer to `Point.__add__()` to see infinity point handling.
        if self.is_inf():
            return InfPoint()
        # e) The rule of doubling:
        # Suppose P_1=(x_1, y_1)∈E(F_p)\{O}, and x_1!=0.
        # Let P_3=(x_3, y_3)=P_1+P_1, then:
        # .. math:
        #   \left\{\begin{array}{l}
        #   x_{3}=\lambda^{2}-2 x_{1} \\
        #   y_{3}=\lambda\left(x_{1}-x_{3}\right)-y_{1}
        #   \end{array}\right.
        #   where
        #   \lambda=\frac{3 x_{1}^{2}+a}{2 y_{1}}
        x1, y1 = self.x, self.y
        # Refer to https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
        # In Python 3.8+ Modular multiplicative inverse function can use `pow()`.
        # Here introduces modular multiplicative inverse to avoid division operation.
        inv_y = pow(2 * y1, -1, ec.p)
        lbd = ((3 * (x1 ** 2) + ec.a) * inv_y) % ec.p
        x3 = (lbd ** 2 - 2 * x1) % ec.p
        y3 = (lbd * (x1 - x3) - y1) % ec.p
        return Point(x3, y3)

    def multiply(self, k):
        """Scalar multiplications on elliptic curves.

        Refer to GB/T 32918.1-2016
        A.3.2 Implementation of scalar multiplications on elliptic curves
        Algorithm 1: binary expansion method
        https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf

        Args:
            k: An integer of number of `Point` multiplication.

        Returns:
            A `Point` object of multiplication result.
        """
        k = format(k, "b")
        # a) Set Q=O.
        Q = InfPoint()
        # b) For j=l−1 (l is the length of k) to 0, do:
        #   b.1) Q=[2]Q.
        #   b.2) If k_j=1, then Q=Q+P.
        for j in range(len(k)):
            Q = Q.double()
            if k[j] == '1':
                Q += self
        # c) Output Q.
        return Q

    def is_inf(self):
        """Get whether the `Point` is an infinity point (O).

        Returns:
            A boolean of whether the `Point` is an infinity point.
        """
        # If a point is defined as `Point`, it is always not an infinity point.
        # Otherwise, it will be defined as `InfPoint`.
        return False

    def is_in_Fp(self):
        """Get whether the `Point` is in prime field (F_p).

        Refer to GB/T 32918.1-2016
        A.1.1 Definition of prime field F_p
        https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf

        Returns:
            A boolean of whether the `Point` is in prime field.
        """
        # F_p consists of the p elements in set {0, 1, 2, ..., p−1}.
        return (0 < self.x < ec.p - 1) and (0 < self.y < ec.p - 1)

    def is_in_curve(self):
        """Get whether the `Point` is on ellipse curve.

        Refer to GB/T 32918.1-2016
        A.1.2.2 Affine coordinate
        https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf

        Returns:
            A boolean of whether the `Point` is on ellipse curve.
        """
        # The set of points on the elliptic curve is denoted by
        # .. math:
        #   E\left(F_{p}\right)=\left\{(x, y) \mid x, y \in F_{p}, y^{2}=x^{3}+a x+b\right\} \cup\{O\}
        # where O is the point at infinity.
        x, y = self.x, self.y
        return (y ** 2) % ec.p == (x ** 3 + ec.a * x + ec.b) % ec.p

    def to_bits(self, order="pcxy"):
        """Conversion of a point to a byte string.

        Refer to GB/T 32918.1-2016
        4.2.8 Conversion of a point to a byte string
        c) The uncompressed form
        https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf

        Args:
            order: A string contains "pc", "x", and "y" to determine string concatenation order.

        Returns:
            A string in binary format of `Point`.
        """
        # 1) Convert the field element x_P, y_P to a byte string X_1, Y_1 of l bytes long.
        bits_x = self.elem_to_bits(self.x)
        bits_y = self.elem_to_bits(self.y)
        # 2) Let PC=04.
        PC = '00000100'
        # 3) Output the byte string S=PC||X_1||Y_1.
        # Note that here introduces `order` to fit some other conditions such as X_1||Y_1.
        return order \
            .replace("pc", PC) \
            .replace("x", bits_x) \
            .replace("y", bits_y)

    @staticmethod
    def elem_to_bits(elem):
        """Conversion of a field element to a byte string.

        Refer to GB/T 32918.1-2016
        4.2.5 Conversion of a field element to a byte string.
        https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf

        Args:
            elem: An integer for binary conversion.

        Returns:
            A string in binary format of the integer.
        """
        # Note that a byte string length is l=⌈t/8⌉ bytes long, where t=⌈log2q⌉.
        # a) Let M_(k-1), M_(k-2), ..., M_(0) be the individual bytes of M from left to right.
        # b) The bytes of M satisfy:
        # .. math:
        #   x=\sum_{i=0}^{k-1} 2^{8i}M_{i}
        t = math.ceil(math.log(ec.p, 2))
        fmt = f"{{0:0{t}b}}"
        s = fmt.format(elem)
        return s

    @staticmethod
    def bits_to_elem(bits):
        """Conversion of a byte string to an integer

        Refer to GB/T 32918.1-2016
        4.2.2 Conversion of a byte string to an integer
        https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf

        Args:
            bits: A string in binary format for integer conversion.

        Returns:
            An integer of the binary string.
        """
        return int(bits, base=2)


class InfPoint(Point):
    """A simple class inherits `Point` for infinity points (O) on an ellipse curve in affine coordinate.

    The x and y for infinity have no actual meaning, which set to `None`.
    """
    def __init__(self):
        super().__init__(None, None)

    def is_in_Fp(self):
        """Get whether the infinity point is in prime field (F_p).

        Refer to GB/T 32918.1-2016
        A.1.1 Definition of prime field F_p
        https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf

        Returns:
            A boolean of whether the infinity point is in prime field (F_p).
        """
        # F_p consists of the p elements in set {0, 1, 2, ..., p−1}.
        return True

    def is_in_curve(self):
        """Get whether the infinity point is on ellipse curve.

        Refer to GB/T 32918.1-2016
        A.1.2.2 Affine coordinate
        https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf

        Returns:
            A boolean of whether the infinity point is on ellipse curve.
        """
        # The set of points on the elliptic curve is denoted by
        # .. math:
        #   E\left(F_{p}\right)=\left\{(x, y) \mid x, y \in F_{p}, y^{2}=x^{3}+a x+b\right\} \cup\{O\}
        # where O is the point at infinity.
        return True

    def is_inf(self):
        """Get whether the `Point` is an infinity point (O).

        Returns:
            A boolean of whether the `Point` is an infinity point (O).
        """
        return True


def hash_bits(c):
    """Hash operation on a binary string.

    Refer to GB/T 32918.4-2016
    5.4.2 Cryptographic hash function
    https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.4-2016.SM2-en.pdf

    Args:
        c: A string in binary format to hash.

    Returns:
        A string in binary format of hash result.
    """
    # This part adopts the cryptographic hash functions approved by the State Cryptography
    # Administration such as the SM3 cryptographic hash algorithm.
    # Note that here uses SHA-256 to simplify the hash operation, instead of importing other 3rd-party libraries.
    hashed = hashlib.sha256(bytearray((int(c[i:i + 8], 2)) for i in range(0, len(c), 8))).digest()
    return "".join(format(x, "b") for x in hashed)


def xor(a, b):
    """Exclusive-or operation for two strings in binary format.

    Args:
        a: A string in binary format.
        b: A string in binary format.

    Returns:
        A string in binary format of the exclusive-or result.
    """
    y = int(a, 2) ^ int(b, 2)
    fmt = f"{{0:0{len(a)}b}}"
    return fmt.format(y)


def verify_key(P: Point):
    """ Validate the generated public key.

    Refer to GB/T 32918.1-2016
    6.2.1 Validation of public keys of elliptic curves over F_p
    https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf

    Args:
        P: A `Point` object of the generated public key.

    Returns:
        A boolean of whether validation is passed.
    """
    return (
        # a) Verify that P is not the point at infinity O.
        not P.is_inf()
        # b) Verify that the coordinates x_p and y_p of the public key are elements belonging to F_p.
        and P.is_in_Fp()
        # c) Verify that :math:`y_{P}^{2} \equiv x_{P}^{3}+a x_{P}+b(\bmod p)`.
        and P.is_in_curve()
        # d) Verify that [n]P=O.
        and P.multiply(ec.n).is_inf()
    )


def generate_key():
    """ Generate the key pair.

    Refer to GB/T 32918.1-2016
    6.1 Key pair generation
    https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.1-2016.SM2-en.pdf

    Returns:
        A key pair (d,P) related to the elliptic curve system parameters.
        d: An integer as private key between 1 and n-1.
        P: A `Point` object as public key.
    """
    while True:
        # a) Generate an integer d in [1, n−2] using a random number generator.
        d = random.randint(1, ec.n - 1)
        # b) Let G be the base point, then compute P=(x_p, y_p)=[d]G.
        G = Point(ec.Gx, ec.Gy)
        P = G.multiply(d)
        # Keep generation until a valid key-pair.
        if verify_key(P):
            return d, P


def str_to_bit(str):
    """Conversion of a text string to a binary string.

    Args:
        str: A string in text format for conversion.

    Returns:
        A string in binary format.
    """
    return ''.join('{0:08b}'.format(ord(x), 'b') for x in str)


def bit_to_str(bits):
    """Conversion of a binary string to a text string.

    Args:
        bits: A string in binary format for conversion.

    Returns:
        A string in text format.
    """
    return "".join([chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8)])


def KDF(Z, klen):
    """Key derivation function.

    Refer to GB/T 32918.4-2016
    5.4.3 Key derivation function
    https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.4-2016.SM2-en.pdf

    Args:
        Z: A string in binary format.
        klen: An integer which represents the bit length of the resulting secret key data
            and is required to be smaller than (2^32−1)v.

    Returns:
        Output: A secret key bit string of length klen.
    """
    v = 256
    Ha = {}
    # a) Initialize a 32 bit counter ct=0x00000001
    # b) For i from 1 to ⌈klen/v⌉ do:
    #   b.1) compute Ha_i=H_v(Z||ct).
    #   b.2) ct++.
    # Note that `H_v()` is a cryptographic hash function which outputs a hash value of length `v` bits.
    upper = math.ceil(klen / v)
    for ct, i in enumerate(range(1, upper + 1)):
        Ha[i] = hash_bits(Z + "{0:016b}".format(ct))
    # c) If klen/v is an integer, let Ha!_⌈klen/v⌉=Ha_⌈klen/v⌉.
    # Otherwise let Ha!_⌈klen/v⌉ be the leftmost (klen-(v*⌊klen/v⌋)) bits of Ha_⌈klen/v⌉.
    if upper == klen / v:
        Ha_mark = Ha[upper]
    else:
        Ha_mark = Ha[upper][:klen - (v * math.floor(klen / v))]
    # d) Let K=Ha_1||Ha_(⌈klen/v⌉-1)||Ha!_⌈klen/v⌉.
    K = "".join(Ha[i] for i in range(1, upper)) + Ha_mark
    return K


def encrypt(M: str, P: Point):
    """Encrypt the message by the public key.

    Refer to GB/T 32918.4-2016
    6.1 Encryption algorithm
    https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.4-2016.SM2-en.pdf

    Args:
        M: A string in binary format as the plaintext message to be sent.
        P: A `Point` object as public key.

    Returns:
        A list of ciphertext list.
    """
    klen = len(M)
    # A1: Generate a random number k in [1, n-1] with the random number generator.
    k = random.randint(1, ec.n - 1)
    # A2: Compute point C1=[k]G=(x_1, y_1) of the elliptic curve, and convert the data type of C1 to bit string.
    C1 = Point(ec.Gx, ec.Gy).multiply(k).to_bits()
    # A3: Compute point S=[h]P_B of the elliptic curve. If S is the infinity point, report error and exit.
    # Note that h is the cofactor of n (See 5.2 System parameters of elliptic curves).
    h = int(ec.n / ec.p)
    if P.multiply(h).is_inf():
        return False
    # A4: Compute point [k]P_B=(x_2, y_2) of the elliptic curve, convert the data type of x_2,y_2 to bit string.
    kP = P.multiply(k)
    # A5: Compute t=KDF(x_2||y_2, klen). If t is an all zero bit string, go to A1.
    t = KDF(kP.to_bits("xy"), klen)
    if int(t, base=2) == 0:
        return False
    # A6: Compute C2 = M XOR t.
    C2 = xor(M, t)
    # A7: Compute C3=Hash(x_2||M||y).
    C3 = hash_bits(kP.to_bits("x") + M + kP.to_bits("y"))
    # A8: Output the ciphertext C1||C2||C3.
    C = [C1, C2, C3]
    return C


def decrypt(C, d):
    """Decrypt the ciphertext by the relative private key.

    Refer to GB/T 32918.4-2016
    7.1 Decryption algorithm
    https://github.com/alipay/tls13-sm-spec/blob/master/sm-en-pdfs/sm2/GBT.32918.4-2016.SM2-en.pdf

    Args:
        C: A list of ciphertext list.
        d: A integer of the private key.

    Returns:
        A string of the plaintext after decryption.
    """
    C1, C2, C3 = C

    klen = len(C2)
    # B1: Get C2 from C and convert the data type of C1 to the point of the elliptic curve.
    # Then, verify whether C1 satisfies the elliptic curve equation.
    PC = C1[:8]
    C1 = C1[8:]
    C1 = Point(
        Point.bits_to_elem(C1[:len(C1) // 2]),
        Point.bits_to_elem(C1[len(C1) // 2:])
    )
    if not C1.is_in_curve():
        return False
    # B2: Compute point S=[h]C1 of the elliptic curve. If S is the infinity point, then output error and exit.
    # Note that h is the cofactor of n (See 5.2 System parameters of elliptic curves).
    h = int(ec.n / ec.p)
    S = C1.multiply(h)
    if S.is_inf():
        return False
    # B3: Compute [d_B]C1=(x_2, y_2) and convert the data type of x_2, y_2 to bit string.
    dC = C1.multiply(d)
    # B4: Compute t=KDF(x_2||y_2, klen) If t is all zero bit string, then output error and exit.
    t = KDF(dC.to_bits("xy"), klen)
    if int(t, base=2) == 0:
        return False
    # B5: Get C2 from C and compute M′=C2 XOR t
    MM = xor(C2, t)
    # B6: Compute u=Hash(x_2||M′||y_2). Get C3 from C If u!=C3, output error and exit.
    u = hash_bits(dC.to_bits("x") + MM + dC.to_bits("y"))
    if u != C3:
        return False
    # B7: Output the plaintext M.
    return MM


if __name__ == "__main__":

    print(
        "System parameters of ellipse curve:\n"
        f"p: {hex(ec.p)}\n"
        f"a: {hex(ec.a)}\n"
        f"b: {hex(ec.b)}\n"
        f"n: {hex(ec.n)}\n"
        f"Gx: {hex(ec.Gx)}\n"
        f"Gy: {hex(ec.Gy)}\n"
        "\n"
    )

    # Generate key pair.
    print("Key Generation:")
    with DebugTimer("Key generation"):
        d, P = generate_key()
    print(
        f"d: {hex(d)}\n"
        f"Px: {hex(P.x)}\n"
        f"Py: {hex(P.y)}\n"
        "\n"
    )

    # Input the message.
    msg = input("Please input the plaintext: ")

    # SM2 Encryption.
    with DebugTimer("SM2 encryption"):
        plain_text = str_to_bit(msg)
        cipher_text = encrypt(plain_text, P)
        hex_result = ''.join(hex(int(c, base=2)) for c in cipher_text)
    print('The ciphertext is:', hex_result)

    # SM2 Decryption.
    with DebugTimer("SM2 decryption"):
        decrypt_text = decrypt(cipher_text, d)
        decrypt_text = bit_to_str(decrypt_text)
    print('The plaintext is:', decrypt_text)
