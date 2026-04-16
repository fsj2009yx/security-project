import random

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        g, x, y = extended_gcd(b, a % b)
        return (g, y, x - (a // b) * y)

def mod_inverse(e, phi):
    g, x, y = extended_gcd(e, phi)
    if g != 1:
        raise Exception('模逆元不存在')
    else:
        return x % phi

def is_prime(n, k=5):
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False
    
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if num % 2 == 0:
            num += 1
        if is_prime(num):
            return num

def generate_rsa_keys(bits=1024):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def encrypt(message, public_key):
    e, n = public_key
    if isinstance(message, str):
        message = message.encode()
    message_int = int.from_bytes(message, byteorder='big')
    if message_int >= n:
        raise Exception('消息长度超过密钥长度')
    cipher_int = pow(message_int, e, n)
    return cipher_int

def decrypt(cipher_int, private_key):
    d, n = private_key
    message_int = pow(cipher_int, d, n)
    message = message_int.to_bytes((message_int.bit_length() + 7) // 8, byteorder='big')
    try:
        return message.decode()
    except:
        return message

def sign(message, private_key):
    d, n = private_key
    if isinstance(message, str):
        message = message.encode()
    message_int = int.from_bytes(message, byteorder='big')
    signature_int = pow(message_int, d, n)
    return signature_int

def verify(message, signature, public_key):
    e, n = public_key
    if isinstance(message, str):
        message = message.encode()
    message_int = int.from_bytes(message, byteorder='big')
    signature_int = pow(signature, e, n)
    return signature_int == message_int