import random
import hashlib


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd_val, x, y


def mod_inverse(e, phi):
    gcd_val, x, _ = extended_gcd(e, phi)
    
    if gcd_val != 1:
        raise ValueError("Modular inverse tidak ada")
    
    return x % phi


def is_prime(n, k=40):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def generate_prime(bits=512):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p


class RSA:
    
    def __init__(self, key_size=1024):
        print(f"Generating RSA keys ({key_size} bits)...")
        
        self.p = generate_prime(key_size // 2)
        self.q = generate_prime(key_size // 2)
        
        self.n = self.p * self.q
        
        self.phi = (self.p - 1) * (self.q - 1)
        
        self.e = 65537
        
        if gcd(self.e, self.phi) != 1:
            self.e = self._find_e()
        
        self.d = mod_inverse(self.e, self.phi)
        
        print(f"RSA keys generated successfully!")
    
    def _find_e(self):
        e = 65537
        while gcd(e, self.phi) != 1:
            e += 2
        return e
    
    def get_public_key(self):
        return (self.e, self.n)
    
    def get_private_key(self):
        return (self.d, self.n)
    
    def encrypt(self, message):
        if isinstance(message, str):
            message_int = int.from_bytes(message.encode(), 'big')
        else:
            message_int = message
        
        if message_int >= self.n:
            raise ValueError("Message terlalu besar untuk key size ini")
        
        ciphertext = pow(message_int, self.e, self.n)
        return ciphertext
    
    def decrypt(self, ciphertext):
        plaintext = pow(ciphertext, self.d, self.n)
        return plaintext
    
    def encrypt_with_public_key(self, message, public_key):
        e, n = public_key
        
        if isinstance(message, str):
            message_int = int.from_bytes(message.encode(), 'big')
        else:
            message_int = message
        
        if message_int >= n:
            raise ValueError("Message terlalu besar untuk key size ini")
        
        ciphertext = pow(message_int, e, n)
        return ciphertext
    
    def decrypt_to_string(self, ciphertext):
        plaintext_int = self.decrypt(ciphertext)
        
        byte_length = (plaintext_int.bit_length() + 7) // 8
        
        try:
            plaintext_bytes = plaintext_int.to_bytes(byte_length, 'big')
            plaintext_str = plaintext_bytes.decode('utf-8')
            return plaintext_str
        except:
            return str(plaintext_int)



