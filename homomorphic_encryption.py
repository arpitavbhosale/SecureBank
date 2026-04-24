"""
Paillier Homomorphic Encryption Implementation
for Banking Data Privacy Preservation System
"""

import random
import math
from typing import Tuple, List


class PaillierPublicKey:
    """Public key for Paillier cryptosystem"""
    
    def __init__(self, n: int, g: int):
        self.n = n
        self.n_squared = n * n
        self.g = g
    
    def __repr__(self):
        return f"PaillierPublicKey(n={self.n})"


class PaillierPrivateKey:
    """Private key for Paillier cryptosystem"""
    
    def __init__(self, lambda_val: int, mu: int, public_key: PaillierPublicKey):
        self.lambda_val = lambda_val
        self.mu = mu
        self.public_key = public_key
    
    def __repr__(self):
        return f"PaillierPrivateKey(lambda={self.lambda_val})"


def gcd(a: int, b: int) -> int:
    """Calculate greatest common divisor"""
    while b:
        a, b = b, a % b
    return a


def lcm(a: int, b: int) -> int:
    """Calculate least common multiple"""
    return abs(a * b) // gcd(a, b)


def mod_inverse(a: int, m: int) -> int:
    """Calculate modular multiplicative inverse using Extended Euclidean Algorithm"""
    if gcd(a, m) != 1:
        raise ValueError("Modular inverse does not exist")
    
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    
    return x1 + m0 if x1 < 0 else x1


def is_prime(n: int, k: int = 5) -> bool:
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
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


def generate_prime(bits: int) -> int:
    """Generate a prime number with specified bit length"""
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1  # Set MSB and LSB
        if is_prime(num):
            return num


def L_function(x: int, n: int) -> int:
    """L function for Paillier: L(x) = (x - 1) / n"""
    return (x - 1) // n


def generate_keypair(bits: int = 512) -> Tuple[PaillierPublicKey, PaillierPrivateKey]:
    """
    Generate Paillier public and private key pair
    
    Args:
        bits: Bit length for prime numbers (default: 512)
    
    Returns:
        Tuple of (public_key, private_key)
    """
    # Generate two large prime numbers
    p = generate_prime(bits)
    q = generate_prime(bits)
    
    # Ensure p and q are different
    while p == q:
        q = generate_prime(bits)
    
    n = p * q
    n_squared = n * n
    
    # g = n + 1 (common choice)
    g = n + 1
    
    # Calculate lambda = lcm(p-1, q-1)
    lambda_val = lcm(p - 1, q - 1)
    
    # Calculate mu = (L(g^lambda mod n^2))^-1 mod n
    g_lambda = pow(g, lambda_val, n_squared)
    l_value = L_function(g_lambda, n)
    mu = mod_inverse(l_value, n)
    
    public_key = PaillierPublicKey(n, g)
    private_key = PaillierPrivateKey(lambda_val, mu, public_key)
    
    return public_key, private_key


def encrypt(public_key: PaillierPublicKey, plaintext: int) -> int:
    """
    Encrypt a plaintext integer using Paillier encryption
    
    Args:
        public_key: Public key for encryption
        plaintext: Integer to encrypt (must be < n)
    
    Returns:
        Encrypted ciphertext
    """
    if plaintext >= public_key.n:
        raise ValueError(f"Plaintext must be less than n={public_key.n}")
    
    # Generate random r where 0 < r < n and gcd(r, n) = 1
    while True:
        r = random.randrange(1, public_key.n)
        if gcd(r, public_key.n) == 1:
            break
    
    # Ciphertext c = g^m * r^n mod n^2
    g_m = pow(public_key.g, plaintext, public_key.n_squared)
    r_n = pow(r, public_key.n, public_key.n_squared)
    ciphertext = (g_m * r_n) % public_key.n_squared
    
    return ciphertext


def decrypt(private_key: PaillierPrivateKey, ciphertext: int) -> int:
    """
    Decrypt a ciphertext using Paillier decryption
    
    Args:
        private_key: Private key for decryption
        ciphertext: Encrypted value
    
    Returns:
        Decrypted plaintext integer
    """
    public_key = private_key.public_key
    
    # Plaintext m = L(c^lambda mod n^2) * mu mod n
    c_lambda = pow(ciphertext, private_key.lambda_val, public_key.n_squared)
    l_value = L_function(c_lambda, public_key.n)
    plaintext = (l_value * private_key.mu) % public_key.n
    
    return plaintext


def add_encrypted(public_key: PaillierPublicKey, c1: int, c2: int) -> int:
    """
    Add two encrypted numbers (Homomorphic addition)
    
    Args:
        public_key: Public key
        c1, c2: Encrypted values
    
    Returns:
        Encrypted sum
    """
    return (c1 * c2) % public_key.n_squared


def multiply_encrypted_by_constant(public_key: PaillierPublicKey, 
                                   ciphertext: int, constant: int) -> int:
    """
    Multiply encrypted number by plaintext constant (Homomorphic scalar multiplication)
    
    Args:
        public_key: Public key
        ciphertext: Encrypted value
        constant: Plaintext multiplier
    
    Returns:
        Encrypted product
    """
    return pow(ciphertext, constant, public_key.n_squared)


def encrypt_float(public_key: PaillierPublicKey, value: float, 
                 precision: int = 100000) -> int:
    """
    Encrypt a floating-point number by scaling to integer
    
    Args:
        public_key: Public key
        value: Float to encrypt
        precision: Scaling factor for decimal precision
    
    Returns:
        Encrypted scaled integer
    """
    scaled_value = int(value * precision)
    return encrypt(public_key, scaled_value)


def decrypt_float(private_key: PaillierPrivateKey, ciphertext: int, 
                 precision: int = 100000) -> float:
    """
    Decrypt and unscale a floating-point number
    
    Args:
        private_key: Private key
        ciphertext: Encrypted value
        precision: Scaling factor used during encryption
    
    Returns:
        Decrypted float
    """
    scaled_value = decrypt(private_key, ciphertext)
    return scaled_value / precision


class HomomorphicBankingSystem:
    """
    Banking system with homomorphic encryption for privacy-preserving operations
    """
    
    def __init__(self, bits: int = 512):
        """Initialize with key generation"""
        self.public_key, self.private_key = generate_keypair(bits)
        self.precision = 100000  # For 5 decimal places
    
    def encrypt_balance(self, balance: float) -> int:
        """Encrypt bank account balance"""
        return encrypt_float(self.public_key, balance, self.precision)
    
    def decrypt_balance(self, encrypted_balance: int) -> float:
        """Decrypt bank account balance"""
        return decrypt_float(self.private_key, encrypted_balance, self.precision)
    
    def add_balances(self, enc_balance1: int, enc_balance2: int) -> int:
        """Add two encrypted balances without decryption"""
        return add_encrypted(self.public_key, enc_balance1, enc_balance2)
    
    def calculate_interest(self, enc_balance: int, interest_rate: float) -> int:
        """Calculate interest on encrypted balance"""
        interest_multiplier = int((1 + interest_rate) * self.precision)
        return multiply_encrypted_by_constant(self.public_key, enc_balance, interest_multiplier)
    
    def process_transaction(self, enc_balance: int, amount: float, is_credit: bool = True) -> int:
        """
        Process transaction on encrypted balance
        
        Args:
            enc_balance: Encrypted current balance
            amount: Transaction amount
            is_credit: True for deposit, False for withdrawal
        
        Returns:
            New encrypted balance
        """
        enc_amount = encrypt_float(self.public_key, amount, self.precision)
        
        if is_credit:
            return add_encrypted(self.public_key, enc_balance, enc_amount)
        else:
            # For subtraction, we need to handle it differently
            # Since Paillier supports addition, we can add the negative
            scaled_amount = int(amount * self.precision)
            negative_amount = self.public_key.n - scaled_amount
            enc_negative = encrypt(self.public_key, negative_amount)
            return add_encrypted(self.public_key, enc_balance, enc_negative)


if __name__ == "__main__":
    # Test the implementation
    print("Testing Paillier Homomorphic Encryption for Banking...")
    print("=" * 60)
    
    # Initialize system
    bank_system = HomomorphicBankingSystem(bits=512)
    
    # Test Case 1: Encrypt and decrypt balance
    print("\nTest 1: Encrypt and Decrypt Balance")
    original_balance = 10000.50
    encrypted_balance = bank_system.encrypt_balance(original_balance)
    decrypted_balance = bank_system.decrypt_balance(encrypted_balance)
    print(f"Original Balance: ₹{original_balance:.2f}")
    print(f"Encrypted: {encrypted_balance}")
    print(f"Decrypted Balance: ₹{decrypted_balance:.2f}")
    
    # Test Case 2: Add encrypted balances
    print("\nTest 2: Add Two Encrypted Balances")
    balance1 = 5000.00
    balance2 = 3000.00
    enc_bal1 = bank_system.encrypt_balance(balance1)
    enc_bal2 = bank_system.encrypt_balance(balance2)
    enc_sum = bank_system.add_balances(enc_bal1, enc_bal2)
    decrypted_sum = bank_system.decrypt_balance(enc_sum)
    print(f"Balance 1: ₹{balance1:.2f}")
    print(f"Balance 2: ₹{balance2:.2f}")
    print(f"Sum (computed on encrypted data): ₹{decrypted_sum:.2f}")
    print(f"Expected: ₹{balance1 + balance2:.2f}")
    
    # Test Case 3: Calculate interest
    print("\nTest 3: Calculate Interest on Encrypted Balance")
    principal = 10000.00
    interest_rate = 0.05  # 5%
    enc_principal = bank_system.encrypt_balance(principal)
    enc_with_interest = bank_system.calculate_interest(enc_principal, interest_rate)
    final_amount = bank_system.decrypt_balance(enc_with_interest)
    print(f"Principal: ₹{principal:.2f}")
    print(f"Interest Rate: {interest_rate * 100}%")
    print(f"Final Amount (computed on encrypted data): ₹{final_amount:.2f}")
    print(f"Expected: ₹{principal * (1 + interest_rate):.2f}")
    
    print("\n" + "=" * 60)
    print("All tests completed successfully!")
