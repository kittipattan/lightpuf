from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class AESGCMCipher:
    """
    A class that provides AES-GCM encryption and decryption operations.

    AES-GCM (Advanced Encryption Standard with Galois/Counter Mode) is an authenticated encryption algorithm
    that ensures both confidentiality and data integrity. It encrypts the plaintext and provides authentication 
    for associated data (AD), which can be metadata that is not encrypted but needs to be authenticated.

    Attributes:
        key (bytes): The secret key used for encryption and decryption. It must be 16, 24, or 32 bytes 
                     long for AES-128, AES-192, or AES-256, respectively.
        aesgcm (AESGCM): An instance of the AESGCM cipher using the provided key.
    """

    def __init__(self, key: bytes):
        """
        Initializes the AESGCMCipher class with a given key.

        Args:
            key (bytes): The encryption key, which must be either 16, 24, or 32 bytes long for AES-128,
                         AES-192, or AES-256, respectively.

        Raises:
            ValueError: If the key length is invalid.
        """
        self.key = key
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes = None) -> bytes:
        """
        Encrypts the given plaintext using AES-GCM with optional associated data (AD).

        The nonce must be provided externally to ensure the uniqueness for each encryption operation. 
        It is recommended to use a unique 12-byte nonce for each encryption.

        Args:
            nonce (bytes): A 12-byte unique nonce to use for encryption.
            plaintext (bytes): The data to be encrypted.
            associated_data (bytes, optional): Additional data to authenticate but not encrypt (such as 
                                               headers or metadata). If not provided, no associated data will 
                                               be authenticated.

        Returns:
            bytes: The ciphertext, which includes the authentication tag.

        Raises:
            ValueError: If any of the provided arguments are invalid.
        """
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes long")
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data)  # Encrypt the plaintext
        return ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
        """
        Decrypts the given ciphertext using AES-GCM, verifying the optional associated data (AD) for integrity.

        The nonce used during encryption must be provided, along with the ciphertext and any associated data.
        If the associated data or ciphertext has been tampered with, decryption will fail and raise an exception.

        Args:
            nonce (bytes): The 12-byte nonce used during encryption.
            ciphertext (bytes): The encrypted data, including the authentication tag.
            associated_data (bytes, optional): The associated data that was authenticated during encryption. 
                                               If provided, it must match the data used during encryption.

        Returns:
            bytes: The decrypted plaintext if decryption and authentication are successful.

        Raises:
            InvalidTag: If decryption fails due to mismatched associated data or corrupted ciphertext.
            ValueError: If any of the provided arguments are invalid.
        """
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes long")
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, associated_data)  # Decrypt the ciphertext
        return plaintext

class AESCBCCipher:
    """
    A class that provides AES-CBC encryption and decryption operations.
    
    AES-CBC (Advanced Encryption Standard with Cipher Block Chaining) is a block cipher mode 
    that provides confidentiality by encrypting blocks of data with a specific key and IV (Initialization Vector).

    Attributes:
        key (bytes): The secret key used for encryption and decryption. It must be 16, 24, or 32 bytes 
                     long for AES-128, AES-192, or AES-256, respectively.
    """

    def __init__(self, key: bytes):
        """
        Initializes the AESCipher class with a given key.

        Args:
            key (bytes): The encryption key, which must be either 16, 24, or 32 bytes long for AES-128, AES-192,
                         or AES-256, respectively.

        Raises:
            ValueError: If the key length is invalid.
        """
        self.block_size = 16  # AES block size is fixed at 16 bytes
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256.")
        self.key = key

    def encrypt(self, plain_text: bytes) -> bytes:
        """
        Encrypts the given plaintext (as bytes) using AES-CBC with a random IV.

        Args:
            plain_text (bytes): The plaintext data to be encrypted.

        Returns:
            bytes: The IV concatenated with the ciphertext.
        """
        padded_plaintext = self.__pad(plain_text)  # Apply byte-based padding
        iv = os.urandom(self.block_size)  # Generate a random IV
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_text = encryptor.update(padded_plaintext) + encryptor.finalize()
        return iv + encrypted_text  # Return IV concatenated with the ciphertext

    def decrypt(self, encrypted_text: bytes) -> bytes:
        """
        Decrypts the given ciphertext using AES-CBC and the provided IV.

        Args:
            encrypted_text (bytes): The encrypted data, with the IV prepended.

        Returns:
            bytes: The decrypted plaintext.
        """
        iv = encrypted_text[:self.block_size]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(encrypted_text[self.block_size:]) + decryptor.finalize()
        return self.__unpad(padded_plaintext)  # Unpad and return bytes

    def __pad(self, plain_text: bytes) -> bytes:
        """
        Pads the plaintext using PKCS7-style padding to make it a multiple of the block size.

        Args:
            plain_text (bytes): The plaintext to pad.

        Returns:
            bytes: The padded plaintext.
        """
        padding_needed = self.block_size - len(plain_text) % self.block_size
        return plain_text + bytes([padding_needed]) * padding_needed

    @staticmethod
    def __unpad(plain_text: bytes) -> bytes:
        """
        Removes PKCS7-style padding from the plaintext.

        Args:
            plain_text (bytes): The padded plaintext.

        Returns:
            bytes: The unpadded plaintext.
        """
        padding_length = plain_text[-1]
        return plain_text[:-padding_length]

    

# import hashlib
# from Crypto import Random
# from Crypto.Cipher import AES
# from base64 import b64encode, b64decode

# class AESCipher(object):
#     def __init__(self, key):
#         self.block_size = AES.block_size
#         if isinstance(key, bytes):
#             self.key = key
#         elif isinstance(key, str):
#             self.key = hashlib.sha256(key.encode()).digest()

#     def encrypt(self, plain_text):
#         plain_text = self.__pad(plain_text)
#         iv = Random.new().read(self.block_size)
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         encrypted_text = cipher.encrypt(plain_text.encode())
#         return b64encode(iv + encrypted_text).decode("utf-8")

#     def decrypt(self, encrypted_text):
#         encrypted_text = b64decode(encrypted_text)
#         iv = encrypted_text[:self.block_size]
#         cipher = AES.new(self.key, AES.MODE_CBC, iv)
#         plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
#         return self.__unpad(plain_text)

#     def __pad(self, plain_text):
#         number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
#         ascii_string = chr(number_of_bytes_to_pad)
#         padding_str = number_of_bytes_to_pad * ascii_string
#         padded_plain_text = plain_text + padding_str
#         return padded_plain_text

#     @staticmethod
#     def __unpad(plain_text):
#         last_character = plain_text[len(plain_text) - 1:]
#         return plain_text[:-ord(last_character)]