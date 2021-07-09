# in this file there are 2 functions (encrypt & decrypt) for encrypting and decrypting text
# using these functions your credentails are encrypted and safe
# i got the functions from this site: https://qvault.io/cryptography/aes-256-cipher-python-cryptography-examples/
# it was very helpful and the functions are pretty much the same but i just changed the format of encrypting


from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes


def encrypt(plain_text: str, password: str):
    """encrypting plain text using AES encryption

    Args:
        plain_text (str): plain text to encrypt
        password (str): the password for decrypting the text later

    Returns:
        str: encrypted text in the format: "salt.nonce.tag.cipher_text"
    """

    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))

    chiper_text = b64encode(cipher_text).decode('utf-8')
    salt = b64encode(salt).decode('utf-8')
    nonce = b64encode(cipher_config.nonce).decode('utf-8')
    tag = b64encode(tag).decode('utf-8')

    return salt + "." + nonce + "." + tag + "." + chiper_text


def decrypt(encrypted_text: str, password: str):
    """decrypting the encrypted text using AES encryption
    if the password is wrong an exception is thrown

    Args:
        encrypted_text (str): the encrypted text to decrypt
        password (str): the password to use in the decryption

    Returns:
        str: the decrypted text
    """
    # decode the dictionary entries from base64
    enc_dict = encrypted_text.split(".")
    salt = b64decode(enc_dict[0])
    nonce = b64decode(enc_dict[1])
    tag = b64decode(enc_dict[2])
    cipher_text = b64decode(enc_dict[3])

    # generate the private key from the password and salt
    private_key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted.decode()
