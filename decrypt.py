from builtins import bytes
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

SECRET_SALT = 'BTQE4MwD6j3kTapkr94uwXDpZG5E3sS7'.encode('utf-8')


def password_to_key(password):
    """
    Use SHA-256 over our password to get a proper-sized AES key.
    This hashes our password into a 256 bit string.
    """
    return SHA256.new(password).digest()


def make_initialization_vector():
    """
    An initialization vector (IV) is a fixed-size input to a cryptographic
    primitive that is typically required to be random or pseudorandom.
    Randomization is crucial for encryption schemes to achieve semantic
    security, a property whereby repeated usage of the scheme under the
    same key does not allow an attacker to infer relationships
    between segments of the encrypted message.
    """
    return Random.new().read(AES.block_size)


def pad_string(string, chunk_size=AES.block_size):
    """
    Pad string the peculirarity that uses the first byte
    is used to store how much padding is applied
    """
    assert chunk_size <= 256, 'We are using one byte to represent padding'
    to_pad = (chunk_size - (len(string) + 1)) % chunk_size
    return bytes([to_pad]) + string + bytes([0] * to_pad)


def unpad_string(string):
    to_pad = string[0]
    return string[1:-to_pad]


def encode(string):
    """
    Base64 encoding schemes are commonly used when there is a need to encode
    binary data that needs be stored and transferred over media that are
    designed to deal with textual data.
    This is to ensure that the data remains intact without
    modification during transport.
    """
    return base64.b64encode(string).decode("latin-1")


def decode(string):
    return base64.b64decode(string.encode("latin-1"))


def encrypt(string, password):
    """
    It returns an encrypted string which can be decrypted just by the
    password.
    """
    key = password_to_key(password)
    IV = make_initialization_vector()
    encryptor = AES.new(key, AES.MODE_CBC, IV)

    # store the IV at the beginning and encrypt
    return IV + encryptor.encrypt(pad_string(string))


def decrypt(string, password):
    key = password_to_key(password)

    # extract the IV from the beginning
    IV = string[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, IV)

    string = decryptor.decrypt(string[AES.block_size:])
    return unpad_string(string)


user_username = 'PassUsernameHere'.encode('utf-8')
user_password = 'PassPasswordHere'.encode('utf-8')

encrypted_username = encrypt(user_username, SECRET_SALT)
encrypted_password = encrypt(user_password, SECRET_SALT)

# print('encrypted_username', encrypted_username)
# print('encrypted_password', encrypted_password)

decrypted_username = decrypt(encrypted_username, SECRET_SALT)
decrypted_password = decrypt(encrypted_password, SECRET_SALT)
# print('decrypted_username', decrypted_username)
# print('decrypted_password', decrypted_password)