"""
Python implementation of CBC HMAC authenticated encryption
"""

from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac


class AEAD(object):
    """
    Authenticated encryption and decryption
    """
    def __init__(self, block_len, mac_key, enc_key):
        self.block_len = block_len
        self.mac_key = mac_key
        self.enc_key = enc_key

    def authenticated_enc(self, data, aad, nonce):
        """
        Authenticated encryption
        :param data: input data
        :param aad: additional associated data
        :param nonce: nonce
        :return: c, the result of authenticated encryption
        """
        raise NotImplementedError("Must override authenticated_enc")


    def authenticated_dec(self, c, aad, nonce):
        """
        Authenticated decryption
        :param c: ciphertext
        :param aad: additional associated data
        :param nonce: nonce
        :return: decrypted data if verification succeeds, fail state else.
        """

        raise NotImplementedError("Must override authenticated_dec")


class AEAD_AES_128_CBC_HMAC_SHA_256(AEAD):
    def __init__(self, *args):
        self.block_len = 16
        self.mac_len = 16
        super(AEAD_AES_128_CBC_HMAC_SHA_256, self).__init__(self.block_len, *args)

    def __strip_padding(self, data):
        """
        Strip all padding from the data
        :param data: input data
        :return: stripped data
        """
        try:
            pad_len = data[-1]
            return data[:-(pad_len + 1)]
        except:
            # print("\nERROR: error in pad stripping")
            None

    def __pad(self, data):
        """
        Pad the data so that the block size is a multiple of block_len
        :param data: input data
        :return: padded data with length an integral multiple of block_len
        """
        pad_len  = 15 - len(data) % 16
        
        pad_byte = pad_len.to_bytes(1, byteorder='big')
        
        return data + pad_byte * (pad_len + 1)
        
    def __auth(self, data):
        """
        Call HMAC_SHA_256
        """
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    def __encrypt(self, p, nonce):
        """
        Encrypt using AES_128_CBC
        """
        cipher = Cipher(algorithms.AES(self.enc_key), modes.CBC(nonce))
        encryptor = cipher.encryptor()
        return encryptor.update(p) + encryptor.finalize()

    def __decrypt(self, c, nonce):
        """
        Decrypt using AES_128_CBC
        """
        cipher = Cipher(algorithms.AES(self.enc_key), modes.CBC(nonce))
        decryptor = cipher.decryptor()
        return decryptor.update(c) + decryptor.finalize()

    def authenticated_enc(self, data, aad, nonce):
        """
        Authenticated encryption
        :param data: input data
        :param aad: additional associated data
        :param nonce: nonce
        :return: c, the result of authenticated encryption
        """
        tag = self.__auth(aad + data)[:16]

        p = self.__pad(data + tag)

        c = self.__encrypt(p, nonce)

        return c


    def authenticated_dec(self, c, aad, nonce):
        """
        Authenticated decryption
        :param c: ciphertext
        :param aad: additional associated data
        :param nonce: nonce
        :return: decrypted data if verification succeeds, fail state else.
        """
        p = self.__decrypt(c, nonce)

        # padding validation
        alleged_len = p[-1]
        is_valid = (p[-(alleged_len+1):-1] == p[-1:] * alleged_len)
        if is_valid:
            pass
        else:
            # print(f"\nERROR: invalid padding: \n{p[-16:]} \n{alleged_len} \n{p[-alleged_len:-1]}")
            return None

        stripped_data = self.__strip_padding(p)
        if stripped_data == None:
            return None
        data, alleged_tag = stripped_data[:-16], stripped_data[-16:]

        tag = self.__auth(aad + data)[:16]
        if (tag == alleged_tag):
            pass
        else:
            # print(f"\nERROR: invalid tag: \n\t{tag} \n\t{alleged_tag}")
            return None

        return data



if __name__ == "__main__":
    # data = b"\xef8K\x17c\xb2hp\x1a$\xecS\x86\x9d\xbc\x11j\x01h\x15\xef\xbd,\xfd\xdc\xb4'\xc2\x03\xfa\t\x05\x81\xa3\xdf\xea*{\x8c\xe4\xbcRq\xe1\xfe\xc4\xd7\x12\x93qH\xff\xb8\xd1\x8f\xb8S\xae\xf6\x9c\xc7j{ 67\xfccH\xf4v)\x94\xa6\x14\xf7\xac\x94\xb4?\x1c_\x12Y\x94:Q\x9c\xa0\xd8n\xc6R\xdc\xc7W\xe2\xb0\x1c5"
    # aad = b"{ \xff\x1b\xca\x98\xd0\xe5\xa55\xca\xa9\xd2U\x8a8\x90K4\x90\xb2\xfa\xa9?O\x80\xea\xa2\x85\xa2ECMEo(\x1f'\x01\xf1\xa4\xd4J\x9a\xfc\xf3\x89\x93\x86\xcf"
    # mac_key = b'\x9e\xdf\xdd\xb1|;\xd4\xbc\xff\x03\xb7\tZy\xef\xeb'
    # enc_key = b'\xdfei\xac\x86\xa5U_r\xff\r\x1c\x8d\x02\xac\x97'
    # aead = AEAD_AES_128_CBC_HMAC_SHA_256(mac_key, enc_key)
    # nonce = b'T\xbaS\x87M\x9dn\xca\xe8\xb0\xcfx\x8c@W\x87'

    data = b'secret data'
    aad = b'more data'
    mac_key = urandom(16)
    enc_key = urandom(16)
    aead = AEAD_AES_128_CBC_HMAC_SHA_256(mac_key, enc_key)
    nonce = urandom(16)
    
    print(f"data = {data}")
    print(f"aad = {aad}")
    print(f"mac_key = {mac_key}")
    print(f"enc_key = {enc_key}")
    print(f"nonce = {nonce}")
    ciphertext = aead.authenticated_enc(data, aad, nonce)
    print(f"ciphertext = {ciphertext}")

    p = aead.authenticated_dec(ciphertext, aad, nonce)
    print(p)
    print(len(data))
    print(len(ciphertext))