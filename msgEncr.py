from Cryptodome.Cipher import DES3, AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import unpad, pad
import random
import rsa




def encryptMsg(msg, alg):
    kS = None
    eMsg = None
    ba = bytearray(str(msg).encode('utf-8'))
    if alg == "3DES":
        while True:
            try:
                kS = DES3.adjust_key_parity(get_random_bytes(24))
                break
            except ValueError:
                pass
        cipher = DES3.new(kS, DES3.MODE_CBC)
        iv = cipher.iv
        eMsg = cipher.encrypt(pad(ba, DES3.block_size))

    elif alg == "AES":
        kS = get_random_bytes(16)
        cipher = AES.new(kS, AES.MODE_CBC)
        eMsg = cipher.encrypt(pad(ba, AES.block_size))
        iv = cipher.iv
        print(iv)

    return kS, eMsg, iv


def decryptMsg(eMsg, alg, kS, iv):
    msg = None
    if alg == "3DES":
        cipher = DES3.new(kS, DES3.MODE_CBC, iv=iv)
        msg = unpad(cipher.decrypt(eMsg), DES3.block_size)
    elif alg == "AES":
        cipher = AES.new(kS, AES.MODE_CBC, iv=iv)
        m=cipher.decrypt(eMsg)
        msg = unpad(m, AES.block_size)

    return msg


def encryptKs(kS, publicKey, alg):
    if alg == "RSA":
        rsaKey = PKCS1_OAEP.new(publicKey)
        return rsaKey.encrypt(kS)
        #return rsa.encrypt(kS, publicKey)
    else:
        return publicKey._encrypt(int.from_bytes(kS, 'big'), int(random.randint(1, publicKey.p - 1)))


def decryptKs(kS, privateKey, alg):
    if alg == "RSA":
        #return rsa.decrypt(kS, privateKey)
        rsaKey = PKCS1_OAEP.new(privateKey)
        return rsaKey.decrypt(kS)
    else:
        return privateKey._decrypt(tuple(kS)).to_bytes(24, 'big')
