from Cryptodome.Cipher import CAST
from Cryptodome.Hash import SHA1

from Cryptodome.PublicKey import DSA, ElGamal, RSA
from Cryptodome.Random import get_random_bytes
import datetime


class PrivateRingStruct:
    def __init__(self, pu, pr, alg, password):
        self.timestamp = str(datetime.datetime.now())
        self.pu = pu
        self.pr = pr
        self.alg = alg
        self.password = password

    def __str__(self):
        return "Timestamp: " + self.timestamp + "\nAlgorithm: " + self.alg +"\n\n"


class PublicRingStruct:
    def __init__(self, pu, alg, userID):
        self.timestamp = datetime.datetime.now()
        self.pu = pu
        self.alg = alg
        self.userID = userID

    def __str__(self):
        if self.alg=="RSA":
            parametres="\ne: "+str(self.pu.e)+"\nn:"+str(self.pu.n)
        else:
            parametres = "\np: " + str(self.pu.p) + "\ng:" + str(self.pu.g)+ "\ny: "+str(self.pu.y)
        return "Timestamp: " + str(self.timestamp) +"\nAlgorithm: " + self.alg + parametres+"\nUser: " + self.userID+"\n\n"


def getHash(password):
    digest = SHA1.new()
    ba = bytearray(password.encode('utf-8'))
    digest.update(ba)
    hp = (digest.hexdigest())
    hashedPassword = hp[-16:]
    return hp, hashedPassword


def encryptPrivateKey(password, key, algo):
    hp, hashedPassword = getHash(password)

    cipher = CAST.new(bytearray(hashedPassword.encode('utf-8')), CAST.MODE_OPENPGP)
    plain = None
    if algo == "RSA":
        plain = key.export_key('PEM')
    elif algo == "DSA":
        plain = key.export_key('PEM')
    else:
        toWrite = {"p": int(key.p), "g": int(key.g), "y": int(key.y), "x": int(key.x)}
        plain = (bytearray(str(toWrite).encode('utf-8')))

    msg = cipher.encrypt(plain)
    return msg, hp


def decryptPrivateKey(password, key, hashedPass, algo):
    hp, hashedPassword = getHash(password)
    if hp != hashedPass:
        return None

    eiv = key[:CAST.block_size + 2]
    ciphertext = key[CAST.block_size + 2:]
    cipher = CAST.new(bytearray(hashedPassword.encode("utf-8")), CAST.MODE_OPENPGP, eiv)

    tmp = cipher.decrypt(ciphertext)

    tmp = tmp.decode('utf-8')
    if algo == "RSA":
        return RSA.import_key(tmp)#rsa.PrivateKey.load_pkcs1(tmp)
    elif algo == "DSA":
        return DSA.import_key(tmp)
    else:
        toWrite = eval(tmp)
        return ElGamal.construct((toWrite["p"], toWrite["g"], toWrite["y"], toWrite["x"]))


def generateKeysRSA(size):
    return RSA.generate(size)#rsa.newkeys(size)


def generateKeysDSA(size):
    return DSA.generate(size)


def generateKeysElGamal(size):
    return ElGamal.generate(size, get_random_bytes)
