import datetime

from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import CAST, DES3, AES
from Crypto.Random import get_random_bytes
import rsa


class PrivateRingStruct:
    def __init__(self, pu, pr, alg, password):
        self.timestamp = datetime.datetime.now()
        self.pu = pu
        self.pr = pr
        self.alg = alg
        self.password = password

    def __str__(self):
        return "ts: " + str(self.timestamp) + ", PU: " + str(self.pu) + ", PR: " + str(self.pr) + ", alg: " + self.alg


class PublicRingStruct:
    def __init__(self, pu, alg, userID):
        self.timestamp = datetime.datetime.now()
        self.pu = pu
        self.alg = alg
        self.userID = userID

    def __str__(self):
        return "ts: " + str(self.timestamp) + ", PU: " + str(self.pu) + ", alg: " + self.alg + ", user: " + self.userID


# {userID:janko@gmam. ring:[{puId:.... , }.{}]}

publicRing = {}
privateRing = {}

def getHash(password):
    digest = hashes.Hash(hashes.SHA1())
    ba = bytearray(password.encode('utf-8'))
    digest.update(ba)
    hp = (digest.finalize())
    hashedPassword = hp[-16:]
    return hp, hashedPassword
def encryptPrivateKey(password, key):
    hp, hashedPassword = getHash(password)
    # print(hashedPassword)

    cipher = CAST.new(hashedPassword, CAST.MODE_OPENPGP)

    plain = (key).save_pkcs1('PEM')

    # print(plain)
    msg = cipher.encrypt(plain)
    return msg, hp

def decryptPrivateKey(password, key, hashedPass):
    hp, _ = getHash(password)
    if hp != hashedPass:
        return None

    cipher = CAST.new(hashedPass, CAST.MODE_OPENPGP)
    return cipher.decrypt(key)


def generateKeysRSA(size):
    return rsa.newkeys(size)


def generateKeysDSA(size):
    pass


def deleteKeys(keyID, email):
    del privateRing[email][keyID]
    del publicRing[keyID]
    return


def saveKeyInPemFormat(key, title):
    with open(f'keys/{title}.pem', 'wb') as p:
        p.write(key.save_pkcs1('PEM'))


def loadPrivateKeyFromPemFormat(title, email, password):
    with open(f'keys/{title}.pem', 'rb') as p:
        privateKey = rsa.PrivateKey.load_pkcs1(p.read())
        if not privateRing.get(email):
            privateRing[email] = {}

        msg, hp = encryptPrivateKey(password, privateKey)
        publicKey = rsa.PublicKey(privateKey["n"], privateKey["e"])
        (privateRing[email])[privateKey["n"] % (2 ** 64)] = PrivateRingStruct(
            publicKey, msg, "RSA", hp)

        publicRing[publicKey["n"] % (2 ** 64)] = PublicRingStruct(publicKey, "RSA", email)
        return privateKey


def loadPublicKeyFromPemFormat(title, email):
    with open(f'keys/{title}.pem', 'rb') as p:
        publicKey = rsa.PublicKey.load_pkcs1(p.read())
        publicRing[publicKey["n"] % (2 ** 64)] = PublicRingStruct(publicKey, "RSA", email)
        return publicKey


def generateKeys():
    name = "Iva"  # input("Unesite ime")
    email = "iva@gmail.com"  # input("Unesite email")
    algo = "RSA"  # input("Unesite algoritam ")
    size = 1024  # int(input("Unesite velicini"))
    keys = None
    if algo == "RSA":
        keys = generateKeysRSA(size)
    else:
        keys = generateKeysDSA(size)
    password = input("Unesite lozinku")

    msg, hp = encryptPrivateKey(password, keys[1])
    # print(msg)

    # Dodavanje u prsten

    if not privateRing.get(email):
        privateRing[email] = {}

    (privateRing[email])[keys[0]["n"] % (2 ** 64)] = PrivateRingStruct(keys[0], msg, algo, hp)

    publicRing[keys[0]["n"] % (2 ** 64)] = PublicRingStruct(keys[0], algo, email)

    saveKeyInPemFormat(keys[1], "test")
    print(keys[1])


def msgAuth(msg, privateKey):
    digest = hashes.Hash(hashes.SHA1())
    ba = bytearray(msg.encode('utf-8'))
    digest.update(ba)
    hashMsg = digest.finalize()

    return rsa.encrypt(hashMsg, privateKey)


def sendMessage(email, password, msg, name, publicKeyAuthID=None, publicKeySec=None):
    toSend = {}
    toSend["data"] = msg
    toSend["ts"] = datetime.datetime.now()
    toSend["filename"] = name

    if (publicKeyAuthID is None):
        tmp = privateRing[email][publicKeyAuthID]
        privateKeyAuth = decryptPrivateKey(password, tmp["pr"], tmp["password"])
        if privateKeyAuth is None:
            return "error"
        authAlg = tmp["alg"]


        toSend["digest"] = msgAuth(toSend, privateKeyAuth)
        toSend["octets"] = None
        toSend["authKeyID"] = publicKeyAuthID
        toSend["tsAuth"] = datetime.datetime.now()
        toSend["alg"] = authAlg


if __name__ == '__main__':
    print('ZP Projekat v1.1')
    generateKeys()  # dodati elgamal-dsa, publicRing
    print(loadPrivateKeyFromPemFormat("test"))
