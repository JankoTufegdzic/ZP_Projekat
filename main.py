import datetime
import json
import ast

from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import CAST, DES3, AES
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes
import rsa

import base64


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
    digest = SHA1.new()#hashes.Hash(hashes.SHA1())
    ba = bytearray(password.encode('utf-8'))
    digest.update(ba)
    hp = (digest.hexdigest())
    hashedPassword = hp[-16:]
    return hp, hashedPassword
def encryptPrivateKey(password, key):
    hp, hashedPassword = getHash(password)
    # print(hashedPassword)

    cipher = CAST.new(bytearray(hashedPassword.encode('utf-8')), CAST.MODE_OPENPGP)

    plain = (key).save_pkcs1('PEM')
    # plain=pad(plain,CAST.block_size)

    # print(plain)
    msg = cipher.encrypt(plain)
    return msg, hp

def decryptPrivateKey(password, key, hashedPass):
    hp, hashedPassword = getHash(password)
    if hp != hashedPass:
        return None

    eiv = key[:CAST.block_size + 2]
    ciphertext = key[CAST.block_size + 2:]
    cipher = CAST.new(bytearray(hashedPassword.encode("utf-8")), CAST.MODE_OPENPGP, eiv)

    tmp = cipher.decrypt(ciphertext)

    # cipher = CAST.new(bytearray(hashedPassword.encode("utf-8")), CAST.MODE_OPENPGP)
    # tmp = cipher.decrypt(key)

    tmp = tmp.decode('utf-8')
    return rsa.PrivateKey.load_pkcs1(tmp)

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
    name = input("Unesite ime")
    email = input("Unesite email")
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
    # digest = hashes.Hash(hashes.SHA1())
    # ba = bytearray(str(msg).encode('utf-8'))
    # digest.update(ba)
    # hashMsg = digest.finalize()

    digest = SHA1.new()  # hashes.Hash(hashes.SHA1())
    ba = bytearray(str(msg).encode('utf-8'))
    digest.update(ba)
    hashMsg = (digest.digest())

    return rsa.encrypt(hashMsg, privateKey)

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
        cipher = DES3.new(kS, DES3.MODE_OPENPGP)

        eMsg = cipher.encrypt(ba)

    elif alg == "AES":
            kS = get_random_bytes(16)
            cipher = AES.new(kS, AES.MODE_OPENPGP)
            eMsg = cipher.encrypt(ba)

    return kS, eMsg


def decryptMsg(eMsg, alg, kS):
    global nonce
    msg = None
    if alg == "3DES":
        cipher = DES3.new(kS, DES3.MODE_OPENPGP)
        msg = cipher.decrypt(eMsg)
    elif alg == "AES":
        cipher = AES.new(kS, AES.MODE_OPENPGP)
        msg = cipher.decrypt(eMsg)

    return msg

def encryptKs(kS, publicKey):
    return rsa.encrypt(kS, publicKey)

def decryptKs(kS, privateKey):
    return rsa.decrypt(kS, privateKey)

def sendMessage(email, password, msg, name, publicKeyAuthID=None, publicKeyEncrID=None, encrAlg=None):
    global privateRing, publicRing
    toSend = {}
    toSend["data"] = msg
    toSend["ts"] = datetime.datetime.now()
    toSend["filename"] = name

    if publicKeyAuthID is not None:
        tmp = privateRing[email][publicKeyAuthID]
        privateKeyAuth = decryptPrivateKey(password, tmp.pr, tmp.password)
        if privateKeyAuth is None:
            return "error"
        authAlg = tmp.alg


        toSend["digest"] = msgAuth(toSend, privateKeyAuth)
        toSend["octets"] = None
        toSend["authKeyID"] = publicKeyAuthID
        toSend["tsAuth"] = datetime.datetime.now()
        toSend["algAuth"] = authAlg

    #zip

    if publicKeyEncrID is not None:
        encrMsg = {}
        kS, encrMsg["data"] = encryptMsg(toSend, encrAlg)
        encrMsg["encrKeyID"] = publicKeyEncrID
        publicKeyEncr = publicRing[publicKeyEncrID].pu
        encrMsg["ks"] = encryptKs(kS, publicKeyEncr)
        encrMsg["algEncr"] = encrAlg
        toSend = encrMsg


    #base64

    with open(f'msgs/{name}.json', "w") as sendmsg:
        sendmsg.write(str(toSend))

def receiveMessage(email, password, name):
    with open(f'msgs/{name}.json') as file:
        toRecv = ast.literal_eval(file.read())

    if "ks" in toRecv :
        kS = toRecv["ks"]
        decrKeyID = toRecv["encrKeyID"]
        data = toRecv["data"]
        alg = toRecv["algEncr"]

        tmp = privateRing[email][decrKeyID]
        privateKey = tmp.pr
        hashedPassword = tmp.password
        privateKey = decryptPrivateKey(password, privateKey, hashedPassword)
        if privateKey is None:
            return "error"

        kS = decryptKs(kS, privateKey)
        toRecv = decryptMsg(data, alg, kS)
        print(ast.literal_eval(toRecv.decode("utf-8")))






if __name__ == '__main__':
    print('ZP Projekat v1.1')
    generateKeys()  # dodati elgamal-dsa, publicRing
    generateKeys()
    # print(loadPrivateKeyFromPemFormat("test"))
    email = input("Uneti email: ")
    password = input("Uneti sifru: ")
    pr = list(privateRing[email].items())[0][0]
    pu = list(publicRing.items())[1][0]
    # print(pr, pu)
    sendMessage(email, password, "radi molim te", "test", pr, pu, "AES")
    email = input("Uneti email: ")
    password = input("Uneti sifru: ")
    receiveMessage(email, password, "test")
