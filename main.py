import ast
import base64
import binascii
import zlib

from keyManipulation import *
from msgAuth import *
from msgEncr import *


class User:
    def __init__(self, username, name):
        self.username = username
        self.name = name

    def __str__(self):
        return "username: " + str(self.username) + ", name: " + str(self.name)


publicRing = {}
privateRing = {}
users = {}


def deleteKeys(keyID, email):
    del privateRing[email][keyID]
    del publicRing[keyID]
    return


def saveKeyInPemFormat(key, title, algo):
    if algo == "RSA":
        with open(title, 'wb') as p:
            p.write("RSA\n".encode('utf-8'))
            p.write(key.export_key('PEM'))
            p.close()
    elif algo == "DSA":
        with open(title, 'wb') as p:
            p.write("DSA\n".encode('utf-8'))
            p.write(key.export_key('PEM'))
            p.close()
    elif algo == "ElGamal":
        with open(title, 'wb') as p:
            toWrite = {}
            toWrite["p"] = int(key.p)
            toWrite["g"] = int(key.g)
            toWrite["y"] = int(key.y)
            if hasattr(key, 'x'):
                toWrite["x"] = int(key.x)
            p.write("-----BEGIN ELGAMAL PUBLIC KEY-----\n".encode('utf-8'))
            toWrite = base64.b64encode(str(toWrite).encode('ascii'))
            p.write(toWrite)
            p.write("\n-----END ELGAMAL PUBLIC KEY-----".encode('utf-8'))
            p.close()


def loadKeyFromPemFormat(title, email, password=None):  # izmeniti za elgamal i dsa
    with open(title, 'rb') as p:
        algKeys = None
        firstLine = p.readline().decode('utf-8')
        if firstLine.find("RSA") != -1:
            algKeys = RSA.import_key(p.read())
            if algKeys.has_private():
                publicKey = algKeys.public_key()
                privateKey = algKeys
                puID = publicKey.n
                addToRings(email, password, privateKey, publicKey, puID, "RSA")
            else:
                publicRing[algKeys.n % (2 ** 64)] = PublicRingStruct(algKeys, "RSA", email)
        elif firstLine.find("ELGAMAL") != -1:
            algKeys = eval(base64.b64decode(p.readline()).decode("ascii"))
            print(algKeys)
            # keys = eval((p.readline()).decode('utf-8'))
            if "x" in algKeys:
                privateKey = ElGamal.construct(
                    (int(algKeys["p"]), int(algKeys["g"]), int(algKeys["y"]), int(algKeys["x"])))
                publicKey = privateKey.publickey()
                puID = publicKey.y
                addToRings(email, password, privateKey, publicKey, puID, "ElGamal")
            else:
                keys = ElGamal.construct((int(algKeys["p"]), int(algKeys["g"]), int(algKeys["y"])))
                publicRing[int(algKeys.y) % (2 ** 64)] = PublicRingStruct(keys, "ElGamal", email)
        elif firstLine.find("DSA") != -1:
            algKeys = DSA.import_key(p.read())
            if algKeys.has_private():
                publicKey = algKeys.public_key()
                privateKey = algKeys
                puID = publicKey.y
                addToRings(email, password, privateKey, publicKey, puID, "DSA")
            else:
                publicRing[algKeys.y % (2 ** 64)] = PublicRingStruct(algKeys, "DSA", email)
        p.close()
        return algKeys


def addToRings(email, password, privateKey, publicKey, pubID, algo):
    msg, hp = encryptPrivateKey(password, privateKey, algo)
    if not privateRing.get(email):
        privateRing[email] = {}

    (privateRing[email])[int(pubID) % (2 ** 64)] = PrivateRingStruct(publicKey, msg, algo, hp)

    publicRing[int(pubID) % (2 ** 64)] = PublicRingStruct(publicKey, algo, email)


def generateKeys(name, email, algo, size, password):
    keys = None

    if algo == "RSA":
        keys = generateKeysRSA(size)
        publicKey = keys.public_key()
        privateKey = keys
        pubID = publicKey.n


    elif algo == "DSA":
        keys = generateKeysDSA(size)
        publicKey = keys.public_key()
        privateKey = keys
        pubID = publicKey.y


    elif algo == "ElGamal":
        keys = generateKeysElGamal(size)
        keys = ElGamal.construct((int(keys.p), int(keys.g), int(keys.y), int(keys.x)))
        publicKey = keys.publickey()
        privateKey = keys
        pubID = publicKey.y

    addToRings(email, password, privateKey, publicKey, pubID, algo)
    saveKeyInPemFormat(privateKey, "test", algo)


def sendMessage(email, password, msg, name, publicKeyAuthID=None, publicKeyEncrID=None, encrAlg=None, zip=False,
                base64encode=False):
    global privateRing, publicRing
    toSend = {}
    toSend["data"] = msg
    toSend["ts"] = datetime.datetime.now()
    toSend["filename"] = name

    if publicKeyAuthID is not None:
        tmp = privateRing[email][publicKeyAuthID]
        privateKeyAuth = decryptPrivateKey(password, tmp.pr, tmp.password, tmp.alg)
        if privateKeyAuth is None:
            return "error"
        authAlg = tmp.alg

        authMsg = {}
        authMsg["data"] = toSend
        authMsg["digest"] = msgAuth(toSend, privateKeyAuth, authAlg)
        authMsg["octets"] = None
        authMsg["authKeyID"] = publicKeyAuthID
        authMsg["tsAuth"] = datetime.datetime.now()
        authMsg["algAuth"] = authAlg
        toSend = authMsg

    if zip:
        zipMsg = {}
        zipMsg["zip"] = zlib.compress(str(toSend).encode('utf-8'))
        toSend = zipMsg

    if publicKeyEncrID is not None:
        encrMsg = {}
        print(bytearray(str(toSend).encode("utf-8")))
        kS, encrMsg["data"], encrMsg["iv"] = encryptMsg(toSend, encrAlg)
        # print(kS)
        encrMsg["encrKeyID"] = publicKeyEncrID
        publicKeyEncr = publicRing[publicKeyEncrID].pu
        encrMsg["ks"] = encryptKs(kS, publicKeyEncr, publicRing[publicKeyEncrID].alg)
        encrMsg["algEncr"] = encrAlg
        toSend = encrMsg

    if base64encode:
        b64Msg = {}
        b64Msg['b64'] = base64.b64encode(str(toSend).encode('ascii')).decode('ascii')
        toSend = base64

    with open(name, "w") as sendmsg:
        sendmsg.write(str(toSend))


def receiveMessage(email, password, name):
    with open(name) as file:
        toRecv = file.read()

    toRecv = ast.literal_eval(toRecv)
    if 'b64' in toRecv:
        toRecv = base64.b64decode(toRecv.encode('ascii')).decode("ascii")

    if "ks" in toRecv:
        kS = toRecv["ks"]
        decrKeyID = toRecv["encrKeyID"]
        data = toRecv["data"]
        alg = toRecv["algEncr"]

        tmp = privateRing[email][decrKeyID]
        privateKey = tmp.pr
        hashedPassword = tmp.password
        privateKey = decryptPrivateKey(password, privateKey, hashedPassword, tmp.alg)
        if privateKey is None:
            return "error"

        kS = decryptKs(kS, privateKey, tmp.alg)
        toRecv = decryptMsg(data, alg, kS, toRecv["iv"])

        toRecv = eval(toRecv.decode("utf-8"))

    if "zip" in toRecv.keys:
        toRecv = eval(zlib.decompress(toRecv['zip']).decode('utf-8'))

    if "digest" in toRecv:
        digest = toRecv["digest"]
        octets = toRecv["octets"]
        authKeyID = toRecv["authKeyID"]
        ts = toRecv["tsAuth"]
        algAuth = toRecv["algAuth"]
        toRecv = toRecv["data"]

        publicKey = publicRing[authKeyID].pu
        print(publicKey)

        if not checkAuth(toRecv, digest, publicKey, algAuth):
            return "error"

    print(toRecv)


if __name__ == '__main__':
    print('ZP Projekat v1.1')
    generateKeys("iva", "iva", "ElGamal", 1024, "123")
    loadKeyFromPemFormat("test", "iva", "123")
    print(publicRing)
    print(privateRing)
