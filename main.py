import ast
import base64
import zlib

from keyManipulation import *
from msgAuth import *
from msgEncr import *

publicRing = {}
privateRing = {}


def deleteKeys(keyID, email):
    del privateRing[email][keyID]
    del publicRing[keyID]
    return


def saveKeyInPemFormat(key, title, algo):
    if algo == "RSA":
        with open(f'keys/{title}.pem', 'wb') as p:
            p.write("RSA\n".encode('utf-8'))
            p.write(key.export_key('PEM'))
            p.close()
    elif algo == "DSA":
        with open(f'keys/{title}.pem', 'wb') as p:
            p.write("DSA\n".encode('utf-8'))
            p.write(key.export_key('PEM'))
            p.close()
    elif algo == "ElGamal":
        with open(f'keys/{title}.pem', 'wb') as p:
            toWrite = {}
            toWrite["p"] = int(key.p)
            toWrite["g"] = int(key.g)
            toWrite["y"] = int(key.y)
            if hasattr(key, 'x'):
                toWrite["x"] = int(key.x)
            p.write("-----BEGIN ELGAMAL PUBLIC KEY-----\n".encode('utf-8'))
            p.write(bytearray(str(toWrite).encode('utf-8')))
            p.write("\n-----END ELGAMAL PUBLIC KEY-----".encode('utf-8'))
            p.close()


def loadKeyFromPemFormat(title, email, password):  # izmeniti za elgamal i dsa
    with open(f'keys/{title}.pem', 'rb') as p:
        publicKey = None
        firstLine = p.readline().decode('utf-8')
        if firstLine.find("RSA") != -1:
            keys = RSA.import_key(p.read())
            if publicKey.has_private():
                publicKey = keys.public_key()
                privateKey = keys
                puID = publicKey.n
                addToRings(email, password, privateKey, publicKey, puID, "RSA")
            else:
                publicRing[keys.n % (2 ** 64)] = PublicRingStruct(keys, "RSA", email)
        elif firstLine.find("ELGAMAL") != -1:
            keys = eval((p.readline()).decode('utf-8'))
            if "x" in publicKey.keys:
                privateKey = ElGamal.construct((int(keys["p"]), int(keys["g"]), int(keys["y"], int(keys["x"]))))
                publicKey = privateKey.publickey()
                puID = publicKey.y
                addToRings(email, password, privateKey, publicKey, puID, "ElGamal")
            else:
                publicKey = ElGamal.construct((int(keys["p"]), int(keys["g"]), int(keys["y"])))
                publicRing[int(keys.y) % (2 ** 64)] = PublicRingStruct(keys, "ElGamal", email)
        elif firstLine.find("DSA") != -1:
            keys = DSA.import_key(p.read())
            if keys.has_private():
                publicKey = keys.public_key()
                privateKey = keys
                puID = publicKey.y
                addToRings(email, password, privateKey, publicKey, puID, "DSA")
            else:
                publicRing[keys.y % (2 ** 64)] = PublicRingStruct(keys, "DSA", email)
        p.close()
        return keys


def addToRings(email, password, privateKey, publicKey, pubID, algo):
    msg, hp = encryptPrivateKey(password, privateKey, algo)
    if not privateRing.get(email):
        privateRing[email] = {}

    (privateRing[email])[int(pubID) % (2 ** 64)] = PrivateRingStruct(publicKey, msg, algo, hp)

    publicRing[int(pubID) % (2 ** 64)] = PublicRingStruct(publicKey, algo, email)


def generateKeys(name,email,algo,size,password):

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


def sendMessage(email, password, msg, name, publicKeyAuthID=None, publicKeyEncrID=None, encrAlg=None,zip=False,base64encode=False):
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
        toSend = zlib.compress(str(toSend).encode('utf-8'))

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
        toSend = base64.b64encode(str(toSend).encode('ascii')).decode('ascii')

    with open(name, "w") as sendmsg:
        sendmsg.write(str(toSend))


def receiveMessage(email, password, name):
    with open(name) as file:
        toRecv = file.read()

    toRecv = base64.b64decode(toRecv.encode('ascii')).decode("ascii")
    toRecv = ast.literal_eval(toRecv)

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

    toRecv = eval(zlib.decompress(toRecv).decode('utf-8'))

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
    generateKeys("iva", "iva", "DSA", 1024, "123")
    loadKeyFromPemFormat("test", "iva", "123")
    print(publicRing)
    print(privateRing)
