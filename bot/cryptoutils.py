from subprocess import call, check_output, Popen, PIPE
from base64 import b64encode, b64decode
import re

supported_algorithms = ["rsa", "prime256v1", "secp384r1"]

# Maps every supported algorithm to their alg parameter in JWS and the hash method used
jws_algs = {
    "rsa": ("RS256", "sha256"),
    "prime256v1": ("ES256", "sha256"),
    "secp384r1": ("ES384", "sha384")
}

# Generates an RSA keypair using the selected key length
def generateRSAkeypair(key_length, location):
    command = "openssl genpkey -algorithm RSA -out \"%s\" -pkeyopt rsa_keygen_bits:%s" % (location, key_length)
    call(command.strip(" "), stdout=None, shell=True)

# Generates an elliptic curve keypair using the selected algorithm 
def generateECkeypair(algo, location):
    command = "openssl ecparam -name %s -genkey -noout -out \"%s\"" % (algo, location)
    call(command.strip(" "), stdout=None, shell=True)
    
# Generates a signature for a given text, key and hash algorithm
def generateSignature(text, keyPath, hashAlgo):
    echo = Popen(["printf", text], stdout=PIPE)
    command = "openssl dgst -%s -sign %s" % (hashAlgo, keyPath)
    digest = Popen(command.split(" "), shell=True, stdin=echo.stdout, stdout=PIPE)
    encoded = check_output("base64 -w 0".split(" "), shell=True, stdin=digest.stdout)
    return encoded.decode("utf-8")

# Converts text to base64
def toBase64(text):
    return b64encode(bytearray(text, "utf-8")).decode("utf-8")
    
# Converts base64 to URL-safe base64
def base64toURL(text):
    return text.replace("+", "-").replace("/", "_").replace("=", "")

# Converts text to URL-safe base64
def textToBase64URL(text):
    return base64toURL(toBase64(text))

def generateSignedJWS(header, body, key, hashAlgo):
    jws_header = textToBase64URL(str(header).replace("'", "\""))
    jws_body = textToBase64URL(str(body).replace("'", "\""))
    jws = jws_header + "." + jws_body
    signature = base64toURL(generateSignature(jws, key, hashAlgo))
    return str({"protected": jws_header, "payload": jws_body, "signature": signature}).replace("'", "\"")

# Generates JWK object for RSA keys
def generateJWK_RSA(key_path):
    jwk = {}
    jwk["kty"] = "RSA"
    jwk["alg"] = "RS256"
    
    # TODO Extract n and e from RSA key
    
    pubkey = getPublicKeyRSA(key_path)

    return jwk

# Generates JWK object for Elliptic Curve keys
def generateJWK_EC(key_path):
    pass
    
def getPublicKeyRSA(key_path):
    output = check_output(("openssl rsa -in %s -text -noout" % key_path).split(" "), shell=True).decode("utf-8")
    regexModulus = "modulus:\s*((?:[0-9a-f]{2}:?\s*)*)"
    modHex = re.search(regexModulus, output).group(1).replace("\n", "").replace(" ", "").replace(":", "")
    regexExp = "publicExponent.*?\(0x(\d*?)\)"
    
    #TODO encode hex values in base64url and return them