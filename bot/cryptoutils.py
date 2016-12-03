from subprocess     import call, check_output, Popen, PIPE
from base64         import b64encode
from hashlib        import sha256

import re, codecs, os

# Maps every supported algorithm to their alg parameter in JWS and the hash method used
jws_algs = {
    "rsa": ("RS256", "sha256"),
    "prime256v1": ("ES256", "sha256"),
    "secp384r1": ("ES384", "sha384")
}

supported_algorithms = jws_algs.keys()

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
    with open(keyPath, "r") as key:
        ec = "EC" in key.readline()
        
    if not ec: # RSA
        digest = Popen(command.split(" "), stdin=echo.stdout, stdout=PIPE)
        encoded = check_output("base64 -w 0".split(" "), stdin=digest.stdout)
        return encoded.decode("utf-8")
    else: # Elliptic Curve
        command += " -hex"
        output = check_output(command.split(" "), stdin=echo.stdout).decode("utf-8")
        hexDigest = re.search("\(stdin\)=\s*([a-f0-9]*)", output).group(1)
        len_r = int(hexDigest[6:8], 16) * 2
        r = hexDigest[8:8+len_r]
        s = hexDigest[12+len_r:]
        if r[0:2] == "00": r = r[2:]
        if s[0:2] == "00": s = s[2:]
        return hexToBase64URL(r + s)

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
    jws_header = textToBase64URL(str(header).replace("'", "\"").replace("True", "true"))
    jws_body = textToBase64URL(str(body).replace("'", "\"").replace("True", "true"))
    jws = jws_header + "." + jws_body
    signature = base64toURL(generateSignature(jws, key, hashAlgo))
    return str({"protected": jws_header, "payload": jws_body, "signature": signature}).replace("'", "\"")

# Generates JWK object for RSA keys
def generateJWK_RSA(key_path):
    jwk = {}
    pubkey = getPublicKeyRSA(key_path)
    
    jwk["kty"] = "RSA"
    jwk["alg"] = "RS256"
    jwk["n"] = pubkey["modulus"]
    jwk["e"] = pubkey["exponent"]

    return jwk

# Generates JWK object for Elliptic Curve keys
def generateJWK_EC(key_path):
    jwk = {}
    pubkey = getPublicKeyEC(key_path)
    
    jwk["kty"] = "EC"
    jwk["crv"] = pubkey["curve"]
    jwk["x"] = pubkey["x"]
    jwk["y"] = pubkey["y"]
    
    return jwk
    
def getPublicKeyRSA(key_path):
    output = check_output(("openssl rsa -in %s -text -noout" % key_path).split(" ")).decode("utf-8")
    regexModulus = "modulus:\s*((?:[0-9a-f]{2}:?\s*)*)"
    modHex = re.search(regexModulus, output).group(1).replace("\n", "").replace(" ", "").replace(":", "")
    if modHex[0:2] == "00": modHex = modHex[2:]
    regexExp = "publicExponent.*?\(0x(\d*?)\)"
    expHex = re.search(regexExp, output).group(1)
    
    if len(expHex) % 2 == 1:
        expHex = "0" + expHex
    
    modulus = hexToBase64URL(modHex)
    exponent = hexToBase64URL(expHex)

    return {"modulus": modulus, "exponent": exponent}

def getPublicKeyEC(key_path):
    output = check_output(("openssl ec -in %s -text -noout" % key_path).split(" "), stderr=PIPE).decode("utf-8")
    regexCoords = "pub:\s*((?:[0-9a-f]{2}:?\s*)*)"
    coordsHex = re.search(regexCoords, output).group(1).replace("\r", "").replace("\n", "").replace(" ", "").replace(":", "")[2:] # Exclude the first byte, which does not contain useful information
    regexCurve = "ASN1 OID:\s*(.*)"
    curve = re.search(regexCurve, output).group(1).rstrip()
    
    nistCurve = {"secp384r1": "P-384", "prime256v1": "P-256"}[curve]
    
    x = coordsHex[0:len(coordsHex)//2]
    y = coordsHex[len(coordsHex)//2:]
    
    return {"x": hexToBase64URL(x), "y": hexToBase64URL(y), "curve": nistCurve}

def hexToBase64URL(hexDump):
    return base64toURL(b64encode(codecs.decode(hexDump, "hex")).decode("utf-8"))

def generateCSR(key, domain_names):
    path_temp_file = os.path.dirname(key) + "/.tmp_conf"
    primary_name = domain_names[0]
    appendLine = "subjectAltName = DNS:" + primary_name + "".join([",DNS:%s" % dom for dom in domain_names])
    with open(path_temp_file, "w") as f:
        f.write("""[ req ]
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
[ SAN ]\n""" + appendLine)
        
    gen_command = "openssl req -new -sha256 -key %s -subj / -reqexts SAN -config %s" % (os.path.normpath(key), os.path.normpath(path_temp_file))
    output = check_output(gen_command.split(" "))
    os.remove(path_temp_file)

    lines = output.decode("utf-8").split("\n")
    csr = "".join([line.strip() for line in lines if line != "" and line[0:5] != "-----"])
    return base64toURL(csr)

def getCertChainLocation(cert_path):
    command = "openssl x509 -in %s -text -noout" % cert_path
    output = check_output(command.split(" ")).decode("utf-8")
    return re.search("CA Issuers - URI:(.*?)\s", output).group(1)
    
def generateKeyThumbprint(jwk):
    if jwk["kty"] == "RSA":
        text = '{"e":"%s","kty":"RSA","n":"%s"}' % (jwk["e"], jwk["n"])
    else:
        text = '{"crv":"%s","kty":"EC","x":"%s","y":"%s"}' % (jwk["crv"], jwk["x"], jwk["y"])
    
    return hexToBase64URL(sha256(text.encode('utf-8')).hexdigest())
