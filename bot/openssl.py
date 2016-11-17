from subprocess import call, check_output, Popen, PIPE

supported_algorithms = ["rsa", "prime256v1", "secp384r1"]

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
    echo = Popen(["printf", "\"" + text + "\""], stdout=PIPE)
    command = "openssl dgst -%s -sign %s" % (hashAlgo, keyPath)
    digest = Popen(command.split(" "), shell=True, stdin=echo.stdout, stdout=PIPE)
    encoded = check_output("base64 -w 0".split(" "), shell=True, stdin=digest.stdout)
    return str(encoded)

# Converts base64 to URL-safe base64
def base64toURL(base64):
    return base64.replace("+", "-").replace("/", "_").replace("=", "")