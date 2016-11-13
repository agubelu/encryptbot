import subprocess
from common_utils import getDomainsFolder

supported_algorithms = ["rsa", "prime256v1", "secp384r1"]

def generateRSAkeypair(key_length):
    command = "openssl genpkey -algorithm RSA -out \"%saccount.key\" -pkeyopt rsa_keygen_bits:%s" % (getDomainsFolder(), key_length)
    subprocess.call(command.strip(" "), stdout=None, shell=True)
    
def generateECkeypair(algo):
    command = "openssl ecparam -name %s -genkey -noout -out \"%saccount.key\"" % (algo, getDomainsFolder())
    subprocess.call(command.strip(" "), stdout=None, shell=True)