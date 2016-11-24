from common_utils import getDomainFolder, getDomainsFolder, getNewNonce, checkRequestStatus
from configmanager import getDomainConfig, getGlobalConfig
from time import sleep
import sys, os, re, json
from urllib.request import urlopen
import cryptoutils
import requests

STAGING_SERVER_API = "https://acme-staging.api.letsencrypt.org"
FULL_SERVER_API = "https://acme-v01.api.letsencrypt.org"

def retrieveCertificate(domainName, flags):
    
    #if not os.path.exists(getDomainsFolder() + "account.key"):
    createAccount()
    
    #TODO check cert expiry

def createAccount():
    # Automatically grab the latest TOS
    le_docs = str(urlopen("https://letsencrypt.org/repository/").read())
    doc = "https://letsencrypt.org" + re.findall("href=\"(\/documents\/LE-SA.*?)\"", le_docs)[0]
    print("""
+---------------------------------------------------------------------+
|                         IMPORTANT NOTICE                            |
|                                                                     |
| You are about to create a Let's Encrypt account, which means that   |
| you agree with the Let's Encrypt Terms of Service which can be      |
| found at the following URL:                                         |
|                                                                     |
| %s    |
|                                                                     |
| If you do not agree, press CTRL + C now to cancel. Otherwise wait   |
| 15 seconds and your account will be automatically created.          |
|                                                                     |
| This message will not be displayed again unless you delete your     |
| account key.                                                        |
+---------------------------------------------------------------------+""" % doc)
    sys.stdout.flush()
    #sleep(15) TODO quitar
    
    global_conf = getGlobalConfig()
    key_algo = global_conf["algorithm"]
    key_len = global_conf["key_length"]
    
    # Generate account keypair using the desired algorithm
    if key_algo not in cryptoutils.supported_algorithms:
        raise Exception("Algorithm %s not supported" % key_algo)
    
    print("\n\nGenerating account keypair...")
    sys.stdout.flush()
    
    folderpath = getDomainsFolder()
    keyPath = folderpath + "account.key"
    
    if key_algo == "rsa":
        cryptoutils.generateRSAkeypair(key_len, keyPath)
    else:
        cryptoutils.generateECkeypair(key_algo, keyPath)
        
    os.chmod(keyPath, 0o600)

    # Get directory from API server    
    if global_conf["staging"] == "true":
        api_url = STAGING_SERVER_API
    else:
        api_url = FULL_SERVER_API

    directory = requests.get(api_url + "/directory").json()
    
    # Register user account
    url_register = directory["new-reg"]
    algs_jws = cryptoutils.jws_algs[key_algo]
        
    jwkKey = getJWKkey(keyPath, key_algo)
    nonce = getNewNonce(api_url)   
    reg_query = cryptoutils.generateSignedJWS({"alg":algs_jws[0], "jwk":jwkKey, "nonce":nonce, "url":url_register}, 
                                              {"terms-of-service-agreed": "true", "contact":["mailto:" + global_conf["email"]], "resource": "new-reg"}, 
                                              keyPath, algs_jws[1])
    
    creation_request = requests.post(url_register, data=reg_query)
    checkRequestStatus(creation_request, 201)
    creation_response = creation_request.json()
    key_id = creation_response["id"]
    
    with open(folderpath + ".key_id", "w") as f:
        f.write(str(key_id))
        
def getJWKkey(key_path, algorithm):
    if algorithm == "rsa":
        return cryptoutils.generateJWK_RSA(key_path)
    else:
        return cryptoutils.generateJWK_EC(key_path)
    