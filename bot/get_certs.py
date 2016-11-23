from common_utils import getDomainFolder, getDomainsFolder
from configmanager import getDomainConfig, getGlobalConfig
from time import sleep
import sys, os, re, json
from urllib.request import urlopen
import cryptoutils

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
    
    """if key_algo == "rsa":
        cryptoutils.generateRSAkeypair(key_len, keyPath)
    else:
        cryptoutils.generateECkeypair(key_algo, keyPath)
    TODO quitar"""
    # Get directory from API server    
    if global_conf["staging"] == "true":
        api_url = STAGING_SERVER_API
    else:
        api_url = FULL_SERVER_API

    directory = json.loads(urlopen(api_url + "/directory").read().decode("utf-8")) 
    
    # Register user account
    url_register = directory["new-reg"]
    algs_jws = cryptoutils.jws_algs[key_algo]
    
    if key_algo == "rsa":
        jwkKey = cryptoutils.generateJWK_RSA(keyPath)
    else:
        jwkKey = cryptoutils.generateJWK_EC(keyPath)
    
    #TODO get a valid nonce
    nonce = "abcde"
    
    reg_query = cryptoutils.generateSignedJWS({"alg":algs_jws[0], "jwk":jwkKey, "nonce":nonce, "url":url_register}, 
                                              {"terms-of-service-agreed": "true", "contact":["mailto:" + global_conf["email"]], "resource": "new-reg"}, 
                                              keyPath, algs_jws[1])
    
    #print(reg_query)
    
    