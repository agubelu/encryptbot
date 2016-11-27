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
    
    if not os.path.exists(getDomainsFolder() + "account.key"):
        createAccount()
        
    print("Checking domain %s" % domainName)
    
    #TODO check cert expiry
    
    domain_conf = getDomainConfig(domainName)
    domain_key_path = getDomainFolder(domainName) + domainName + ".key"
    key_algo = domain_conf["algorithm"]
    key_len = domain_conf["key_length"]
    
    if not os.path.exists(domain_key_path):
        print("Domain keypair not found, creating a new one")
        sys.stdout.flush()
        if key_algo == "rsa":
            cryptoutils.generateRSAkeypair(key_len, domain_key_path)
        else:
            cryptoutils.generateECkeypair(key_algo, domain_key_path)
        os.chmod(domain_key_path, 0o600)
        
    domain_alt_names = domain_conf["alternative_names"].split(" ")
    domain_web_roots = domain_conf["web_roots"].split(" ")
    
    if(len(domain_alt_names) != len(domain_web_roots) - 1):
        print("Error: there must be one web root for each alt. name and one for the primary name")
        print("Skipping domain...")
        return
    
    # Generate CSR
    csr = cryptoutils.generateCSR(domain_key_path, domainName, domain_alt_names)
    
     # Get directory from API server    
    if domain_conf["staging"] == "true":
        api_url = STAGING_SERVER_API
    else:
        api_url = FULL_SERVER_API
        
    directory = requests.get(api_url + "/directory").json()
    url_request_cert = directory["new-cert"]
    nonce = getNewNonce(api_url)
    
    with open(getDomainsFolder() + ".key_id") as f:
        keyID = f.read()
        
    account_key = getDomainsFolder() + "account.key"
    algs_jws = cryptoutils.jws_algs[getGlobalConfig()["algorithm"]]
    jwkAccountKey = getJWKkey(account_key, key_algo)
    reg_query = cryptoutils.generateSignedJWS({"alg":algs_jws[0], "jwk":jwkAccountKey, "nonce":nonce, "url":url_request_cert}, 
                                              {"csr":csr, "resource": "new-cert"}, 
                                              account_key, algs_jws[1])
    print(reg_query)
    print(url_request_cert)
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
| 10 seconds and your account will be automatically created.          |
|                                                                     |
| This message will not be displayed again unless you delete your     |
| account key.                                                        |
+---------------------------------------------------------------------+""" % doc)
    sys.stdout.flush()
    #TODO sleep(10)
    
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
                                              {"terms-of-service-agreed": True, "contact":["mailto:" + global_conf["email"]], "resource": "new-reg", "agreement":doc}, 
                                              keyPath, algs_jws[1])
    
    creation_request = requests.post(url_register, data=reg_query)
    checkRequestStatus(creation_request, 201)
    creation_response = creation_request.json()
    key_id = creation_response["id"]
    
    with open(folderpath + ".key_id", "w") as f:
        f.write(str(key_id))
        
    print("Account created successfully")
        
def getJWKkey(key_path, algorithm):
    if algorithm == "rsa":
        return cryptoutils.generateJWK_RSA(key_path)
    else:
        return cryptoutils.generateJWK_EC(key_path)
    