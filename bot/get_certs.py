from common_utils       import getDomainFolder, getDomainsFolder, getNewNonce, checkRequestStatus
from configmanager      import getDomainConfig, getGlobalConfig
from time               import sleep
from base64             import b64encode
from urllib.request     import urlopen
from shutil             import copyfile
from datetime           import datetime

import sys, os, re, subprocess
import cryptoutils
import requests

STAGING_SERVER_API = "https://acme-staging.api.letsencrypt.org"
FULL_SERVER_API = "https://acme-v01.api.letsencrypt.org"

DOMAIN_CHALLENGE_RETRY_INTERVAL = 3 # Seconds
DOMAIN_CHALLENGE_MAX_RETRIES = 10

def retrieveCertificate(domainName, flags):
    
    domains_folder = getDomainsFolder()
    domain_conf = getDomainConfig(domainName)
    
    # Create account if it doesn't exist yet
    if not os.path.exists(domains_folder + "account.key"):
        createAccount()
    
    # Check cert expiry
    certPath = getDomainFolder(domainName) + domainName + ".crt"
    if "-f" not in flags and os.path.exists(certPath):
        cert_expiry_time = cryptoutils.getCertExpiry(certPath)
        now = datetime.utcnow()
        minTime = int(domain_conf["renewal_time"])
        diff = (cert_expiry_time - now).days
        
        if diff > minTime:
            print("Certificate for %s is still valid for %d more days" % (domainName, diff))
            return
    
    print("Obtaining certificate for domain %s\n" % domainName)
    sys.stdout.flush()
    
    domain_key_path = getDomainFolder(domainName) + domainName + ".key"
    key_algo = domain_conf["algorithm"]
    key_len = domain_conf["key_length"]
    
    # Generate domain keypair if it doesn't exist
    if not os.path.exists(domain_key_path):
        print("Domain keypair not found, creating a new one\n")
        sys.stdout.flush()
        if key_algo == "rsa":
            cryptoutils.generateRSAkeypair(key_len, domain_key_path)
        else:
            cryptoutils.generateECkeypair(key_algo, domain_key_path)
        os.chmod(domain_key_path, 0o600)
        
    # Get primary and alternative names for domain, and check that there is a web root for each name
    domain_names = [domainName] + domain_conf["alternative_names"].split(" ")
    domain_web_roots = domain_conf["web_roots"].split(" ")
    
    if(len(domain_names) != len(domain_web_roots)):
        print("Error: there must be one web root for the primary name and one for each alt. name")
        print("Skipping domain...")
        return
    
    # Get directory from API server    
    if domain_conf["staging"] == "true":
        api_url = STAGING_SERVER_API
    else:
        api_url = FULL_SERVER_API
        
    directory = requests.get(api_url + "/directory").json()
    url_request_auth = directory["new-authz"]
    nonce = getNewNonce(api_url)
    
    # Complete HTTP challenge for each domain name
    account_key = domains_folder + "account.key"
    global_conf = getGlobalConfig()
    global_key_algo = global_conf["algorithm"]
    algs_jws = cryptoutils.jws_algs[global_key_algo]
    jwkAccountKey = getJWKkey(account_key, global_key_algo)
    keyThumbprint = cryptoutils.generateKeyThumbprint(jwkAccountKey)
    
    for i in range(len(domain_names)):
        name = domain_names[i]
        root_path = domain_web_roots[i]
        print("Validating domain %s" % name)
        sys.stdout.flush()
    
        auth_query = cryptoutils.generateSignedJWS({"alg":algs_jws[0], "jwk":jwkAccountKey, "nonce":nonce, "url":url_request_auth}, 
                                              {"identifier":{"type":"dns", "value":name}, "resource": "new-authz"}, 
                                              account_key, algs_jws[1])
        
        auth_request = requests.post(url_request_auth, data=auth_query)
        nonce = auth_request.headers["Replay-Nonce"]
        
        if auth_request.status_code == 403:
            # Account.key exists but LE is requesting us to register the account
            # Maybe we're changing from Staging to Full or viceversa
            createAccount(True, api_url)
            # Try again
            auth_request = requests.post(url_request_auth, data=auth_query)
            nonce = auth_request.headers["Replay-Nonce"]
            
        checkRequestStatus(auth_request, 201)
        
        try:
            challenge = [ch for ch in auth_request.json()["challenges"] if ch["type"] == "http-01"][0]
        except:
            # This shouldn't happen...
            print("It looks like Let's Encrypt is not accepting HTTP challenges...")
            return
        
        if challenge["status"] == "valid":
            print("Domain %s is already validated\n" % name)
            continue
        
        challenge_url = challenge["uri"]
        challenge_token = challenge["token"]
        
        key_authorization = challenge_token + "." + keyThumbprint
        
        if root_path[-1] != "\\" and root_path[-1] != "/":
            root_path += "/"
            
        # Generate the well known path if it doesn't exist yet
        if not os.path.exists(root_path + ".well-known"):
            os.mkdir(root_path + ".well-known")
        if not os.path.exists(root_path + ".well-known/acme-challenge"):
            os.mkdir(root_path + ".well-known/acme-challenge")
            
        token_path = root_path + ".well-known/acme-challenge/" + challenge_token
            
        # Place the token and validate it
        with open(token_path, "w") as f:
            f.write(key_authorization)
            
        challenge_query = cryptoutils.generateSignedJWS({"alg":algs_jws[0], "jwk":jwkAccountKey, "nonce":nonce, "url":challenge_url}, 
                                              {"keyAuthorization":key_authorization, "resource":"challenge"}, 
                                              account_key, algs_jws[1])
        
        challenge_request = requests.post(challenge_url, data=challenge_query)
        nonce = challenge_request.headers["Replay-Nonce"]
        
        def challengeOK():
            print("Domain %s successfully validated\n" % name)
            os.remove(token_path)
            
        def challengeFailed(req):
            print("Could not validate domain %s\n" % name)
            print(req.content.decode("utf-8"))
            os.remove(token_path)
            
        if challenge_request.status_code == 202:
            # Authorization is still in progress, keep polling
            for i in range(DOMAIN_CHALLENGE_MAX_RETRIES):         
                sleep(DOMAIN_CHALLENGE_RETRY_INTERVAL)
                polling_request = requests.get(challenge_url)
               
                if polling_request.status_code == 202:
                    if polling_request.json()["status"] == "valid":
                        # Challenge has been successfully completed
                        challengeOK()
                        break
                    elif i == DOMAIN_CHALLENGE_MAX_RETRIES - 1:
                        # If we've reached here, max polling attempts have been reached
                        print("Maximum polling attempts for challenge status reached")
                        print("Please check that the token can be reached at the following URL:")
                        print("http://%s/.well-known/acme-challenge/%s" % (name, challenge_token))
                        return
                    else:
                        # Challenge validation still in progress
                        continue
                else:
                    # Error code, challenge failed
                    challengeFailed(polling_request)
                    return
                    
            
        elif challenge_request.status_code == 200:
            # Authorization validated immediately
            challengeOK()
        else:
            # Authorization failed immediately
            challengeFailed(challenge_request)
            return
        
    # Domain(s) validation finished successfully
    # Generate CSR and request certificate
    print("\nRequesting certificate")
    sys.stdout.flush()
    csr = cryptoutils.generateCSR(domain_key_path, domain_names)
    request_cert_url = directory["new-cert"]
    cert_query = cryptoutils.generateSignedJWS({"alg":algs_jws[0], "jwk":jwkAccountKey, "nonce":nonce, "url":request_cert_url}, 
                                              {"csr":csr, "resource":"new-cert"}, 
                                              account_key, algs_jws[1])
    
    cert_request = requests.post(request_cert_url, data=cert_query)
    checkRequestStatus(cert_request, 201)
    
    domain_cert_base64 = b64encode(cert_request.content).decode("utf-8")
    print("Writing " + domainName + ".crt")
    sys.stdout.flush()
    
    # Save certificate to domain folder
    with open(certPath, "w") as cert:
        cert.writelines(b64toCert(domain_cert_base64))
        
    # Get the chain
    chain_location = cryptoutils.getCertChainLocation(certPath)
    chain_request = requests.get(chain_location)
    chain_cert_base64 = b64encode(chain_request.content).decode("utf-8")
    chain = b64toCert(chain_cert_base64)
    
    if domain_conf["chained_certs"] == "true":
        # Concatenate chain to the cert
        with open(certPath, "a") as cert:
            cert.writelines(chain)
    else:
        # Write chain to another file
        print("Writing chain.crt")
        sys.stdout.flush()
        with open(getDomainFolder(domainName) + "chain.crt", "w") as ch:
            ch.writelines(chain)
            
            
    # Copy cert and key to the desired location
    folder_copy_cert = domain_conf["folder_copy_cert"]
    if len(folder_copy_cert) > 0:
        print("\nCopying cert to %s" % folder_copy_cert)
        sys.stdout.flush()
        copyfile(certPath, folder_copy_cert + "/%s.crt" % domainName)
        
    folder_copy_key = domain_conf["folder_copy_key"]
    if len(folder_copy_key) > 0:
        print("Copying key to %s" % folder_copy_key)
        sys.stdout.flush()
        copyfile(domain_key_path, folder_copy_key + "/%s.key" % domainName)
        
    # Execute the user command
    command = domain_conf["after_command"]
    if len(command) > 0:
        subprocess.call(command.split(" "), shell=True)
    
    
def createAccount(auto=False, alt_api_url=None):

    global_conf = getGlobalConfig()
    key_algo = global_conf["algorithm"]
    key_len = global_conf["key_length"]
    folderpath = getDomainsFolder()
    keyPath = folderpath + "account.key"
    
    le_docs = str(urlopen("https://letsencrypt.org/repository/").read())
    doc = "https://letsencrypt.org" + re.findall("href=\"(\/documents\/LE-SA.*?)\"", le_docs)[0]
    
    if not auto:
        # Automatically grab the latest TOS
        docWithSpaces = doc + (" " * max(0, 68 - len(doc)))
        print("""
    +---------------------------------------------------------------------+
    |                         IMPORTANT NOTICE                            |
    |                                                                     |
    | You are about to create a Let's Encrypt account, which means that   |
    | you agree with the Let's Encrypt Terms of Service:                  |
    |                                                                     |
    | %s|
    |                                                                     |
    | If you do not agree, press CTRL + C now to cancel. Otherwise wait   |
    | 10 seconds and your account will be automatically created.          |
    |                                                                     |
    | This message will not be displayed again unless you delete your     |
    | account key.                                                        |
    +---------------------------------------------------------------------+""" % docWithSpaces)
        sys.stdout.flush()
        sleep(10)
        
        # Generate account keypair using the desired algorithm
        if key_algo not in cryptoutils.supported_algorithms:
            raise Exception("Algorithm %s not supported" % key_algo)
        
        print("\n\nGenerating account keypair...")
        sys.stdout.flush()
        
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
            
    if alt_api_url != None:
        api_url = alt_api_url

    directory = requests.get(api_url + "/directory").json()
    
    # Register user account
    print("Registering account")
    sys.stdout.flush()
    url_register = directory["new-reg"]
    algs_jws = cryptoutils.jws_algs[key_algo]
        
    jwkKey = getJWKkey(keyPath, key_algo)
    nonce = getNewNonce(api_url)   
    reg_query = cryptoutils.generateSignedJWS({"alg":algs_jws[0], "jwk":jwkKey, "nonce":nonce, "url":url_register}, 
                                              {"terms-of-service-agreed": True, "contact":["mailto:" + global_conf["email"]], "resource": "new-reg", "agreement":doc}, 
                                              keyPath, algs_jws[1])
    
    creation_request = requests.post(url_register, data=reg_query)
    checkRequestStatus(creation_request, 201)
    
    # Apparently LE doesn't support authorization by key id...
    # I'll just leave this here in case they do in the future
    """
    creation_response = creation_request.json()
    key_id = creation_response["id"]
    with open(folderpath + ".key_id", "w") as f:
        f.write(str(key_id))
    """
        
    print("Account created successfully\n")
        
def getJWKkey(key_path, algorithm):
    if algorithm == "rsa":
        return cryptoutils.generateJWK_RSA(key_path)
    else:
        return cryptoutils.generateJWK_EC(key_path)
    
def b64toCert(b64):
    cert_lines = ["-----BEGIN CERTIFICATE-----\n"]
    for i in range(len(b64) // 64 + 1):
        line = b64[i*64 : min(len(b64), i*64 + 64)]
        if len(line) == 0: break
        cert_lines.append(line + "\n")
    cert_lines.append("-----END CERTIFICATE-----\n")
    return cert_lines
    