from common_utils import getDomainFolder, getDomainsFolder
from configmanager import getDomainConfig, getGlobalConfig
from time import sleep
import sys, os, re
from urllib.request import urlopen
import cryptoutils

def retrieveCertificate(domainName, flags):
    
    if not os.path.exists(getDomainsFolder() + "account.key"):
        createAccount()

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
    sleep(15)
    
    global_conf = getGlobalConfig()
    key_algo = global_conf["algorithm"]
    key_len = global_conf["key_length"]
    
    if key_algo not in cryptoutils.supported_algorithms:
        raise Exception("Algorithm %s not supported" % key_algo)
    
    print("\n\nGenerating account keypair...")
    sys.stdout.flush()
    
    folderpath = getDomainsFolder()
    if key_algo == "rsa":
        cryptoutils.generateRSAkeypair(key_len, folderpath + "account.key")
    else:
        cryptoutils.generateECkeypair(key_algo, folderpath + "account.key")