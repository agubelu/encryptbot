import os
import requests

def getWorkingFolder():
    return os.path.dirname(os.path.realpath(__file__)).replace("\\","/") + "/"

def getDomainsFolder():
    return getWorkingFolder() + "../domains/"

def getDomainFolder(domainName):
    return getDomainsFolder() + domainName

def getNewNonce(api_url):
    req = requests.get(api_url + "/directory")
    checkRequestStatus(req, 200)
    return req.headers["Replay-Nonce"]
    
def checkRequestStatus(request, expected):
    if request.status_code != expected:
        raise Exception("HTTP code %d: %s" % (request.status_code, request.content.decode("utf-8")))