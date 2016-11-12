import os

def getWorkingFolder():
    return os.path.dirname(os.path.realpath(__file__)) + "/"

def getDomainsFolder():
    return getWorkingFolder() + "../encryptbot_domains/"

def getDomainFolder(domainName):
    return getDomainsFolder() + domainName