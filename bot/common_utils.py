import os

def getWorkingFolder():
    return os.path.dirname(os.path.realpath(__file__)).replace("\\","/") + "/"

def getDomainsFolder():
    return getWorkingFolder() + "../domains/"

def getDomainFolder(domainName):
    return getDomainsFolder() + domainName