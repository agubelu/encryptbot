import sys

def showDefaultMessage():
    print("Use \"encryptbot.py help\" to get help.")
    
def displayHelp():
    print("Usage: encryptbot [command] [options] [parameters]")
    print("\nAvailable commands:")
    print("help - Displays this information")
    print("update - Checks if a new version of encryptbot is available and updates if so")
    print("create-domain - Creates a new domain to be managed by encryptbot (use before get-certs and revoke-certs)")
    print("    Example: encryptbot.py create-domain yourdomain1.com yourdomain2.net")
    print("get-certs - Obtains certificates for the domains specified in [parameters]")
    print("    Example: encryptbot.py get-certs -f yourdomain1.com yourdomain2.net")
    print("    Example: encryptbot.py get-certs -a")
    print("revoke-certs - Revokes a domain certificate")
    print("    Example: encryptbot.py revoke-certs yourdomain1.com")
    print("\nOptions:")
    print("-a - Obtain certificates for all registered domains")
    print("-f - Force certificate retrieval ignoring expiry checks (be wary of rate limits)")

def checkForUpdates():
    pass

def getCertificates():
    pass

def revokeCertificates():
    pass

def createDomainFolder():
    pass

#####################################################################################################

if len(sys.argv) < 2:
    showDefaultMessage()
    sys.exit(0)
    
command = sys.argv[1].lower()
info = sys.argv[2:]

params = [p for p in info if p[0] != "-"]
options = [o for o in info if o[0] == "-"]

commands = {
    "help": displayHelp,
    "update": checkForUpdates,
    "get-certs": getCertificates,
    "revoke-certs": revokeCertificates,        
    "create-domain": createDomainFolder
}

commands.get(command, showDefaultMessage)()