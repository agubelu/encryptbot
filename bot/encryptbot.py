import sys, os, shutil
from configmanager import generateDomainConfigFile

def showDefaultMessage():
    print("Use \"encryptbot.py help\" to get help.")
    
def displayHelp():
    print("Usage: encryptbot [command] [flags] [parameters]")
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
    print("\nFlags:")
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

domainsFolder = "../encryptbot_domains"

# Generate the domains folder if it doesn't exist yet
if not os.path.isdir(domainsFolder):
    print("encryptbot_domains folder not found, creating a new one with default configuration")
    os.mkdir(domainsFolder)

# If the configuration file is missing, generate a new one
if not os.path.exists(domainsFolder + "/common.cfg"):
    shutil.copy("default_config.cfg", domainsFolder + "/common.cfg")
    

# Loop through the domain folders and generate the config file if it isn't there
for domain in [d[0] for d in os.walk(domainsFolder)][1:]:
    if not os.path.exists(domain + "/domain.cfg"):
        generateDomainConfigFile(domain)

# Handle the command
if len(sys.argv) < 2:
    showDefaultMessage()
    sys.exit(0)
    
command = sys.argv[1].lower()
info = sys.argv[2:]

params = [p for p in info if p[0] != "-"]
flags = [o for o in info if o[0] == "-"]

commands = {
    "help": displayHelp,
    "update": checkForUpdates,
    "get-certs": getCertificates,
    "revoke-certs": revokeCertificates,        
    "create-domain": createDomainFolder
}

commands.get(command, showDefaultMessage)()