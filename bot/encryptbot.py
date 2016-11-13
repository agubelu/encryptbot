import sys, shutil
from configmanager import *
from common_utils import *

workingFolder = getWorkingFolder()
domainsFolder = getDomainsFolder()

def showDefaultMessage(flags, params):
    print("Use \"encryptbot.py help\" to get help.")
    
def displayHelp(flags, params):
    print("Usage: encryptbot [command] [flags] [parameters]")
    print("\nAvailable commands:")
    print("  help          - Displays this information")
    print("  update        - Checks if a new version of encryptbot is available and updates if so")
    print("  create-domain - Creates a new domain to be managed by encryptbot (use before get-certs and revoke-certs)")
    print("      Example: encryptbot.py create-domain yourdomain1.com yourdomain2.net")
    print("  get-certs     - Obtains certificates for the domains specified in [parameters]")
    print("      Example: encryptbot.py get-certs -f yourdomain1.com yourdomain2.net")
    print("      Example: encryptbot.py get-certs -a")
    print("  revoke-certs  - Revokes a domain certificate")
    print("      Example: encryptbot.py revoke-certs yourdomain1.com")
    print("\nFlags:")
    print("  -a - Obtain certificates for all registered domains")
    print("  -f - Force certificate retrieval ignoring expiry checks (be wary of rate limits)")

def checkForUpdates(flags, params):
    pass #TODO

def getCertificates(flags, params):
    pass #TODO

def revokeCertificates(flags, params):
    pass #TODO

def createDomainFolder(flags, params):
    for domain in params:
        if not os.path.exists(getDomainFolder(domain)):
            os.mkdir(getDomainFolder(domain))
            generateDomainConfigFile(getDomainFolder(domain))
            print("Created domain " + domain)
        else:
            print("Domain %s already exists, skipping" % domain)

#####################################################################################################

# Generate the domains folder if it doesn't exist yet
if not os.path.exists(domainsFolder):
    print("encryptbot_domains folder not found, creating a new one with default configuration")
    os.mkdir(domainsFolder)

# If the configuration file is missing, generate a new one
if not os.path.exists(domainsFolder + "common.cfg"):
    shutil.copy(workingFolder + "default_config.cfg", domainsFolder + "common.cfg")
    

# Loop through the domain folders and generate the config file if it isn't there
for domain in [d[0] for d in os.walk(domainsFolder)][1:]:
    if not os.path.exists(domain + "/domain.cfg"):
        generateDomainConfigFile(domain)

# Handle the command
if len(sys.argv) < 2:
    showDefaultMessage(None, None)
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

commands.get(command, showDefaultMessage)(flags, params)