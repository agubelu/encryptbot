from common_utils   import getWorkingFolder, getDomainsFolder, getDomainFolder, generateDomainConfigFile
from certs          import retrieveCertificate, revokeCertificate

import sys, shutil, os

VERSION = "0.1"

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
    print("      Example: encryptbot.py get-certs yourdomain1.com yourdomain2.net")
    print("      Example: encryptbot.py get-certs -f yourdomain1.com")
    print("      Example: encryptbot.py get-certs -a")
    print("  revoke-certs  - Revokes a domain certificate")
    print("      Example: encryptbot.py revoke-certs yourdomain1.com")
    print("\nFlags:")
    print("  -a - Select all registered domains")
    print("  -f - Force certificate retrieval ignoring expiry checks (be wary of rate limits)")
    print("  -d - Delete certificate(s) after a successful revocation")

def checkForUpdates(flags, params):
    pass #TODO: hacer

def getCertificates(flags, params):
    registeredDomains = next(os.walk(domainsFolder))[1]
    
    if "-a" in flags:
        domains = registeredDomains
    else:
        domains = params
        
    for dom in domains:
        if dom not in registeredDomains:
            print("Domain %s is not found, skipping..." % dom)
            continue
        retrieveCertificate(dom, flags)

def revokeCertificates(flags, params):
    registeredDomains = next(os.walk(domainsFolder))[1]
    
    if "-a" in flags:
        print("You are about to revoke ALL of your certificates!")
        sys.stdout.flush()
        conf = input("Do you wish to continue? [y/N]:")
        
        if conf.lower() != "y": return
        domains = registeredDomains
    else:
        domains = params
        
    for dom in domains:
        if dom not in registeredDomains:
            print("Domain %s is not found, skipping..." % dom)
            continue
        revokeCertificate(dom, flags)
        

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
    print("domains folder not found, creating a new one with default configuration")
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