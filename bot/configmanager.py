from common_utils import getWorkingFolder, getDomainsFolder, getDomainFolder
import re
from codecs import open

def generateDomainConfigFile(domain):
    with open(getWorkingFolder() + "default_config.cfg", "r", "utf-8") as def_config:
        content = def_config.readlines()
        new_file = content[0:6]
        new_file.append("\n")
        new_file.append("# Domain alternative names separated by spaces\n")
        new_file.append("# Do NOT include the primary name (i.e. the folder name)\n")
        new_file.append("alternative_names=\"host1.yourdomain.com host2.yourdomain.com\"\n")
        new_file.append("\n")
        new_file.append("# Web root path for your domain(s) separated by spaces\n")
        new_file.append("# One for your primary name and one for each alternative name\n")
        new_file.append("web_roots=\"/var/www/html1 /var/www/html2 /var/www/html3\"\n")
        new_file.append("\n")
        new_file.append("# Domain-specific overrides\n")
        new_file.append("# Un-comment them as you need\n")
        new_file.append("\n")
        new_file += ["# " + option for option in content[6:] if option[0] != "#" and option[0] != "\n"]
        
        file = open(domain + "/domain.cfg", "w", "utf-8")
        file.writelines(new_file)
        file.close()
        
def getGlobalConfig():
    res = {}
    with open(getDomainsFolder() + "common.cfg", "r", "utf-8") as config:
        for line in [l for l in config.readlines() if l[0] != "#" and l[0] != "\n" and l[0] != "\r"]:
            matches = re.match("(.*?)\s*=\s*\"(.*?)\"", line)
            key = matches.group(1)
            val = matches.group(2)
            res[key] = val
    return res        
            
def getDomainConfig(domainName):
    res = getGlobalConfig()
    with open(getDomainFolder(domainName) + "domain.cfg", "r", "utf-8") as config:
        for line in [l for l in config.readlines() if l[0] != "#" and l[0] != "\n" and l[0] != "\r"]:
            matches = re.match("\s*(.*?)\s*=\s*\"(.*?)\"", line)
            key = matches.group(1)
            val = matches.group(2)
            res[key] = val
    return res