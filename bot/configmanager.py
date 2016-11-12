import os

def generateDomainConfigFile(domain):
    workingFolder = os.path.dirname(os.path.realpath(__file__))
    
    with open(workingFolder + "/default_config.cfg") as def_config:
        content = def_config.readlines()
        new_file = content[0:6]
        new_file.append("\n")
        new_file.append("# Domain alternative names separated by spaces\n")
        new_file.append("# Do NOT include the primary name (i.e. the folder name)\n")
        new_file.append("alternative_names=\"host1.yourdomain.com host2.yourdomain.com\"\n")
        new_file.append("\n")
        new_file.append("# Web root path for your domain(s) separated by spaces\n")
        new_file.append("# One for your primary name and one for each alternative name\n")
        new_file.append("web_roots=\"/var/www/html/\" \"/var/www/html\"\n")
        new_file.append("\n")
        new_file.append("# Domain-specific overrides\n")
        new_file.append("\n")
        new_file += ["# " + option for option in content[6:] if option[0] != "#" and option[0] != "\n"]
        
        file = open(domain + "/domain.cfg", "w")
        file.writelines(new_file)
        file.close()
