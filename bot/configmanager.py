def generateDomainConfigFile(domain):
    with open("default_config.cfg") as def_config:
        content = def_config.readlines()
        new_file = content[0:6]
        new_file.append("\n")
        print(new_file)