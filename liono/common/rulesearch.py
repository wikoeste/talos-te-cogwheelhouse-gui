from liono.common import settings
import os,re

# open local rules and remove the keywords for local replay
def writelocal(rule):
    with open(settings.rulesDir + 'local.rules', 'r+') as fw:
        text = fw.read()
        rule = re.sub('^#', '', text)
        rule = re.sub('detection_filter.+?;', '', rule)
        rule = re.sub('flowbits.+?;', '', rule)
        rule = re.sub('flow:.+?;', '', rule)
        settings.rule = rule
        fw.seek(0)
        fw.write(rule)
        fw.truncate()
    fw.close()

# get snort rule text
def snortsig(sid):
    found = None
    sid.strip()
    rules = "local.rules"
    rule  = None
    path  = settings.rulesDir
    if sid.isdigit() is False:  # sid is raw rule text and not an integer
        with open(path + 'local.rules', 'w') as f:
            f.write(sid)
            settings.unedited = sid
            rule = sid
            f.close()
        writelocal(rule)
    elif int(sid) < 1000000:           # search for any sid < one million
        ruleid = (f"sid:{sid};")
        print(ruleid)
        for file in os.listdir(path):
            fname = os.path.join(path,file)
            if ruleid in open(fname).read():
                print("Rule found in, "+ file)              # print the rule file name
                found = fname
                for line in open(found):
                    for match in re.finditer(ruleid, line):
                        with open (path+'local.rules', 'w') as f:
                            f.write(line)
                            settings.unedited = line        # write the rule to return
                            rule              = line
                            f.close()
                writelocal(rule)                            # write a local copy of the rule to test with as a backup
    else:                                                   # Error in finding the rule
        settings.unedited   = rule
        settings.rule       = rule
        print(sid + ":Not Found in Snort Rules")
    print(rule)                                             #print what rule we found for debugging