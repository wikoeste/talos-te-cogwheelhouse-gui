import getpass,re,os.path,datetime

# Global vars inititialized
def init():
    global uname,cec,umb,umbjira,talosjira,lastninety,elasticqrys
    global filedata,csvfname,rj,sherlockKey,inteldbmatches
    global htmlfname,homedir,templatespath,fname,junoKey,juno,que,results,guidconvert
    global acedbhost,acedatabase,jkey,jsondump,ques,escalations,etd,monthly,cog
    global rule,vrt,snortversion,unedited,projDir,pcapDir,rulesDir
    global search01,sigmgr,sigkey

# get home dir location based on OS/platform
def gethome():
    match     = ''
    freebsd   = "/home/{}".format(uname)+"/.profile"
    osx       = "/Users/{}".format(uname)+"/.profile"
    if os.path.exists(freebsd):
        fname   = freebsd
        home    = "/home/{}".format(uname)
    else:
        fname   = osx
        home    = "/Users/{}".format(uname)
    return fname,home

#Get api keys for internal lookups
def getKey(keyname):
    #take the search keyname and return the appropriate api key
    with open(fname, 'r') as fp:
        lines = fp.read().splitlines()
        for l in lines:
            if keyname.upper() in l:
                match = l
    key = re.sub(r'.*=|.*API=','',match) # remove key name and = sign
    key = re.sub(r'"','',key)            # remove quotes from keys
    #print(key)
    return key

# Setting global vars
cec                 = None
uname               = getpass.getuser()
fname,homedir       = gethome()
junoKey             = getKey("jupiter")
sherlockKey         = getKey("sherlock")
jkey                = getKey("jrw")
juno                = 'https://prod-juno-search-api.sv4.ironport.com/'
juno90              = "https://prod-juno-search-api.sco.cisco.com/juno_past_3_months/_search?"
jsondump            = ""
#AnalystConsole Creds
acedbhost           = 'ava-tdbro-01prd.vrt.sourcefire.com'
acedatabase         = 'analyst_console'
templatespath       = "/Users/wikoeste/Documents/PycharmProjects/talos-te-toolbox/templates/"
lastninety          = datetime.datetime.now() - datetime.timedelta(90)
lastseven           = datetime.datetime.now() - datetime.timedelta(7)
# ticket web urls
umbjira             = "https://jira.it.umbrella.com/rest/api/2/search"
talosjira           = "https://jira.talos.cisco.com/rest/api/2/search"
ace                 = "https://analyst-console.vrt.sourcefire.com"
engjira             = "https://jira-eng-rtp3.cisco.com/rest/api/2/search"
clamavjira          = "https://jira-eng-sjc1.cisco.com/rest/api/2/search"
# data dictionary of all ticket data
filedata            = {"ID":[],"Link":[],"Description":[],"DateOpened":[],"LastModified":[]} # assigned/unassigned
elasticqrys         = {"cids":[],"cats":[]}
guidconvert         = {"cid":[],"date":"","rj":[],"esascores":[],'corpscores':[],'rjscores':[],'sbrs':[]}
sbjatresults        = {"tickets":[],"scores":[],"hits":[]}
inteldbmatches      = {'url':[],'feed':[],'time':0}
ques                = {'cog':0,'email':0,'web':0,'snort':0,'amp':0,'other':0,'sbrs':0,'sdr':0,'open':0,'closed':0,"hot":0}
escalations         = {'total':0,'eers':0,'thr':0,'resbz':0,'webcat':0}
etd                 ={'total':0,'fp':0,'fn':0,'other':0}
monthly             = ''
cog                 = ''
etdresults          = []
acedata             = []

# file names
csvfname            = os.path.join(templatespath, "casemanager-smry.csv")
htmlfname           = os.path.join(templatespath, "assigned.html")
unassigned          = os.path.join(templatespath, "unassigned.html")
elastichtml         = os.path.join(templatespath, "results/elasticresults.html")
rjresultshtml       = os.path.join(templatespath, "results/rjresults.html")
acehtml             = os.path.join(templatespath, "acetickets.html")
backlogbuddy        = os.path.join(templatespath, "scripts/backlogbuddy.html")
wbrsfeeds           = os.path.join(templatespath, "scripts/wbrsfeeds.html")

#snort replay
snortversion = None
rule         = None
unedited     = None
vrt          = None
projDir      = "/Users/" + uname + "/Documents/PycharmProjects/talos-te-toolbox/liono/"
pcapDir      = "/Users/" + uname + "/Documents/PycharmProjects/talos-te-toolbox/liono/pigreplay/pcaps/"
rulesDir     = "/Users/" + uname + "/Documents/PycharmProjects/talos-te-toolbox/liono/pigreplay/snort-rules/"

# bp cloud download api
bpuser  = "wikoeste"
key     = "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"
repo    = "code.engine.sourcefire.com/Cloud/apde-signatures.git"
pkg     = f"https://{bpuser}:{key}@{repo}"
# dictionary to store bp usr input id revision and name
bp      = {"usrstrng":"","id":0,"rev":0,"name":"","active":"","type":""}
bpres   = []

# clam av
search01     = "https://search01.vrt.sourcefire.com/"
sigmgr       = "https://sigmanager.talos.cisco.com/"
sigkey       = getKey("sigmgr")