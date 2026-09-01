import datetime
import getpass
import os
import re
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_LAYOUT = (PROJECT_ROOT / "templates").is_dir()
DATA_ROOT = Path(
    os.getenv(
        "COGWHEELHOUSE_DATA_ROOT",
        str(PROJECT_ROOT if SOURCE_LAYOUT else Path(sys.prefix) / "share" / "talos-te-cogwheelhouse-gui"),
    )
).expanduser().resolve()
STATE_ROOT = Path(
    os.getenv(
        "COGWHEELHOUSE_STATE_ROOT",
        str(PROJECT_ROOT if SOURCE_LAYOUT else Path.home() / ".local" / "share" / "talos-te-cogwheelhouse-gui"),
    )
).expanduser().resolve()

# Global vars inititialized
def init():
    global uname,cec,umb,umbjira,talosjira,lastninety,elasticqrys
    global filedata,csvfname,rj,sherlockKey,inteldbmatches
    global htmlfname,homedir,templatespath,fname,junoKey,juno,que,results,guidconvert
    global acedbhost,acedatabase,jkey,jsondump,ques,escalations,etd,monthly,cog
    global rule,vrt,snortversion,unedited,projDir,pcapDir,rulesDir,rulesDirs
    global search01,sigmgr,sigkey

# get home dir location based on OS/platform
def gethome():
    home = str(Path.home())
    return str(Path(home) / ".profile"), home

#Get api keys for internal lookups
def getKey(keyname):
    #take the search keyname and return the appropriate api key
    match = ''
    try:
        with open(fname, 'r', encoding='utf-8') as fp:
            lines = fp.read().splitlines()
    except OSError:
        lines = []
    for line in lines:
        if keyname.upper() in line:
            match = line
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
templatespath       = str(DATA_ROOT / "templates") + os.sep
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
projDir      = str(DATA_ROOT / "liono") + os.sep
pcapDir      = str(
    Path(
        os.getenv(
            "PIGREPLAY_PCAP_DIR",
            str((PROJECT_ROOT if SOURCE_LAYOUT else STATE_ROOT) / "liono" / "pigreplay" / "pcaps"),
        )
    ).expanduser().resolve()
) + os.sep
_configured_rules = os.getenv("PIGREPLAY_SHARED_RULES_DIR", "").strip()
rulesDirs    = tuple(
    dict.fromkeys(
        path.rstrip("/") + "/"
        for path in (
            *([_configured_rules] if _configured_rules else []),
            "/var/tmp/snort-rules",
            "/private/var/tmp/snort-rules",
        )
    )
)
# /var/tmp is the canonical cross-platform location. On macOS it resolves to
# /private/var/tmp, so both spellings are retained for rule discovery and UI
# diagnostics while downloads and temporary local rules use one path.
rulesDir     = rulesDirs[0]

# bp cloud download api
bpuser  = "wikoeste"
key     = os.getenv("BP_GITHUB_TOKEN", "")
repo    = "code.engine.sourcefire.com/Cloud/apde-signatures.git"
pkg     = f"https://{bpuser}:{key}@{repo}" if key else f"https://{repo}"
# dictionary to store bp usr input id revision and name
bp      = {"usrstrng":"","id":0,"rev":0,"name":"","active":"","type":""}
bpres   = []

# clam av
search01     = "https://search01.vrt.sourcefire.com/"
sigmgr       = "https://sigmanager.talos.cisco.com/"
sigkey       = getKey("sigmgr")
