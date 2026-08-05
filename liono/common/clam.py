from liono.common import settings
settings.init()
import requests,json,re,os,subprocess

# Drop the clamav signature with new sigmgr
def dropsig(sid,reason,notes):
    print(f"\n\n===Drop a ClamAV SigID: {sid}===")
    headers    = {'Content-type': 'application/json','X-APIKEY': settings.sigkey}
    payload    = {"signature_id":sid, "reason":reason, "message":notes}
    url        = settings.sigmgr+"/v1/signature/drop"
    response   = requests.post(url, headers=headers,json=payload,verify=False)
    if response.status_code == 200:
        rjson   = response.json()
        print(json.dumps(rjson, indent=2))
        msg     = rjson["message"]
        msg     = re.sub(r" at.+", "", msg)
        status  = rjson["success"]
        if status == 0:
            status = "Fail"
        else:
            status = "Pass"

        results = ("===SigMgr Drop Status===\n" +
                  "Status : "+ status +
                  f"\nSigID: {sid}" +
                  f"\nDesc : {msg}")
        print(results)
        res = results.replace("\n", "<br>")
        return res
    else:
        err = ("SIG Manager API Error!\n HTTP ERROR: "+ str(response.status_code))
        print(err)

# Search for ClamAV and Amp hits by SHA256 or SampleID (sid)
# this still uses search01.vrt.sourcefire
def searchvrt(sample,vrt):
    results  = []
    url      = settings.search01+"sample/"+sample
    match    = re.match("[A-Za-z.]|\\d{7}\\-\\d",sample)     # clam sample id or rulename via regex
    s256     = re.match("[A-Fa-f0-9]{64}",sample)            # sha256 regex
    if match:
        #get clam sig data from sigtools
        cmd     = f"/usr/local/bin/sigtool --find-sigs={sample}"
        if os.path.isfile("/usr/local/bin/sigtool"):
            try:
                res     = subprocess.run(cmd,capture_output=True,text=True,check=True)
                print(res)
                filtres = re.sub(r"\[.*\]|;.*",'',res)
                print("==ClamAV Sigtool Results==")
                print(filtres)
            except subprocess.CalledProcessError as e:
                err=(f"Command failed with return code {e.returncode}\nSTDOUT: {e.stdout}\nSTDERR: {e.stderr}")
                print(err)
                return err
            except FileNotFoundError as e:
                err=(f"Sigtool not located!\n {e}")
                print(err)
                return err
            except:
                err=(f"==ClamAV Sigtool Results==\n Error with sigtool.")
                print(err)
                return err
        else:
            err=("==ClamAV Sigtool Results==\nSigtool not installed.")
            print(err)
            return err
    elif s256:
        response = requests.get(url, auth =(settings.uname,vrt),verify=False)
        if response.status_code == 200:
            rjson = response.json()
            #print(json.dumps(rjson, indent=2))
            sid              = 0
            s256,ftype       = (None,None)
            fireamp,clam     = ([],[])
            amphits,clamhits = (None,None)
            # get AMP detection
            if len(rjson["fireamp_detection"]["current"]) == 0:
                amphits = "None"
            else:
                [fireamp.append(i) for i in rjson["fireamp_detection"]["current"]]
                amphits = "\n".join(i for i in fireamp)
            # get clam detection
            if len(rjson["clamav_detection"]["current"]) == 0:
                clamhits = "None"
            else:
                [clam.append(i) for i in rjson["clamav_detection"]["current"]]
                clamhits = "\n".join(i for i in clam)
            # get the sid
            if "sample_id" in json.dumps(rjson):
                sid = rjson["sample_id"]
            else:
                sid = "None"
            if "updated" in json.dumps(rjson):
                updated = rjson["updated"]
                updated = re.sub(r"T|Z","",updated)
            else:
                updated = "None"
            try:
                origin = rjson["origin"]
            except KeyError:
                origin = "None"
            try:
                s256 = rjson["SHA256"]
            except KeyError:
                s256 = "None"
            try:
                ftype = rjson["current_mimetype"]
            except KeyError:
                ftype = "Unknown"
            #Print the results from Search01
            #print(s256,sid,updated,clamhits,amphits,origin)
            data = ("SHA256: " + s256+
                "\nSampleID: " + sid+
                "\nUpdated: " + updated+
                "\nFile Type: "+ ftype+
                "\nAmpDections: " + amphits+
                "\nClamAV: " + clamhits+
                "\nOrigin: " + origin)
            data = data.replace("\n", "<br>")
            return data
        else:
            err = (f"VRT Search01 API Error\n HTTP ERROR: {response.status_code}")
            print(err)
            return err
    else:
        err = (f"The submission, {sample}, is not a valid SHA256, Sample-ID or Signature-ID.")
        print(err)
        return err