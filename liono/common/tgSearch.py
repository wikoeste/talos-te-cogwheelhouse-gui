import os

import requests
from terminaltables import AsciiTable
######################################
def tgFileSearch(sha): #Search TG for shas
    tgurl       = 'https://panacea.threatgrid.com/api/v2/search/submissions?q='
    apiKey      = os.getenv("THREATGRID_API_KEY", "").strip()
    if not apiKey:
        raise RuntimeError("THREATGRID_API_KEY is not configured.")
    total,sums  = (0,0)
    tscores     = []
    thrtbeh     = {"score":[],"name":[],"desc":[]}
    tgdata      = {"fname":[],"sid":[],"date":[],"score":[]}
    metadata    = {"fname":[],"s256":[],"ftype":[],"magic":[]}
    try:
        r = requests.get(
            url=tgurl,
            params={"q": sha, "api_key": apiKey, "limit": 10},
            timeout=(5, 30),
        )
        r.raise_for_status()
        jresp = r.json()
        total = jresp.get('data', {}).get('total') or 0
        if total > 0:
            for x in jresp['data']['items']:
                status      = x['item']['status']
                filename    = x['item']['filename']

                if status == "job_done":
                    #add tgdata
                    thrtScore   = x['item']['analysis']['threat_score']
                    submission  = x['item']['submitted_at']
                    sampleid    = x['item']['sample']
                    tgdata["fname"].append(filename)
                    tgdata["date"].append(submission)
                    tgdata["sid"].append(sampleid)
                    tgdata["score"].append(thrtScore)
                    tscores.append(str(thrtScore))

                    #Get meta data
                    metadata["fname"].append(x['item']['analysis']['metadata']['malware_desc'][0]['filename'])
                    metadata["s256"].append(x['item']['analysis']['metadata']['malware_desc'][0]['sha256'])
                    metadata["ftype"].append(x['item']['analysis']['metadata']['malware_desc'][0]['type'])
                    metadata["magic"].append(x['item']['analysis']['metadata']['malware_desc'][0]['magic'])

                    #Get threat behaviours with a score 85 or greater
                    for b in x['item']['analysis']['behaviors']:
                        thrtvalue = b['threat']
                        if thrtvalue >= 75:
                            #thrtbeh.append({"BIScore":thrtvalue,"BIName":b['name'],"Desc":b['title']})
                            thrtbeh["score"].append(str(thrtvalue))
                            thrtbeh["name"].append(b['name'])
                            thrtbeh["desc"].append(b['title'])
                else: # status is not completed
                    thrtScore = "0"
                    tscores.append(str(thrtScore))
                    submission  = x['item']['submitted_at']
                    sampleid    = x['item']['sample']
                    tgdata["fname"].append(status)
                    tgdata["date"].append(submission)
                    tgdata["sid"].append(sampleid)
                    tgdata["score"].append("N/A")
        else:
            tscores.append(0)
        #get average threat grid scores
        sums        = sum(int(i) for i in tscores)
        samples     = len(tscores)
        avrg        = sums / samples if samples else 0
        avg         = round(avrg, 2)

        #format api data
        fnames       = "\n".join(i for i in tgdata["fname"])
        sampleids    = "\n".join(i for i in tgdata["sid"])
        submitted    = "\n".join(i for i in tgdata["date"])
        scores       = "\n".join(str(i) for i in tscores)
        thrtbehname = "\n".join(i for i in thrtbeh["name"])
        thrtbscr    = "\n".join(str(i) for i in thrtbeh["score"])
        thrtdesc    = "\n".join(str(i) for i in thrtbeh["desc"])
        metafname    = "\n".join(i for i in metadata["fname"])
        metas256     = "\n".join(i for i in metadata["s256"])
        metaftype    = "\n".join(i for i in metadata["ftype"])
        metamagic    = "\n".join(i for i in metadata["magic"])


        #format api results for table printing
        data = [
            ["Sample ID","Score","File Name","Date Submitted"],
            [sampleids,scores,fnames,submitted],
            ["Avg TG Score:", str(avg)],
        ]
        thrtbehdata = [
            ["BI Score","Name","Desc"],
            [str(thrtbscr),thrtbehname,thrtdesc]
        ]
        metatbldata = [
            ["Filename","SHA256","FileType","Magic"],
            [ metafname,metas256,metaftype,metamagic],
        ]
        #
        #biresults = []
        #maresults = []
        #maresults.append(tgdata)
        #biresults.append(thrtbeh)

        #create 2 ascii tabes
        tgresults   = AsciiTable(data)
        tbehresults = AsciiTable(thrtbehdata, 'Threat Behaviours > 80')
        tgmetadata = AsciiTable(metatbldata,'TG Meta Data')
        #Print Tables
        print(tgresults.table)
        print(tbehresults.table)
        print(tgmetadata.table)
        #send back to flask for HTML UI
        return (tgdata,thrtbeh)
    except (requests.RequestException, ValueError, KeyError, TypeError):
        raise RuntimeError("Threat Grid search failed.") from None
