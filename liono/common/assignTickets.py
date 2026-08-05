from liono.common import settings
settings.init()
from liono.logging import logger
import requests,json
requests.packages.urllib3.disable_warnings()
from jira import JIRA

def assignque(ticket):
    results = "Failed to assign ticket {}".format(ticket)
    if type(ticket) == list:
        for i in ticket:
            if "COG" in ticket:
                results = jira(ticket)
                return results
            else:
                return results
    else:
        if "COG" in ticket:
            results = jira(ticket)
            return results
        elif ticket.isdigit() == True: #its bugzilla
            return results
        else:
            return results

def jira(ticket):
    options = {"server": "https://jira.talos.cisco.com"}
    jira = JIRA(basic_auth=(settings.uname, settings.cec), options=options)
    issue = jira.issue(ticket)
    jira.assign_issue(ticket, settings.uname)
    comment(ticket)
    assigned = "The COG case was assigned to {}".format(settings.uname)+", {}".format(ticket)
    return assigned

def comment(ticket):
    template = "I have taken ownership of this ticket and will investigate the issue shortly. \
        I will update the ticket once the analysis is complete. Thank you."
    options = {"server": "https://jira.talos.cisco.com"}
    jira = JIRA(basic_auth=(settings.uname, settings.cec), options=options)
    issue = jira.issue(ticket)
    comment = jira.add_comment(ticket, template)
    success = "COG ticket accepted"
    return success

def resolveclose(ticket):
    hdrs  = {'Content-type': 'application/json'}
    if "COG" in ticket:
        options = {"server": "https://jira.talos.cisco.com"}
        jira = JIRA(basic_auth=(settings.uname, settings.cec), options=options)
        issue = jira.issue(ticket)
        transitions = jira.transitions(issue)
        #print([(t['id'], t['name']) for t in transitions])
        status = issue.fields.status
        #print(status)
        if status == "Open":
            jira.transition_issue(issue, '5', resolution={'id': '1'})
        elif status == "COG Investigating":
            jira.transition_issue(issue, '741', resolution={'id': '1'})
        else:
            jira.transition_issue(issue, '5', resolution={'id': '1'})
    elif ticket.isdigit() == True:  # its bugzilla, resolve bz ticket
        status     = "Resolved"
        resolution = ["Pending","Fixed","Invalid","Later","Complteted","Duplicate","Wontfix","worksforme"]
        data = {'comment': {u'body': u'Closing this bug as, Resolved Fixed', 'is_private': False}, "status":status,
            "resolution":resolution[1],'api_key': settings.bzKey}
        response = requests.put(settings.bugzilla +"/"+ ticket, headers=hdrs, json=data, verify=False)
        if response.status_code == 200 or 201:
            jresp = response.json()
            res = ("BZ API comment POST results", json.dumps(jresp, indent=2))
            print(res)
            logger.log(res)
        else:
            err = ("BZ API Error closing case {}".format(response.status_code))
            logger.log(err)
    else:
        err = ("invalid ticket, ", +ticket)
        print(err)
        logger.log(err)

'''
No longer use this queue
def bzticket(bugid): # auto assign and comment bz tickets
    teuser = settings.uname+"@cisco.com"
    params = {'id': int(bugid), 'assigned_to': teuser,'api_key': settings.bzKey}
    resp = requests.put(settings.bugzilla+"/"+bugid, params=params, verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        #print("BZ API POST Assigned to user", json.dumps(jresp, indent=2))
        #{'last_change_time': '2022-01-07T13:57:43Z',
        # 'id': 2096209,
        # 'changes':
        # {'assigned_to':
        # {'removed': 'vrt-incoming@sourcefire.com', 'added': 'wikoeste@cisco.com'}
        # },
        # 'alias': ['SR692838030']
        # }
        params = {"comment": "Assigned.","api_key": settings.bzKey}
        comment = requests.post(settings.bugzilla+"/"+bugid+"/comment", params=params, verify=False)
        if comment.status_code == 200 or 201:
            jresp = comment.json()
            res = ("BZ API comment POST results", json.dumps(jresp, indent=2))
            print(res)
            logger.log(res)
        else:
            err = ("BZ API Error adding comment {}".format(comment.status_code))
            logger.log(err)
    else:
        err = ("BZ API Assign Error {}".format(resp.status_code))
        logger.log(err)
'''