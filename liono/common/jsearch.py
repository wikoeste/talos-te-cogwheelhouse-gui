from liono.common import settings
from jira import JIRA
from jira.exceptions import JIRAError
import requests,os,re,json,threading
from collections import Counter, OrderedDict
from dataclasses import dataclass
from datetime import date, timedelta


JIRA_SERVER = "https://jira.talos.cisco.com"
JIRA_METRIC_FIELDS = (
    "summary,created,resolutiondate,priority,status,resolution,"
    "issuetype,customfield_13528"
)
JIRA_METRIC_DAY_OPTIONS = OrderedDict((("7", 7), ("30", 30), ("60", 60)))
JIRA_METRIC_FISCAL_OPTION_COUNT = 8
PRODUCT_ISSUE_TYPES = {
    "IPAS": {"email"},
    "FILE": {"endpoint"},
    "SNORT": {"vulnerability"},
    "SBRS": {"sbrs"},
    "WEB": {"phishtank", "web"},
    "OTHER": {"anti-virus", "mailer", "other"},
}
HIGH_VOLUME_CUSTOMER_THRESHOLD = 5


class JiraMetricsError(RuntimeError):
    """Raised when COG Jira metrics cannot be retrieved."""


class JiraMetricsPeriodError(ValueError):
    """Raised when a Jira Metrics reporting period is not supported."""


@dataclass(frozen=True)
class JiraMetricDateRange:
    key: str
    label: str
    start: date
    end: date

    @property
    def end_exclusive(self):
        return self.end + timedelta(days=1)

    @property
    def display(self):
        return "{} – {}".format(
            self.start.strftime("%B %-d, %Y"),
            self.end.strftime("%B %-d, %Y"),
        )


def _last_saturday_in_july(year):
    day = date(year, 7, 31)
    return day - timedelta(days=(day.weekday() - 5) % 7)


def _fiscal_year_start(fiscal_year):
    return _last_saturday_in_july(fiscal_year - 1) + timedelta(days=1)


def _fiscal_quarter_range(fiscal_year, quarter):
    if quarter not in (1, 2, 3, 4):
        raise JiraMetricsPeriodError("Unsupported Cisco fiscal quarter.")
    fiscal_start = _fiscal_year_start(fiscal_year)
    start = fiscal_start + timedelta(weeks=13 * (quarter - 1))
    next_start = (
        fiscal_start + timedelta(weeks=13 * quarter)
        if quarter < 4
        else _fiscal_year_start(fiscal_year + 1)
    )
    key = "FY{}-Q{}".format(fiscal_year, quarter)
    return JiraMetricDateRange(
        key=key,
        label="Cisco FY{} Q{}".format(fiscal_year, quarter),
        start=start,
        end=next_start - timedelta(days=1),
    )


def _fiscal_quarter_for_day(day):
    fiscal_year = day.year if day <= _last_saturday_in_july(day.year) else day.year + 1
    fiscal_start = _fiscal_year_start(fiscal_year)
    quarter = min(((day - fiscal_start).days // 91) + 1, 4)
    return fiscal_year, quarter


def fiscal_quarter_options(today=None, count=JIRA_METRIC_FISCAL_OPTION_COUNT):
    """Return the current and recent Cisco fiscal quarters, newest first."""
    day = today or date.today()
    fiscal_year, quarter = _fiscal_quarter_for_day(day)
    options = []
    for offset in range(count):
        position = (fiscal_year * 4 + quarter - 1) - offset
        option_year, option_index = divmod(position, 4)
        options.append(_fiscal_quarter_range(option_year, option_index + 1))
    return options


def resolve_metric_date_range(period="7", quarter=None, today=None):
    """Resolve an allowlisted reporting period into immutable calendar dates."""
    day = today or date.today()
    if period in JIRA_METRIC_DAY_OPTIONS:
        days = JIRA_METRIC_DAY_OPTIONS[period]
        return JiraMetricDateRange(
            key=period,
            label="Last {} days".format(days),
            start=day - timedelta(days=days - 1),
            end=day,
        )
    if period != "fiscal":
        raise JiraMetricsPeriodError("Unsupported Jira Metrics date range.")

    allowed_quarters = {
        option.key: option for option in fiscal_quarter_options(today=day)
    }
    selected = quarter or next(iter(allowed_quarters))
    try:
        return allowed_quarters[selected]
    except KeyError as exc:
        raise JiraMetricsPeriodError("Unsupported Cisco fiscal quarter.") from exc


def _metric_queries(date_range):
    start = date_range.start.isoformat()
    end = date_range.end_exclusive.isoformat()
    created_window = 'created >= "{}" AND created < "{}"'.format(start, end)
    resolved_window = 'resolved >= "{}" AND resolved < "{}"'.format(start, end)
    return OrderedDict((
        ("priority", (
            "project = COG AND priority in (P1, P2) AND {} "
            "ORDER BY created DESC"
        ).format(created_window)),
        ("invalid", (
            "project = COG AND resolution = Invalid AND {} "
            "ORDER BY resolved DESC"
        ).format(resolved_window)),
        ("mailer", (
            "project = COG AND issuetype = Mailer AND {} "
            "ORDER BY created DESC"
        ).format(created_window)),
        ("all", "project = COG AND {} ORDER BY created DESC".format(created_window)),
    ))


def _field_name(value):
    return str(getattr(value, "name", value) or "Unknown")


def _date_only(value):
    return str(value or "Unknown").split("T", 1)[0]


def _metric_row(issue):
    fields = issue.fields
    return {
        "key": str(issue.key),
        "summary": str(getattr(fields, "summary", "") or "No summary"),
        "priority": _field_name(getattr(fields, "priority", None)),
        "created": _date_only(getattr(fields, "created", None)),
        "resolved": _date_only(getattr(fields, "resolutiondate", None)),
        "status": _field_name(getattr(fields, "status", None)),
        "resolution": _field_name(getattr(fields, "resolution", None)),
    }


def _product_breakdown(issues):
    counts = OrderedDict((product, 0) for product in PRODUCT_ISSUE_TYPES)
    unmapped = 0
    for issue in issues:
        issue_type = _field_name(getattr(issue.fields, "issuetype", None)).casefold()
        product = next(
            (
                name
                for name, issue_types in PRODUCT_ISSUE_TYPES.items()
                if issue_type in issue_types
            ),
            None,
        )
        if product:
            counts[product] += 1
        else:
            unmapped += 1
    rows = [{"product": name, "count": count} for name, count in counts.items()]
    if unmapped:
        rows.append({"product": "UNMAPPED", "count": unmapped})
    rows.append({"product": "TOTAL COG REQUESTS", "count": len(issues)})
    return rows


def _customer_name(value):
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    for attribute in ("value", "name", "displayName"):
        candidate = getattr(value, attribute, None)
        if candidate:
            return str(candidate).strip()
    customer = str(value or "").strip()
    return customer or "Unknown"


def _high_volume_customers(issues):
    counts = Counter(
        _customer_name(getattr(issue.fields, "customfield_13528", None))
        for issue in issues
    )
    return [
        {"customer": customer, "count": count}
        for customer, count in sorted(
            counts.items(), key=lambda item: (-item[1], item[0].casefold())
        )
        if customer != "Unknown" and count > HIGH_VOLUME_CUSTOMER_THRESHOLD
    ]


def jira_metrics(date_range=None, jira=None):
    """Return COG Request metrics for one validated reporting window."""
    selected_range = date_range or resolve_metric_date_range()
    try:
        client = jira or JIRA(
            basic_auth=(settings.uname, settings.jkey),
            options={"server": JIRA_SERVER},
            get_server_info=False,
            max_retries=2,
            timeout=(5, 30),
        )
        issue_sets = {
            name: list(
                client.search_issues(
                    jql,
                    maxResults=False,
                    fields=JIRA_METRIC_FIELDS,
                )
            )
            for name, jql in _metric_queries(selected_range).items()
        }
        all_issues = issue_sets["all"]
        return {
            "priority": [_metric_row(issue) for issue in issue_sets["priority"]],
            "invalid": [_metric_row(issue) for issue in issue_sets["invalid"]],
            "mailer": [_metric_row(issue) for issue in issue_sets["mailer"]],
            "products": _product_breakdown(all_issues),
            "customers": _high_volume_customers(all_issues),
            "date_range": selected_range,
        }
    except (JIRAError, OSError, ValueError, TypeError, AttributeError) as exc:
        raise JiraMetricsError("Unable to retrieve Jira Metrics from COG Requests.") from exc

# search the various jira q's for any related tickets
def search(queue,qry):
    results     = None
    res         = []
    options     = {"server": "https://jira.talos.cisco.com"}
    jira        = JIRA(basic_auth=(settings.uname, settings.jkey), options=options)
    # Print the results by queue
    if queue == "COG":
        jqry = 'project=COG AND text ~ "' + str(qry) + '" order by key desc'
        results = jira.search_issues(str(jqry), maxResults=100)
        print("=== COG Search Results===")
        for r in results:
            print('{}'.format(r.key))
            res.append(r.key)
        return res
    elif queue  == "EERS":
        jqry = 'project=EERS AND text ~ "' + str(qry) + '" order by key desc'
        results = jira.search_issues(str(jqry), maxResults=10)
        print("===EERS Search Results===")
        for r in results:
            print('{}'.format(r.key))
            res.append(r.key)
        return res
    elif queue  == "RESBZ":
        print(qry)
        jqry = 'project=RESBZ AND text ~ "' + str(qry) + '" order by key desc'
        results = jira.search_issues(str(jqry), maxResults=10)
        print("===RESBZ Search Results===")
        for r in results:
            print('{}'.format(r.key))
            res.append(r.key)
        return res
    elif queue  == "THR":
        jqry = 'project= THR AND text ~ "' + str(qry) + '" order by key desc'
        results = jira.search_issues(str(jqry), maxResults=10)
        print("===THR Search Results===")
        for r in results:
            print('{}'.format(r.key))
            res.append(r.key)
        return res
    elif queue == "ALL":
        jqry    = 'project in (COG,EERS,THR,RESBZ) AND text ~ "'+str(qry)+'" order by key desc'
        results = jira.search_issues(str(jqry), maxResults=10)
        print("===All Jira Q's Search Results===")
        for r in results:
            print('{}'.format(r.key))
            res.append(r.key)
        return res
    # ERROR
    else:
        err = "Error, there is no ticket queue {}".format(queue)
        print(err)
        return err

def last7():
    tix,created,status,results = ([],)*4
    op,cl,reo       = 0,0,0
    jql             = None
    headers         = {'Content-type': 'application/json'}
    rqurl           = "https://jira.talos.cisco.com/rest/api/2/search"
    #assigned in the last 7
    jql = "?jql=project=COG and created >= -7d and assignee in (" + settings.uname + ")+"# AND status in (Open, Reopened, 'Pending Reporter', 'COG Investigating', 'Pending 3rd Party') order by updated DESC"
    resp = requests.get(rqurl+jql, headers=headers,auth=(settings.uname,settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        #print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            for i in jresp['issues']:
                tix.append(i['key'])
                datefrmt = re.sub("T.+", "", i['fields']['created'])
                created.append(datefrmt)
                status.append(i['fields']['status']['name'])
                if (i['fields']['status']['name'] == "Open"):
                    op+=1
                elif (i['fields']['status']['name'] == 'Resolved'):
                    cl+=1
                elif (i['fields']['status']['name'] == 'Reopened'):
                    reo+=1
                else:
                    pass

        return tix,op,cl,reo
    else:
        return None,0,0,0

def ques():
    proj    = ["COG","EERS","THR","BZ"]
    itype   = ["EMAIL","FILE","SNORT","WEB","OTHER","SBRS","ETD"]
    jql     = None
    headers = {'Content-type': 'application/json'}
    rqurl   = "https://jira.talos.cisco.com/rest/api/2/search"

    # submitted cog tix in last 7 days
    jql = "?jql=project=COG and created >= -7d&maxResults=500"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'cog':len(jresp['issues'])})
    else:
        settings.ques.update({'cog':0})

    # cog - type email
    jql = "?jql=project=COG AND issuetype = Email and created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'email':len(jresp['issues'])})
    else:
        settings.ques.update({'email':0})

    # cog - type web+phish
    jql = "?jql=project=COG AND issuetype in (Phishtank, Web) and created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'web':len(jresp['issues'])})
        else:
            settings.ques.update({'web':0})

    # cog - type endpoint/amp
    jql = "?jql=project=COG AND issuetype = Endpoint and created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'amp': len(jresp['issues'])})
        else:
            settings.ques.update({'amp': 0})

    # cog - type snort
    jql = "?jql=project=COG AND issuetype = Vulnerability and created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'snort': len(jresp['issues'])})
        else:
            settings.ques.update({'snort': 0})
    else:
        print("HTTP ERR: "+resp.status_code)

    # cog - type sbrs
    jql = "?jql=project=COG AND issuetype = SBRS and created >= -7d AND assignee in (membersOf(cog_users))"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'sbrs': len(jresp['issues'])})
        else:
            settings.ques.update({'sbrs': 0})

    # cog - type other
    jql = "?jql=project=COG AND issuetype in (Anti-Virus, Mailer, Other) and created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'other': len(jresp['issues'])})
        else:
            settings.ques.update({'other': 0})

    closed    = "?jql=project=COG AND status in (Resolved, Closed) AND created >= -7D&maxResults=100"
    # closed in last 7
    rclsd = requests.get(rqurl + closed, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if rclsd.status_code == 200:
        jresp = rclsd.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print('closed ' + str(len(jresp['issues'])))
            settings.ques.update({'closed': len(jresp['issues'])})
        else:
            settings.ques.update({'closed': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # still open last 7
    notclosed = "?jql=project=COG AND status not in (Resolved, Closed) AND created >= -7D&maxResults=100"
    ropen = requests.get(rqurl + notclosed, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if ropen.status_code == 200:
        jresp = ropen.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print('not closed ', str(len(jresp['issues'])))
            settings.ques.update({'open': len(jresp['issues'])})
        else:
            settings.ques.update({'open': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # COG ESCALATED TO....
    # escalated by cog to ee,ntdr,thr,sdow
    jql = "?jql=project in (EERS, RESBZ, SDOCS, SDOW, THR) AND created >= -7d AND reporter in (membersOf(cog_users))&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        print('escalations ='+ str(len(jresp['issues'])))
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            #print(len(jresp['issues']))
            settings.escalations.update({'total': len(jresp['issues'])})
        else:
            settings.escalations.update({'total': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # escalated to ee
    jql = "?jql=project=EERS AND created >= -7d AND reporter in (membersOf(cog_users))&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.escalations.update({'eers': len(jresp['issues'])})
        else:
            settings.escalations.update({'eers': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    #escalated to resbz
    jql  = "?jql=project = RESBZ AND created >= -7d AND reporter in (membersOf(cog_users))&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.escalations.update({'resbz': len(jresp['issues'])})
        else:
            settings.escalations.update({'resbz':0})
    else:
        print('HTTP ERR:', resp.status_code)

    #escalated to THR
    jql = "?jql=project = THR AND created >= -7d AND reporter in (membersOf(cog_users))&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.escalations.update({'thr': len(jresp['issues'])})
        else:
            settings.escalations.update({'thr': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # etd fn
    jql = "?jql=project = COG AND cf[20021] in (cascadeOption(33092)) AND assignee in (membersOf(cog_users)) AND created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.etd.update({'fn': len(jresp['issues'])})
        else:
            settings.etd.update({'fn': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # etd fp
    jql = "?jql=project = COG AND cf[20021] in (cascadeOption(33093)) AND assignee in (membersOf(cog_users)) AND created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.etd.update({'fp': len(jresp['issues'])})
        else:
            settings.etd.update({'fp': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # etd other
    jql = "?jql=project = COG AND cf[20021] in (cascadeOption(33094)) AND assignee in (membersOf(cog_users)) AND created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.etd.update({'other': len(jresp['issues'])})
        else:
            settings.etd.update({'other': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # cog all p1 & p2 last 7
    jql = "?jql=project = COG AND priority in (P1, P2) AND created >= -7d ORDER BY created DESC&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            print(len(jresp['issues']))
            settings.ques.update({'hot': len(jresp['issues'])})
        else:
            settings.ques.update({'hot': 0})
    else:
        print('HTTP ERR:', resp.status_code)

    # cases by company in last 7 days
    totl = 0
    comp = []
    jql  = "?jql=project = COG AND created >= -7d&maxResults=500"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            totl = len(jresp['issues'])
            for i in jresp['issues']:
                name = i["fields"]["customfield_13528"]
                comp.append(name)
            cust    = Counter(comp)
            srtcust = OrderedDict(cust.most_common())
            settings.monthly = srtcust
            settings.monthly.update({"Total":totl})
        else:
            settings.monthly = 0
    else:
        print('HTTP ERR:', resp.status_code)

    # open cases per TE engineer last 7
    te  = []
    jql = "?jql=project = COG AND assignee in (membersOf(cog_users)) AND created >= -7d&maxResults=100"
    resp = requests.get(rqurl + jql, headers=headers, auth=(settings.uname, settings.jkey), verify=False)
    if resp.status_code == 200:
        jresp = resp.json()
        # print(json.dumps(jresp, indent=2))
        if len(jresp['issues']) > 0:
            for i in jresp["issues"]:
                assignee = i["fields"]["assignee"]["displayName"]
                te.append(assignee)
            cog     = Counter(te)
            cogordr = OrderedDict(cog.most_common())
            settings.cog = cogordr
        else:
            settings.cog.update({'total': 0})
    else:
        print('HTTP ERR:', resp.status_code)
