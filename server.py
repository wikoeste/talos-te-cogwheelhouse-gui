# lib imports
from flask import Flask,render_template,request,redirect,session,url_for,send_from_directory,flash,jsonify
from werkzeug.exceptions import NotFound
from werkzeug.utils import secure_filename
import re,json,ipaddress,os,sys,datetime,itertools,csv,io,hmac,secrets
import subprocess
from datetime import timedelta
from pathlib import Path
from flask_login import current_user
import pandas as pd
import git
from dotenv import load_dotenv


__version__ = "0.6.0"
PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env", override=False)
INSTALLED_DATA_ROOT = Path(sys.prefix) / "share" / "talos-te-cogwheelhouse-gui"
DATA_ROOT = PROJECT_ROOT if (PROJECT_ROOT / "templates").is_dir() else INSTALLED_DATA_ROOT

# local file imports
from liono import main as loader
from liono.common import settings
settings.init()
from liono.common import assignTickets,getTickets,q,csvtohtml,sherlock,bpsearch
from liono.common import aceqrys,jsearch,inteldb,ruledownload,snortreplay,tgSearch,clam
from liono.common import rulesearch as rs
from liono.common import teamcalendar
from liono.common import sicategories
from liono.common import malicious_top100 as malicious_top100_data
from liono.common import elasticqueries as elastic_queries_service
from liono.common import jirapost, replaypost
from liono.common import pcapanalyzer
from liono.common import bpsearch_queries
from liono.common import crlookup as crlookup_api

# Flask app config
app = Flask(
    __name__,
    template_folder=str(DATA_ROOT / "templates"),
    static_folder=str(DATA_ROOT / "static"),
)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)
# configure project folders for upload and downloads
RULES_FOLDER       = settings.rulesDir #snort rules download dir
UPLOAD_FOLDER      = settings.pcapDir  #pcaps directory
ALLOWED_EXTENSIONS = {'pcap'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['RULES_FOLDER']  = RULES_FOLDER
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = timedelta(days=7)
#################################################
#################################################

# Web templates
@app.route('/') # goes to layout.html
def home():
    if 'username' in session:
        username = session['username']
        print('Logged in as ' + username)
        return redirect('/layout')
    return redirect(url_for('login'))

@app.route('/layout')
def layout():
    if 'username' in session:
        return render_template('layout.html')
    return redirect(url_for('notloggedin'))


def _malicious_top100_csrf_token():
    token = session.get('malicious_top100_csrf')
    if not token:
        token = secrets.token_urlsafe(32)
        session['malicious_top100_csrf'] = token
    return token


def _replay_csrf_token():
    token = session.get('replay_csrf')
    if not token:
        token = secrets.token_urlsafe(32)
        session['replay_csrf'] = token
    return token


def _cr_csrf_token():
    token = session.get('cr_csrf')
    if not token:
        token = secrets.token_urlsafe(32)
        session['cr_csrf'] = token
    return token


def _bpsearch_csrf_token():
    token = session.get('bpsearch_csrf')
    if not token:
        token = secrets.token_urlsafe(32)
        session['bpsearch_csrf'] = token
    return token


def _valid_bpsearch_csrf():
    expected = session.get('bpsearch_csrf', '')
    supplied = request.form.get('csrf_token', '')
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def _valid_replay_csrf():
    expected = session.get('replay_csrf', '')
    supplied = request.form.get('csrf_token', '')
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def _valid_cr_csrf():
    expected = session.get('cr_csrf', '')
    supplied = request.form.get('csrf_token', '')
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def _malicious_top100_api_unauthorized():
    return jsonify({'error': 'authentication required'}), 401


@app.after_request
def _malicious_top100_security_headers(response):
    protected_tool_path = (
        request.path == '/malicious-top100'
        or request.path.startswith('/api/malicious-top100/')
        or request.path in {
            '/elasticq', '/getelastic', '/replay', '/testpcap',
            '/testpcap/results/jira', '/bpSearch', '/getbp',
            '/analyzepcap', '/analyzepcap/results',
            '/bpsearch/query', '/bpdownload',
            '/crlookup', '/crlookup/results', '/crlookup/results/jira',
        }
    )
    if protected_tool_path:
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response


@app.route('/malicious-top100')
def malicious_top100():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    return render_template(
        'malicious_top100.html',
        csrf_token=_malicious_top100_csrf_token(),
    )


@app.route('/api/malicious-top100/data')
def malicious_top100_api_data():
    if 'username' not in session:
        return _malicious_top100_api_unauthorized()
    return jsonify(malicious_top100_data.load_cache())


@app.route('/api/malicious-top100/refresh', methods=['POST'])
def malicious_top100_api_refresh():
    if 'username' not in session:
        return _malicious_top100_api_unauthorized()
    expected = session.get('malicious_top100_csrf', '')
    supplied = request.headers.get('X-CSRF-Token', '')
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        return jsonify({'error': 'invalid request token'}), 403
    if request.content_length not in (None, 0):
        return jsonify({'error': 'request body not accepted'}), 400
    try:
        return jsonify(malicious_top100_data.refresh())
    except Exception:
        app.logger.exception('Unable to refresh malicious Top 100 feeds')
        return jsonify({'error': 'refresh failed; cached data retained'}), 502


def _malicious_top100_csv_safe(value):
    text = str(value)
    return "'" + text if text.startswith(('=', '+', '-', '@')) else text


@app.route('/api/malicious-top100/export')
def malicious_top100_api_export():
    if 'username' not in session:
        return _malicious_top100_api_unauthorized()
    kind = request.args.get('type', '')
    output_format = request.args.get('format', 'csv')
    if kind not in {'urls', 'ips', 'hashes'} or output_format not in {'csv', 'json'}:
        return jsonify({'error': 'invalid export parameters'}), 400
    items = malicious_top100_data.load_cache()['indicators'][kind]
    if output_format == 'json':
        body = json.dumps(items, indent=2)
        content_type = 'application/json; charset=utf-8'
    else:
        stream = io.StringIO(newline='')
        fields = ['rank', 'value', 'score', 'confidence', 'sources', 'first_seen', 'threat']
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for item in items:
            row = {**item, 'sources': '; '.join(item['sources'])}
            writer.writerow({key: _malicious_top100_csv_safe(row.get(key, '')) for key in fields})
        body = stream.getvalue()
        content_type = 'text/csv; charset=utf-8'
    response = app.response_class(body, content_type=content_type)
    response.headers['Content-Disposition'] = f'attachment; filename="top100-{kind}.{output_format}"'
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/team-calendar')
def team_calendar():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    month = request.args.get('month')
    try:
        calendar_month = teamcalendar.load_month(month)
        return render_template('team_calendar.html', calendar=calendar_month)
    except teamcalendar.CalendarConfigurationError as exc:
        app.logger.warning('Team Calendar is not configured: %s', exc)
        return render_template(
            'team_calendar.html',
            calendar=None,
            calendar_error=str(exc),
            source_url=teamcalendar.DEFAULT_WEB_URL,
            configuration_error=True,
        )
    except teamcalendar.CalendarFetchError as exc:
        app.logger.warning('Unable to load Team Calendar: %s', exc)
        return render_template(
            'team_calendar.html',
            calendar=None,
            calendar_error=str(exc),
            source_url=teamcalendar.DEFAULT_WEB_URL,
            configuration_error=False,
        ), 502

@app.route('/langs')
def langs():
    if 'username' in session:
        return render_template('/scripts/lang.html')
    return redirect(url_for('notloggedin'))

@app.route('/backlogbuddy')
def backlogbuddy():
    if 'username' in session:
        csvtohtml.htmloutput(settings.backlogbuddy)
        return render_template('/scripts/backlogbuddy.html')
    return redirect(url_for('notloggedin'))

@app.route('/wbrsfeeds')
def wbrsfeeds():
    if 'username' in session:
        warning = None
        try:
            expirations, warning = sicategories.load_expirations()
        except (sicategories.SICategoryConfigurationError,
                sicategories.SICategoryFetchError) as exc:
            app.logger.warning('Unable to load SI-category expirations: %s', exc)
            expirations = {}
            warning = str(exc)
        try:
            rows = sicategories.load_feed_rows(
                Path(app.static_folder) / 'wbrsfeeds.csv', expirations
            )
        except (OSError, csv.Error) as exc:
            app.logger.exception('Unable to load WBRS feed data')
            return render_template('./err/err.html', err='Unable to load WBRS feed data.'), 500
        return render_template(
            '/scripts/wbrsfeeds.html',
            feeds=rows,
            expiration_warning=warning,
            source_url=os.getenv(
                'CONFLUENCE_SI_CATEGORY_PAGE_URL',
                sicategories.DEFAULT_PAGE_URL,
            ),
        )
    return redirect(url_for('notloggedin'))

@app.route('/elasticq')
def elasticqueries():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    token = session.get('elastic_query_csrf')
    if not token:
        token = secrets.token_urlsafe(32)
        session['elastic_query_csrf'] = token
    return render_template(
        './forms/elasticqrys.html',
        csrf_token=token,
        query_specs=elastic_queries_service.public_specs(),
        selected_type='submissions',
        submitted_value='',
        error=None,
    )

@app.route('/unassigned')
def unassigned():
    if 'username' in session:
        getTickets.unassigned(session['pw'])
        return render_template('unassigned.html')
    return redirect(url_for('notloggedin'))

@app.route('/assigned')
def assigned():
    if 'username' in session:
        loader.main(session['pw'])
        return render_template('assigned.html')
    return redirect(url_for('notloggedin'))

@app.route('/acetickets')
def acetickets():
    if 'username' in session:
        return render_template('acetickets.html')
    return redirect(url_for('notloggedin'))

# jira search options
@app.route('/jirasearch')
def jirasearch():
    if 'username' in session:
        return render_template('./forms/jirasearch.html')
    return redirect(url_for('notloggedin'))

# sherlock reinjection api form
@app.route('/reinjection')
def reinjection():
    if 'username' in session:
        return render_template('./forms/reinjectionform.html')
    return redirect(url_for('notloggedin'))

# Get umbrella intelproxy submission form
@app.route('/proxysearchform')
def intelproxysearchform():
    if 'username' in session:
        return render_template('./forms/intelproxyscript.html')
    return redirect(url_for('notloggedin'))

# Get ETD cid submission form
@app.route('/etd')
def etd():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        return render_template('/forms/etdlookup.html')

# load TG/Malware analytics search form
@app.route('/tg')
def tg():
    if 'username' in session:
        return render_template('./forms/tgSearch.html')
    return redirect(url_for('notloggedin'))

# load clamav sig search form via sha256
@app.route('/clamsearch')
def clamsearch():
    if 'username' in session:
        return render_template('./forms/clamSearch.html')
    return redirect(url_for('notloggedin'))

# END WEB TEMPLATES


###SNORT3 REPLAY WEB TEMPLATES
@app.route('/pigreplay')                        # run snort 3 replay ui tool
def pigreplay():
    if 'username' in session:
        return render_template('./replay/pigreplay.html')
    return redirect(url_for('notloggedin'))

@app.route('/uploadpcap')                       #
def uploadpcap():
    if 'username' in session:
        return render_template('./replay/upload.html')
    return redirect(url_for('notloggedin'))

@app.route('/downloadpcap')                     #
def dlpcap():
    if 'username' in session:
        return render_template('./replay/download.html')
    return redirect(url_for('notloggedin'))

@app.route('/deletepcap')                       #
def delpcap():
    if 'username' in session:
        return render_template('./replay/delete.html')
    return redirect(url_for('notloggedin'))

@app.route('/rulesearch')                       #
def rulesearch():
    if 'username' in session:
        return render_template('./replay/rulesearch.html')
    return redirect(url_for('notloggedin'))

@app.route('/ruledl')                           #
def ruledl():
    if 'username' in session:
        return render_template('./replay/vrtauth.html')
    return redirect(url_for('notloggedin'))


def _prepare_cr_batch(cves):
    batch = crlookup_api.lookup_many(cves)
    successful = [item for item in batch if not item.get('error')]
    direct_matches, sid_matches = [], []
    try:
        direct_matches = rs.find_cve_signatures(cves)
        all_sids = []
        for item in successful:
            item['snort_sids'] = crlookup_api.extract_snort_sids(item.get('payload'))
            for sid in item['snort_sids']:
                if sid not in all_sids:
                    all_sids.append(sid)
        sid_matches = rs.find_signatures(all_sids)
    except (OSError, ValueError) as exc:
        for item in successful:
            item['rule_lookup_error'] = str(exc)

    for item in batch:
        item['records'] = crlookup_api.format_payload(item.get('payload')) if not item.get('error') else []
        item['research'] = crlookup_api.extract_research(item.get('payload')) if not item.get('error') else {}
        item.setdefault('snort_sids', [])
        matches, identities = [], set()
        for match in direct_matches:
            if match.get('cve') != item.get('cve'):
                continue
            identity = (match.get('source_path'), match.get('line_number'), match.get('sid'), match.get('rule'))
            if identity not in identities:
                identities.add(identity)
                matches.append(match)
        for match in sid_matches:
            if match.get('sid') not in item['snort_sids']:
                continue
            enriched = dict(match, match_source='Analysis API SID')
            identity = (enriched.get('source_path'), enriched.get('line_number'), enriched.get('sid'), enriched.get('rule'))
            if identity not in identities:
                identities.add(identity)
                matches.append(enriched)
        item['snort_signatures'] = matches
    return batch


@app.route('/crlookup')
def crlookup():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    return render_template('./replay/crlookup.html', csrf_token=_cr_csrf_token())


@app.route('/crlookup/results', methods=['POST'])
def crlookup_results():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    if not _valid_cr_csrf():
        return render_template('/err/err.html', err='The CVE lookup form expired. Refresh the page and try again.'), 400
    try:
        cves = crlookup_api.normalize_cves(request.form.get('cves', ''))
        batch = _prepare_cr_batch(cves)
    except crlookup_api.CRLookupError as exc:
        return render_template('/err/err.html', err=str(exc)), 400
    successful_count = sum(not item.get('error') for item in batch)
    return render_template(
        './replay/crlookupresults.html', batch=batch, cves=cves,
        successful_count=successful_count, failed_count=len(batch) - successful_count,
        csrf_token=_cr_csrf_token(), jira_copy_all=jirapost.format_cr_results(batch),
        cr_ticket_links=crlookup_api.ticket_link_parts,
    )


@app.route('/crlookup/results/jira', methods=['POST'])
def crlookup_results_jira():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    if not _valid_cr_csrf():
        return render_template('/err/err.html', err='The CVE results form expired. Run the lookup again.'), 400
    if request.form.get('post_to_jira') != 'yes':
        return redirect(url_for('crlookup'))
    try:
        ticket = jirapost.validate_ticket(request.form.get('ticket'))
        cves = crlookup_api.normalize_cves(request.form.get('cves', ''))
        batch = _prepare_cr_batch(cves)
        if not any(not item.get('error') for item in batch):
            return render_template('/err/err.html', err='No successful CVE results are available to post.'), 502
        issue_key = jirapost.post_cr_results(
            ticket, batch, username=settings.uname,
            password=session.get('pw') or settings.jkey,
        )
    except (crlookup_api.CRLookupError, jirapost.JiraPostError) as exc:
        return render_template('/err/err.html', err=str(exc)), 400
    return render_template(
        './replay/cr-jira-results.html', issue_key=issue_key,
        jira_url='{}/browse/{}'.format(jirapost.JIRA_SERVER, issue_key),
    )
#END SNORT WEB TEMPLATES


#<!--Login & Logout Page for scripts-->
@app.route('/login', methods = ['POST', 'GET'])
def login():
    session.clear()
    if (request.method == 'POST'):
        username = request.form.get('username')
        password = request.form.get('password')     
        session['username'] = username
        session['pw']       = password
        settings.cec        = password
        if username == settings.uname:
            loader.main(session['pw']) # run que searches
            return redirect('assigned')
        else:
            return "<h1>Wrong username or password</h1>\n" \
            "<p><a href=login>Click here to log in.</a></p>\n"
    else:
        return render_template("/auth/login.html")

# if not logged in display message, offer link to login
@app.route('/notloggedin')
def notloggedin():
    return render_template("/auth/invalid.html")

# remove the username from the session if it is there
@app.route('/logout')
def logout():
   session.pop('username', None)
   session.clear()
   return render_template("/auth/login.html")

#Creates a 3 hour timeout for the user
@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=180)
    session.modified = True
# END login log out scripts


# Ticket Queue actions
# generate csv & html page for assigned,unassigned,ace tix
@app.route('/runscript')                            # get the ticket data for user
def runscript():
    if 'username' not in session:
        return render_template('/auth/login.html')
    else:
        loader.main(session['pw'])  # run que searches main.py
        return render_template('assigned.html')

# assign tickets base on check box selection
@app.route('/takescript', methods = ['POST','GET'])
def takescript(): # assign tickets
    if 'username' not in session:
        return render_template(url_for('notloggedin'))
    else:
        if request.method == 'POST':
            selected = request.form.getlist('checks')
            print('the list of tix are {}'.format(selected))
            if selected != "":
                for i in selected:
                    assignTickets.assignque(i)
            getTickets.unassigned(session['pw'])  # get the new unassigned tickets after taking one from the list
            return redirect('unassigned') # reload the unassigned paged
        else: # fail to assign generate error
            return render_template('/err/assignerror.html')

#BULK Resolve - NOT USED MUCH
@app.route('/bulkresolve', methods = ['POST'])      #  bulk close cases
def bulkresolve():
    selected = ""  # empty
    print(request.method)
    print(request.values)
    if 'username' not in session:
        return render_template(url_for('notloggedin'))
    else:
        if request.method == 'POST':
            jsondata = request.json
            selected = request.form.getlist('resolve')
            if selected != "":
                for i in selected:
                    assignTickets.resolveclose(i)
                loader.main(session['pw'])  # run que searches
                return redirect(url_for('assignedtickets'))  # reload the unassigned paged
        else:
            return render_template('/err/err.html', err=request.method)  # this should be an error page

# ACE q searches
@app.route('/getacetix')                            # get ace tickets from test db and return results
def getacetix():
    if 'username' not in session:
        return render_template('/auth/login.html')
    else:
        try:
            aceqrys.get_ace_dispute()
        except RuntimeError as exc:
            return render_template('/err/err.html', err=str(exc)), 503
        except Exception:
            app.logger.exception("Analyst Console ticket refresh failed")
            return render_template('/err/err.html', err="Analyst Console ticket refresh failed."), 502
        #if settings.acedata is not None:
        #    return render_template('/results/acetickets.html', data =settings.acedata)
        #else:
        return render_template('/acetickets.html')
###END Tickets#########=


#Jira ticket q searches
# get tickets from talos jira instance for the user
@app.route('/assignedtickets')
def assignedtickets():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        loader.main(session['pw'])                  # run que searches
        return render_template('assigned.html')

# get all unassigned tickets from jira cog
@app.route('/unassignedtickets')
def unassignedtickets():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        getTickets.unassigned(session['pw'])
        return redirect('unassigned')

'''
# get tickets from talos jira instance for the user
@app.route('/talosjiratickets')
def talosjiratickets():
    if 'username' not in session:
        return redirect('./auth/invalid.html.html')
    else:
        settings.filedata = {"ID":[],"Link":[],"Description":[],"DateOpened":[],"LastModified":[]}
        getTickets.jira("all",True,session['pw'])
        if settings.filedata is not None:
            csvtohtml.writedata(True)
            csvtohtml.htmloutput(settings.htmlfname)
            return render_template('assigned.html')
        else:
            return render_template('./err/err.html', err="No tickets found")
'''

# get tickets from talosops jira q for the user
@app.route('/talosjiraops')
def talosjiraops():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        settings.filedata = {"ID":[],"Link":[],"Description":[],"DateOpened":[],"LastModified":[]}
        getTickets.jira("ops",True,session['pw'])
        if settings.filedata is not None:
            csvtohtml.writedata(True)
            csvtohtml.htmloutput(settings.htmlfname)
            return render_template('assigned.html')
        else:
            return render_template('./err/err.html',err="No Talos OPS tickets found")

# get tickets from eers jira q for the user
@app.route('/talosjiraeers')
def talosjiraeers():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        settings.filedata = {"ID":[],"Link":[],"Description":[],"DateOpened":[],"LastModified":[]}
        getTickets.jira("eers",True,session['pw'])
        if settings.filedata is not None:
            csvtohtml.writedata(True)
            csvtohtml.htmloutput(settings.htmlfname)
            return render_template('assigned.html')
        else:
            return render_template('./err/err.html', err="No EERS escalations found.")

# get tickets from thr jira q for the user
@app.route('/talosjirathr')
def talosjirathr():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        settings.filedata = {"ID":[],"Link":[],"Description":[],"DateOpened":[],"LastModified":[]}
        getTickets.jira("thr",True,session['pw'])
        if settings.filedata is not None:
            csvtohtml.writedata(True)
            csvtohtml.htmloutput(settings.htmlfname)
            return render_template('assigned.html')
        else:
            return render_template('./err/err.html')

# get tickets from resbz jira q for the user
@app.route('/talosjiraresbz')
def talosjiraresbz():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        settings.filedata = {"ID": [], "Link": [], "Description": [], "DateOpened": [], "LastModified": []}
        getTickets.jira("resbz", True, session['pw'])
        if settings.filedata is not None:
            csvtohtml.writedata(True)
            csvtohtml.htmloutput(settings.htmlfname)
            return render_template('assigned.html')
        else:
            return render_template('./err/err.html')
#END JIRA  Queues#


###Scripts###
#Search umbrella proxy lists for a matching entry
@app.route('/inteldbproxyscript', methods=['POST','GET'])
def inteldbproxyscript():
    if 'username' not in session:
        return render_template(url_for('notloggedin'))
    else:
        settings.inteldbmatches.clear()
        settings.inteldbmatches = {'url':[],'feed':[],'time':0}
        if request.method   == 'POST':
            print(request.values)
            res = request.values
            if request.form.get('sample') is not None:
                sample      = request.form.get('sample')
                inteldb.lookup(sample)
                timeformt   = settings.inteldbmatches['time']
                seconds     = timeformt % (24 * 3600)
                hour        = seconds // 3600
                seconds     %= 3600
                minutes     = seconds // 60
                seconds     %= 60
                tmstmp      = "%d:%02d:%02d" % (hour, minutes, seconds)
                print(tmstmp)
                return render_template('/results/intelproxy-results.html',
                                res=settings.inteldbmatches['url'],feed=settings.inteldbmatches['feed'],time=tmstmp)
            else:
                err = "Error getting Umbrella Intel Proxy results!"
                return render_template('/err/err.html',err=err)

# get rj results from cid or list of cids
@app.route('/getrj', methods = ['POST','GET'])
def getrj():
    # clear/empty rhe rjresults dict
    settings.guidconvert.clear()
    # reset dictionary values
    settings.guidconvert = {"cid": [], "date": "", "rj": [], "esascores": [],
                            'corpscores': [], 'rjscores': [],'sbrs': []}
    if 'username' not in session:
        return render_template(url_for('notloggedin'))
    else:
        if request.method == 'POST':
            #print(request.values)
            cids  = request.form.getlist('cid')
            cids  = [x.replace("\"","'") for x in cids]      # remove any quotes and replace with single quote
            cids  = [x.replace('\r\n', '","') for x in cids] # remove new line chars, replace with comma
            flag  = "rj"
            sherlock.reinjection(cids,settings.uname,settings.sherlockKey)
            return render_template('./results/rjresults.html',res=settings.guidconvert["rj"])
        else:
            # return error page as not RJ results for cid
            return render_template('/err/err.html',err="Not a valid Request POST method!")
# ETD RJ Lookup form

# ETD get api verdict and return the results
@app.route('/getetd',methods=['POST'])
def getetd():
    if 'username' not in session:
        return render_template(url_for('notloggedin'))
    else:
        if request.method == 'POST':
            settings.etdresults.clear()
            #print(request.values)
            cids  = request.form.get('cid').split('\n')
            q.etdverdicts(cids)
            joined = '\n'.join(map(str,settings.etdresults))
            return render_template('./results/etdresults.html', res=joined)
        else:
            # return error page as not RJ results for cid
            return render_template('/err/err.html',err="Not a valid Request POST method!")
# END ETD

# get malware analytics/tg sha256 results
@app.route('/gettg',methods=['POST'])
def gettg():
    if 'username' not in session:
        return render_template(url_for('notloggedin'))
    else:
        if request.method == 'POST':
            sha = (request.form.get('sha256') or '').strip()
            if not re.fullmatch(r'[A-Fa-f0-9]{64}', sha):
                return render_template('/err/err.html', err="Not a valid SHA256 hash: " + sha)

            try:
                submission_data, behavior_data = tgSearch.tgFileSearch(sha)
            except RuntimeError as exc:
                app.logger.exception("Threat Grid search failed for SHA256 %s", sha)
                return render_template('/err/err.html', err="Malware Analytics search failed: " + str(exc))
            except Exception:
                app.logger.exception("Threat Grid search failed for SHA256 %s", sha)
                return render_template('/err/err.html', err="Malware Analytics search failed."), 502

            submissions = [
                {
                    'sample_id': sample_id,
                    'score': score,
                    'filename': filename,
                    'date': date,
                }
                for sample_id, score, filename, date in itertools.zip_longest(
                    submission_data.get('sid', []),
                    submission_data.get('score', []),
                    submission_data.get('fname', []),
                    submission_data.get('date', []),
                    fillvalue='',
                )
            ]
            behaviors = [
                {'score': score, 'name': name, 'description': description}
                for score, name, description in itertools.zip_longest(
                    behavior_data.get('score', []),
                    behavior_data.get('name', []),
                    behavior_data.get('desc', []),
                    fillvalue='',
                )
            ]
            return render_template(
                './results/tgresults.html',
                sha=sha,
                submissions=submissions,
                behaviors=behaviors,
            )
        else:
            # return error page
            return render_template('/err/err.html',err="Not a valid Request POST method!")
####END SCRIPTS###

###############
# SEARCH TOOLS

# drop clam av sig
@app.route('/dropclam', methods=['POST'])
def dropclam():
    results = None
    if 'username' not in session:
        return render_template(url_for('notloggedin'))
    else:
        if request.method == 'POST':
            print(request.values)
            sig     = request.values.get('sig')
            reas    = request.values.get('reason')
            notes   = request.values.get('notes')
            results = clam.dropsig(sig,reas,notes)
            if results == None:
                err = "No Results"
                return render_template('/err/err.html', err=err)
            else:
                return render_template('/results/clamresults.html',res=results)
        else:                                                       # Return Error
            err = "Not a post request!"
            return render_template("./err/err.html", err=err)

#search for clamav sigs by sha256
@app.route('/getclam', methods = ['POST','GET'])
def getclam():
    s256    = None
    results = None
    if 'username' not in session:
        return render_template(url_for('notloggedin'))
    else:
        if request.method   == 'POST':
            #print(request.values)
            s256    = request.form.get('sha256')
            vrt     = request.form.get('vrt')
            results = clam.searchvrt(s256,vrt)
            if results == None:
                #err = (f"No Results from clam.searchvrt,{s256}")
                return render_template('/err/err.html', err=results)
            else:
                return render_template('/results/clamresults.html',res=results)
        else:                                                       # Return Error
            err = "Not a post request!"
            return render_template("./err/err.html", err=err)

# jira search qrys
@app.route('/getjira', methods = ['POST','GET'])
def getjira():
    results = None
    if 'username' not in session:
        return render_template(url_for('notloggedin'))
    else:
        if request.method   == 'POST':
            print(request.values)
            if request.form.get('cog') != '':
                cog = request.form.get('cog')
                results = jsearch.search("COG",cog)
            elif request.form.get('cve') != '':
                cve = request.form.get('cve')
                results = jsearch.search("ALL",cve)
            elif re.search(r'[A-Fa-f0-9]{64}', request.form.get('sha256')) is True:
                s256 = request.form.get('sha256')
                results = jsearch.search("ALL",s256)
            elif request.form.get('thr')  != '':
                qry = request.form.get('thr')
                results = jsearch.search("THR",qry)
            elif request.form.get('eers') != '':
                qry = request.form.get('eers')
                results = jsearch.search("EERS",qry)
            elif request.form.get('resbz') != '':
                qry = request.form.get('resbz')
                results = jsearch.search("RESBZ",qry)
            else:
                err = "Invalid search."
                return render_template('/err/err.html', err=err)
            if results == None:
                err = "No Results"
                return render_template('/err/err.html', err=err)
            else:
                return render_template('/results/jirasearchresults.html',res=results)
        else:
            err = ("Error with getting jira search web api results")
            print(err)
            return render_template('./err/err.html',err=err)

@app.route('/getelastic', methods=['POST'])
def getelastic():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    expected = session.get('elastic_query_csrf', '')
    supplied = request.form.get('csrf_token', '')
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        return render_template('./err/err.html', err='Invalid request token. Reload the search page and try again.'), 403
    if request.content_length is not None and request.content_length > 22_000:
        return render_template('./err/err.html', err='The search request is too large.'), 413
    allowed_fields = {'csrf_token', 'query_type', 'query_value'}
    if any(field not in allowed_fields for field in request.form):
        return render_template('./err/err.html', err='The search request contains unsupported fields.'), 400

    query_type = request.form.get('query_type', '')
    query_value = request.form.get('query_value', '')
    try:
        result = elastic_queries_service.search(query_type, query_value)
    except elastic_queries_service.ElasticQueryValidationError as exc:
        return render_template(
            './forms/elasticqrys.html',
            csrf_token=expected,
            query_specs=elastic_queries_service.public_specs(),
            selected_type=query_type,
            submitted_value=query_value[:20480],
            error=str(exc),
        ), 400
    except elastic_queries_service.ElasticQueryServiceError as exc:
        app.logger.warning('Elastic query failed for type %s', query_type)
        return render_template(
            './forms/elasticqrys.html',
            csrf_token=expected,
            query_specs=elastic_queries_service.public_specs(),
            selected_type=query_type,
            submitted_value=query_value[:20480],
            error=str(exc),
        ), 502
    return render_template('./results/elasticresults.html', result=result)
######################
#SNORT 3 Replay Calls
# File upload
def allowed_file(filename):                                     # only allow pcap extension upload
    return bool(filename) and '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def pcap_upload_folder():
    """Return the configured PCAP directory as an absolute path."""
    folder = Path(app.config['UPLOAD_FOLDER']).expanduser()
    return folder if folder.is_absolute() else Path(app.root_path) / folder


def available_pcaps():
    """List downloadable PCAP files without failing when the folder is missing."""
    folder = pcap_upload_folder()
    folder.mkdir(parents=True, exist_ok=True)
    return sorted(
        path.name for path in folder.iterdir()
        if path.is_file() and allowed_file(path.name)
    )


def requested_pcap(filename):
    """Validate a route filename and return its path inside the PCAP directory."""
    safe_name = secure_filename(filename)
    if safe_name != filename or not allowed_file(safe_name):
        return None
    return pcap_upload_folder() / safe_name


def analyzer_pcap(filename):
    """Return one validated, existing PCAP path for read-only analysis."""
    path = requested_pcap(filename)
    if path is None or not path.is_file():
        raise pcapanalyzer.AnalysisError("Choose an available staged PCAP file.")
    return path.resolve()


@app.route('/analyzepcap')
def analyzepcap():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    return render_template(
        '/replay/analyzepcap.html',
        files=available_pcaps(),
        csrf_token=_replay_csrf_token(),
    )


@app.route('/analyzepcap/results', methods=['POST'])
def analyzepcap_results():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    if not _valid_replay_csrf():
        return render_template('/err/err.html', err='The analyzer form expired. Refresh the page and try again.'), 400
    filename = request.form.get('pcap') or ''
    sid = (request.form.get('sid') or '').strip()
    submitted_rule = request.form.get('rule') or ''
    rule, rule_source = submitted_rule, None
    try:
        if sid:
            matches = rs.find_signatures([sid])
            if not matches:
                searched = ' or '.join(settings.rulesDirs)
                raise pcapanalyzer.AnalysisError(f'SID {sid} was not found under {searched}.')
            rule_source = matches[0]
            rule = rule_source['rule']
        elif not rule.strip():
            raise pcapanalyzer.AnalysisError('Enter a Snort SID or paste a Snort rule.')
        analysis = pcapanalyzer.analyze(analyzer_pcap(filename), rule)
    except (pcapanalyzer.AnalysisError, ValueError) as exc:
        app.logger.warning('PCAP analysis failed for %s: %s', filename, exc)
        return render_template(
            '/replay/analyzepcap.html', files=available_pcaps(),
            csrf_token=_replay_csrf_token(), analysis_error=str(exc),
            selected_pcap=filename, submitted_sid=sid,
            submitted_rule=submitted_rule,
        ), 400
    analysis['rule_source'] = rule_source
    app.logger.info(
        'Analyzed PCAP %s against SID %s: %d matches',
        filename, analysis['rule'].get('sid') or 'unspecified',
        analysis['matched_packet_count'],
    )
    return render_template('/replay/analyzepcap-results.html', analysis=analysis)

# Success function for one or more file uploads
@app.route('/upload', methods=['POST'])
def uploadfile():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))

    files = request.files.getlist('files')
    if not files:
        # Retain compatibility with older clients that submit a single `file` field.
        files = request.files.getlist('file')

    selected_files = [file for file in files if file and file.filename]
    if not selected_files:
        return render_template(
            '/replay/ack.html',
            uploaded_files=[],
            rejected_files=['No PCAP files were selected.'],
        ), 400

    upload_folder = pcap_upload_folder()
    try:
        upload_folder.mkdir(parents=True, exist_ok=True)
    except OSError:
        app.logger.exception("Unable to create PCAP upload directory")
        return render_template(
            '/replay/ack.html',
            uploaded_files=[],
            rejected_files=['The PCAP upload directory is unavailable.'],
        ), 500

    uploaded_files = []
    rejected_files = []
    for file in selected_files:
        original_name = file.filename
        safe_name = secure_filename(original_name)
        if not safe_name or not allowed_file(safe_name):
            rejected_files.append(f'{original_name}: only .pcap files are allowed.')
            continue

        try:
            file.save(upload_folder / safe_name)
        except OSError:
            app.logger.exception("Unable to save uploaded PCAP %s", safe_name)
            rejected_files.append(f'{original_name}: the file could not be saved.')
        else:
            uploaded_files.append(safe_name)

    response_status = 200 if uploaded_files else 400
    return render_template(
        '/replay/ack.html',
        uploaded_files=uploaded_files,
        rejected_files=rejected_files,
    ), response_status

# List the pcaps for download
@app.route('/filedownloads', methods=['GET'])               # list of upload files to save
def list_files():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    try:
        return render_template('/replay/download.html', files=available_pcaps())
    except OSError:
        app.logger.exception('Unable to list PCAP files for download')
        return render_template('./err/err.html', err='The PCAP directory is unavailable.'), 500

# Download the pcap and save the file
@app.route('/download/<path:filename>',methods=['GET'])     # save the file
def download(filename):
    if 'username' not in session:
        return redirect(url_for('notloggedin'))

    pcap_path = requested_pcap(filename)
    if pcap_path is None:
        return render_template('./err/err.html', err='The requested PCAP filename is invalid.'), 400
    if not pcap_path.is_file():
        app.logger.warning('PCAP download requested for missing file: %s', filename)
        return render_template('./err/err.html', err=f'PCAP file not found: {filename}'), 404

    try:
        return send_from_directory(
            pcap_upload_folder(),
            pcap_path.name,
            as_attachment=True,
            download_name=pcap_path.name,
        )
    except NotFound:
        app.logger.warning('PCAP disappeared before download: %s', filename)
        return render_template('./err/err.html', err=f'PCAP file not found: {filename}'), 404

# Select the File/pcap to  Delete
@app.route('/filedeletion', methods=['GET'])                # List the pcaps you can delete
def delfiles():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    try:
        return render_template('./replay/delete.html', files=available_pcaps())
    except OSError:
        app.logger.exception('Unable to list PCAP files for deletion')
        return render_template('./err/err.html', err='The PCAP directory is unavailable.'), 500

# Delete the selected file
@app.route('/delete/<path:filename>',methods=['GET','POST']) # Execture the deletion of a file
def delete(filename):
    if 'username' not in session:
        return redirect(url_for('notloggedin'))

    pcap_path = requested_pcap(filename)
    if pcap_path is None:
        return render_template('./err/err.html', err='The requested PCAP filename is invalid.'), 400

    try:
        pcap_path.unlink()
    except FileNotFoundError:
        app.logger.warning('PCAP deletion requested for missing file: %s', filename)
        return render_template('./err/err.html', err=f'PCAP file not found: {filename}'), 404
    except OSError:
        app.logger.exception('Unable to delete PCAP file: %s', filename)
        return render_template('./err/err.html', err=f'Unable to delete PCAP file: {filename}'), 500

    app.logger.info('Deleted PCAP file: %s', filename)
    return render_template('./replay/deleteack.html', name=filename)

# Deletes all pcaps from snort replay previously uploaded
@app.route('/delete_all_files', methods=['GET','POST'])
def delete_all_files():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    try:
        for filename in available_pcaps():
            (pcap_upload_folder() / filename).unlink()
        return render_template('./replay/deleteack.html', name="All PCAP files deleted.")
    except OSError:
        app.logger.exception('Unable to delete all PCAP files')
        return render_template('./err/err.html', err='Unable to delete all PCAP files.'), 500

# Log in with VRT creds to Download  latest snort rules
@app.route('/vrtauth', methods=['POST'])                #gets vrt creds from authform to download snort rules
def auth():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    elif (request.method == 'POST'):
        username = request.form.get('username')
        password = request.form.get('password')
        session['username'] = username
        session['pw']       = password
        settings.vrt        = password
        if username == settings.uname:
            res = ruledownload.checkrules()
            #ruledownload.gets3rules()
            if res == True:
                return render_template('./replay/ruledownload.html', name="Rule Download successful")
            elif res == False:
                return render_template("./replay/ruledownload.html", name="No rule download needed as last download was 24 hours ago.")
            else:
                return redirect('/')
        else:
            err = "Wrong username or password!"
            print(err)
            return render_template('/err/err.html', err=err)
    else:
        err = "Error not a POST requst method!"
        print(request.method)
        return render_template('./err/err.html',err=err)

# User option to Search Rules for signatures
@app.route('/rulesearchresults', methods=['POST'])        # rule search results
def rulesearchresults():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        if request.method == 'POST':
            if request.form.get('sid') is not None:
                rule = request.form.get('sid')
                rs.snortsig(rule)
                return render_template('/replay/searchresults.html', name=settings.unedited)
            else:
                err = "not a valid snort sig id"
                return render_template('/err/err.html', err=err)
        else:
            err = "Error not a POST requst method!"
            print(request.method)
            return render_template('/err/err.html',err=err)

# Select the pcap and snort rule to test
@app.route('/replay')                                   #replay form
def replay():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    return render_template(
        '/replay/replay.html',
        files=snortreplay.list_pcaps(UPLOAD_FOLDER),
        rule_locations=settings.rulesDirs,
        csrf_token=_replay_csrf_token(),
    )

# Execute pcap replay
@app.route('/testpcap',methods=['POST'])                # execute replay form inputs
def testpcap():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    if not _valid_replay_csrf():
        return render_template('/err/err.html', err='The replay form expired. Refresh the page and try again.'), 400

    sid = (request.form.get('sid') or '').strip()
    selected_pcap = request.form.get('pcaps')
    run_content_analysis = request.form.get('analyze_content') == 'yes'
    requested_policy = request.form.get('policy', 'lcl')
    policies = {
        'lcl': ('lcl', 'Local Rules Only'),
        'max': ('max', 'Max'),
        'sec': ('sec', 'Security'),
        'bal': ('bal', 'Balanced'),
        'con': ('con', 'Connectivity'),
        'all': ('all', 'All Rules'),
        'dbg': ('debug', 'No Quiet Mode'),
    }
    if requested_policy not in policies:
        return render_template('/err/err.html', err='Invalid Snort policy selected.'), 400
    if not selected_pcap:
        return render_template('/err/err.html', err='Select a PCAP file or Run all uploaded PCAPs.'), 400
    if not sid.isdigit() or int(sid) < 1:
        return render_template('/err/err.html', err='Enter a valid positive Snort signature ID.'), 400

    rs.snortsig(sid)
    local_rules = Path(settings.rulesDir) / 'local.rules'
    if not local_rules.is_file():
        return render_template('/err/err.html', err='Unable to prepare the selected Snort rule.'), 400

    command_policy, policy_label = policies[requested_policy]
    try:
        if selected_pcap == '__all__':
            pcap_files = snortreplay.list_pcaps(UPLOAD_FOLDER)
            if not pcap_files:
                return render_template('/err/err.html', err='No PCAP files are available to replay.'), 400
            pcapdata = snortreplay.replay_directory(UPLOAD_FOLDER)
            results = snortreplay.s3(command_policy, pcap_dir=UPLOAD_FOLDER)
            policy_label = f'{policy_label} — all {len(pcap_files)} PCAPs'
            analysis_files = pcap_files
        else:
            safe_name = secure_filename(selected_pcap)
            pcap_path = Path(UPLOAD_FOLDER) / safe_name
            if safe_name != selected_pcap or not allowed_file(safe_name) or not pcap_path.is_file():
                return render_template('/err/err.html', err='The selected PCAP file is invalid or unavailable.'), 400
            pcapdata = snortreplay.replay(safe_name)
            results = snortreplay.s3(command_policy, pcap=safe_name)
            analysis_files = [safe_name]
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        app.logger.exception('Snort replay failed')
        return render_template('/err/err.html', err=f'Snort replay failed: {exc}'), 500

    snortversion = snortreplay.getsnortversion()
    settings.snortversion = snortversion
    for line in snortversion.splitlines():
        line = line.strip()
        if 'Version' in line:
            settings.snortversion = line
    if results is None:
        return render_template('/err/err.html', err='No alerts or other results were returned.'), 400
    analyzer_results, content_analysis = [], []
    if run_content_analysis:
        for analysis_filename in analysis_files:
            try:
                analysis = pcapanalyzer.analyze(
                    analyzer_pcap(analysis_filename),
                    re.sub(r'^\s*#\s*', '', settings.unedited or ''),
                )
                analyzer_results.append({'filename': analysis_filename, 'analysis': analysis, 'error': None})
                content_analysis.append(f'=== {analysis_filename} ===')
                content_analysis.extend(pcapanalyzer.summary_lines(analysis))
                sections = pcapanalyzer.summary_sections(analysis, include_packet_sample=False)
                content_analysis.extend(pcapanalyzer.flatten_summary([], sections))
            except (pcapanalyzer.AnalysisError, OSError, ValueError) as exc:
                analyzer_results.append({'filename': analysis_filename, 'analysis': None, 'error': str(exc)})
                content_analysis.extend([f'=== {analysis_filename} ===', f'Analyzer unavailable: {exc}'])
    replay_result = {
        'sid': sid,
        'snort_version': settings.snortversion,
        'policy': policy_label,
        'capture_summary': pcapdata,
        'content_analysis': content_analysis,
        'runtime_alerts': results,
    }
    try:
        replay_post_token = replaypost.store_result(**replay_result)
        replay_post_error = None
    except replaypost.ReplayPostError as exc:
        app.logger.warning('Unable to stage replay results for Jira: %s', exc)
        replay_post_token = None
        replay_post_error = str(exc)
    return render_template(
        '/replay/replayResults.html',
        pol=policy_label,
        results=results,
        rule=settings.unedited,
        snortversion=settings.snortversion,
        pcapdata=pcapdata,
        analyzer_results=analyzer_results,
        replay_post_token=replay_post_token,
        replay_post_error=replay_post_error,
        replay_jira_copy=jirapost.format_replay_results(replay_result),
        csrf_token=_replay_csrf_token(),
    )


@app.route('/testpcap/results/jira', methods=['POST'])
def testpcap_results_jira():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    if not _valid_replay_csrf():
        return render_template('/err/err.html', err='The Jira form expired. Refresh the page and try again.'), 400

    token = request.form.get('replay_post_token', '')
    if request.form.get('post_to_jira') != 'yes':
        replaypost.discard_result(token)
        flash('Replay results were not posted to Jira.', 'info')
        return redirect(url_for('replay'))

    try:
        ticket = jirapost.validate_cog_ticket(request.form.get('jira_ticket'))
        replay_result = replaypost.load_result(token)
    except (jirapost.JiraPostError, replaypost.ReplayPostError) as exc:
        app.logger.warning('Replay Jira post validation failed: %s', exc)
        return render_template('/err/err.html', err=str(exc)), 400

    try:
        issue_key = jirapost.post_replay_results(
            ticket,
            replay_result,
            username=settings.uname,
            password=settings.jkey,
        )
    except jirapost.JiraPostError as exc:
        app.logger.warning('Replay Jira post failed: %s', exc)
        return render_template('/err/err.html', err=str(exc)), 502

    replaypost.discard_result(token)
    app.logger.info('Posted PCAP replay results to %s', issue_key)
    return render_template(
        '/replay/replaypost-results.html',
        ticket=issue_key,
        jira_url=jirapost.JIRA_SERVER,
    )
###END SNORT FUNCTIONS###


## Date-range COG Jira metrics
@app.route('/last7')
@app.route('/jira-metrics')
def jira_metrics():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    try:
        selected_range = jsearch.resolve_metric_date_range(
            period=request.args.get('period', '7'),
            quarter=request.args.get('quarter'),
        )
        metrics = jsearch.jira_metrics(date_range=selected_range)
    except jsearch.JiraMetricsPeriodError as exc:
        app.logger.info('Rejected Jira Metrics reporting period: %s', exc)
        return render_template('./err/err.html', err=str(exc)), 400
    except jsearch.JiraMetricsError as exc:
        app.logger.warning('Unable to load Jira Metrics: %s', exc)
        return render_template('./err/err.html', err=str(exc)), 502
    return render_template(
        './results/last7.html',
        priority_tickets=metrics['priority'],
        invalid_tickets=metrics['invalid'],
        mailer_tickets=metrics['mailer'],
        product_metrics=metrics['products'],
        high_volume_customers=metrics['customers'],
        date_range=metrics['date_range'],
        fiscal_quarters=jsearch.fiscal_quarter_options(),
        jira_browse_url='https://jira.talos.cisco.com/browse',
    )
###############################


@app.route('/ajx')
def ajx():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        return render_template('results/ajx.html')

###############
###BP SEARCH###
# amp bp lookup page
@app.route('/bpSearch')
def bpSearch():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    selected_tool = request.args.get('tool', 'signature')
    if selected_tool not in bpsearch_queries.menu_options():
        selected_tool = 'signature'
    return render_template(
        '/bpsearch/lookup.html',
        menu_options=bpsearch_queries.menu_options(),
        selected_tool=selected_tool,
        day_options=bpsearch_queries.DAY_OPTIONS,
        csrf_token=_bpsearch_csrf_token(),
    )

# get the bp api data and return the results
@app.route('/getbp',methods=['POST'])
def getbp():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    if not _valid_bpsearch_csrf():
        return render_template('/err/err.html', err='The BP Search form expired. Refresh the page and try again.'), 400
    query = (request.form.get('query') or request.form.get('bpid') or request.form.get('name') or '').strip()
    if not re.fullmatch(r'[A-Za-z0-9_.:/ -]{1,120}', query):
        return render_template('/err/err.html', err='Enter a valid BP name, SigID, MITRE tactic, CVE, or search string.'), 400
    settings.bpres.clear()
    try:
        bpsearch.bp(query)
        results = jsearch.search('THR', query)
    except (OSError, ValueError, git.GitError) as exc:
        app.logger.warning('BP signature search failed: %s', exc)
        return render_template('/err/err.html', err='The BP signature search could not be completed.'), 502
    return render_template(
        '/results/bpresults.html',
        res=results or [],
        data=settings.bpres,
        query=query,
    )


@app.route('/bpsearch/query', methods=['POST'])
def bpsearch_query():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    if not _valid_bpsearch_csrf():
        return render_template('/err/err.html', err='The BP Search form expired. Refresh the page and try again.'), 400
    option = request.form.get('option', '')
    allowed_fields = {'csrf_token', 'option', 'query', 'business_guid', 'agent_guid', 'bp_sig_id', 'sha256', 'days', 'company_name'}
    if set(request.form) - allowed_fields:
        return render_template('/err/err.html', err='The BP Search request contained unsupported fields.'), 400
    try:
        result = bpsearch_queries.search(option, request.form)
    except bpsearch_queries.BPSearchError as exc:
        return render_template(
            '/bpsearch/lookup.html',
            menu_options=bpsearch_queries.menu_options(),
            selected_tool=option if option in bpsearch_queries.menu_options() else 'signature',
            day_options=bpsearch_queries.DAY_OPTIONS,
            csrf_token=_bpsearch_csrf_token(),
            form_error=str(exc),
        ), 400
    return render_template('/bpsearch/query-results.html', result=result)

# download the latest AMP BP sigs
@app.route('/bpdownload',methods=['POST'])
def bpdownload():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    if not _valid_bpsearch_csrf():
        return render_template('/err/err.html', err='The BP download form expired. Refresh the page and try again.'), 400
    try:
        res = bpsearch.bpdownload()
    except (OSError, git.GitError) as exc:
        app.logger.warning('BP signature download failed: %s', exc)
        return render_template('/err/err.html', err='The BP signature download could not be completed.'), 502
    return render_template('/bpsearch/bpdownloadresults.html', res=res)
###END BP SEARCH###

######################
###MAIN APPLICATION###
######################
def main():
    host = os.getenv("COGWHEELHOUSE_HOST", "127.0.0.1")
    port = int(os.getenv("COGWHEELHOUSE_PORT", "8000"))
    debug = os.getenv("FLASK_DEBUG", "false").strip().lower() in {
        "1", "true", "yes", "on",
    }
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    main()
