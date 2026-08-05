# lib imports
from flask import Flask,render_template,request,redirect,session,url_for,send_from_directory,flash,jsonify
from werkzeug.utils import secure_filename
import re,json,ipaddress,os,datetime,itertools,csv
from datetime import timedelta
from flask_login import current_user
import pandas as pd

# local file imports
from liono import main as loader
from liono.common import settings
settings.init()
from liono.common import assignTickets,getTickets,q,csvtohtml,sherlock,bpsearch
from liono.common import aceqrys,jsearch,inteldb,ruledownload,snortreplay,tgSearch,clam
from liono.common import rulesearch as rs

# Flask app config
app = Flask(__name__)
app.secret_key = '3R!n7665'
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
        csvtohtml.htmloutput(settings.wbrsfeeds)
        return render_template('/scripts/wbrsfeeds.html')
    return redirect(url_for('notloggedin'))

@app.route('/elasticq')
def elasticqueries():
    if 'username' in session:
        return render_template('./forms/elasticqrys.html')
    return redirect(url_for('notloggedin'))

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
        aceqrys.get_ace_dispute()
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
            print(request.values)
            sha = request.form.get('sha256')
            if re.findall(r'\b[A-Fa-f0-9]{64}\b', sha) is not None:
                print("Match sha256")
                r1,r2 = tgSearch.tgFileSearch(sha)
                return render_template('./results/tgresults.html', r1=r1,r2=r2)
            else:
                print('Not a valid SHA256 Entry!')
                return render_template('/err/err.html', err="Not a valid hash: "+sha)
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

@app.route('/getelastic', methods = ['POST'])       # juno qrs
def getelastic():
    flag = "juno"
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        if request.method   == 'POST':
            print(request.values)
            # run the associated elastic query
            if request.form.get('username') == settings.uname:
                q.submissions(settings.uname+"@cisco.com")
                flag = "juno1" # username
            elif re.search(r'[A-Fa-f0-9]{64}', request.form.get('sha256')):
                flag = "juno2" # sha256
                q.sha256(request.form.get('sha256'))
            elif re.search(r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$', request.form.get('sender')):
                flag = "juno4" # senderemail
                q.senderemail(request.form.get('sender'))
            elif request.form.get('subj') is not None:
                flag = "juno5"
                q.subject(request.form.get('subj'))
            elif ipaddress.ip_address(request.form.get('ip')):
                flag = "juno3" # senderip
                q.senderip(request.form.get('ip'))
            elif request.form.get('domain') is not None:
                flag = "juno"
                q.fromdomain(request.form.get('domain'))
            else:
                pass
            csvtohtml.writedata(flag)
            csvtohtml.htmloutput(settings.elastichtml)
            return(render_template('./results/elasticresults.html'))
        else:
            err = ("Error: Request method NOT post!")
            print(err)
            return render_template('./err/err.html',err=err)
######################
#SNORT 3 Replay Calls
# File upload
def allowed_file(filename):                                     # only allow pcap exstention upload
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Sucess function for file upload
@app.route('/upload', methods=['POST'])                        # return if file upload is successful
def uploadfile():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        if request.method == 'POST':
            if 'file' not in request.files:                         # check if the post request has the file part
                flash('No file part')
                return redirect(url_for('upload'))
            file = request.files['file']
            if file.filename == '':                                 # If no file, browser submits an empty file without a filename.
                flash('No selected file')
                return redirect(url_for('upload'))
            if file and allowed_file(file.filename):
                f     = request.files['file']
                fname = secure_filename(f.filename)
                f.save(app.config['UPLOAD_FOLDER']+fname)
                return render_template("/replay/ack.html", name=f.filename)
        else:                                                       # Return Error
            err = "Not a post request for file upload!"
            return render_template("./err/err.html", err=err)

# List the pcaps for download
@app.route('/filedownloads', methods=['GET'])               # list of upload files to save
def list_files():
    upf = []
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        for filename in os.listdir(UPLOAD_FOLDER):
            path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(path):
                upf.append(filename)
        return render_template('/replay/download.html', files=upf)

# Download the pcap and save the file
@app.route('/download/<path:filename>',methods=['GET'])     # save the file
def download(filename):
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
        return send_from_directory(path,filename)

# Select the File/pcap to  Delete
@app.route('/filedeletion', methods=['GET'])                # List the pcaps you can delete
def delfiles():
    upf = []
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        for filename in os.listdir(UPLOAD_FOLDER):
            path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(path):
                upf.append(filename)
        return render_template('./replay/delete.html',files=upf)

# Delete the selected file
@app.route('/delete/<path:filename>',methods=['GET','POST']) # Execture the deletion of a file
def delete(filename):
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        path = os.path.join(os.getcwd(), app.config['UPLOAD_FOLDER'])
        if os.path.exists(path):
            os.remove(os.path.join(path, filename))
            return render_template('./replay/deleteack.html', name=filename)
        else:
            err = "File does not exist!"
            return render_template('./err/err.html', err=err)

# Deletes all pcaps from snort replay previously uploaded
@app.route('/delete_all_files', methods=['GET','POST'])
def delete_all_files():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        try:
            for filename in os.listdir(UPLOAD_FOLDER):
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                if os.path.isfile(file_path):
                    os.remove(file_path)
            return render_template('./replay/deleteack.html', name="All files deleted.")
        except Exception as e:
            err = f"Error deleting files: {e}"
            return render_template('./err/err.html', err=err)

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
    upf = []
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        for filename in os.listdir(UPLOAD_FOLDER):
            path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(path):
                upf.append(filename)
        return render_template('/replay/replay.html',files=upf)

# Execute pcap replay
@app.route('/testpcap',methods=['POST'])                # execute replay form inputs
def testpcap():
    sid,policy,pcap = (None,None,None)
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        if request.method == 'POST':
            #print(request.values)
            sid      = request.form.get("sid")
            pcap     = request.form['pcaps']
            policy   = request.form.get('policy')
            if sid is not None and sid != "":
                rs.snortsig(sid)
            if os.path.exists(settings.rulesDir+"local.rules"):
                # Get network info from the pcap
                pcapdata     = snortreplay.replay(pcap)
                print("Dropdown selection; ",policy)
                if policy == "max":
                    results = snortreplay.s3("max", pcap)
                elif policy == "sec":
                    results = snortreplay.s3("sec", pcap)
                elif policy == "bal":
                    results = snortreplay.s3("bal", pcap)
                elif policy == "con":
                    results = snortreplay.s3("con", pcap)
                elif policy == "all":
                    results = snortreplay.s3("all", pcap)
                elif policy == "dbg":
                    results = snortreplay.s3("debug", pcap)
                else:
                    # Replay pcap through snort with the user input signature
                    results = snortreplay.s3("lcl",pcap)
                    policy  = "Local Rules Only"
                # get snort version
                snortversion = snortreplay.getsnortversion()
                for l in snortversion.splitlines():
                    l = l.strip()
                    if "Version" in l:
                        settings.snortversion = l
                if results is not None:
                    return render_template('/replay/replayResults.html',pol=policy,results=results,rule=settings.unedited,
                                snortversion=settings.snortversion, pcapdata=pcapdata)
            else:
                err = "No Alerts or other Results"
                sid, raw, pcap = (None, None, None)
                return render_template('/err/err.html', err=err)
        else:
            err ="Not a Post request!"
            sid, raw, pcap = (None, None, None)
            return render_template('/err/err.html', err=err)
###END SNORT FUNCTIONS###


##Last 7 days jira team metrics
@app.route('/last7')
def last7():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        tix             = []
        hdrs            = ["ID","Created","Status"]
        res,op,cl,reo   = jsearch.last7()
        total           = len(res)/3
        for i in range(0,len(res),3):
            x = i
            tix.append(res[x:x+3])
        jsearch.ques()
        totaletd = settings.etd.get('fp')+ settings.etd.get('fn')+settings.etd.get('other')
        #print('ETD cases: '+ str(settings.etd.get('fp')), str(settings.etd.get('fn')), str(settings.etd.get('other')))
        settings.etd.update({'total': totaletd})
        return render_template('./results/last7.html',user=settings.uname,hdrs=hdrs,data=tix,total=total,op=op,cl=cl,reo=reo,cog=settings.ques["cog"],
            email=settings.ques["email"],amp=settings.ques["amp"],snort=settings.ques["snort"],web=settings.ques["web"],
            other=settings.ques["other"],totalesc=settings.escalations["total"],ee=settings.escalations["eers"],thr=settings.escalations["thr"],
            resbz=settings.escalations["resbz"],etd=totaletd,fp=settings.etd["fp"],fn=settings.etd["fn"],etdother=settings.etd["other"],
            sbrs=settings.ques["sbrs"],opn=settings.ques["open"],clsd=settings.ques["closed"],hot=settings.ques["hot"],
            monthly=settings.monthly, team=settings.cog)
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
    else:
        return render_template('/bpsearch/lookup.html')

# get the bp api data and return the results
@app.route('/getbp',methods=['POST'])
def getbp():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        if request.method == 'POST':
            settings.bpres.clear()
            #settings.bp.clear()
            print(request.values)
            bpid = request.form.get("bpid")
            name = request.form.get("name")
            if bpid is not None and bpid != '':
                bpsearch.bp(bpid)
                results = jsearch.search("THR", bpid)
                print(results)
                return render_template('/results/bpresults.html',res=results,data=settings.bpres)
            elif name is not None and name != '':
                bpsearch.bp(name)
                results = jsearch.search("THR", name)
                return render_template('/results/bpresults.html',res=results, data=settings.bpres)
            else:
                return render_template('/err/err.html',err="No valid BP query.",bpid=bpid,name=name)

# download the latest AMP BP sigs
@app.route('/bpdownload',methods=['POST'])
def bpdownload():
    if 'username' not in session:
        return redirect(url_for('notloggedin'))
    else:
        if request.method == 'POST':
            res = bpsearch.bpdownload()
            return render_template('/bpsearch/bpdownloadresults.html', res =res)
###END BP SEARCH###

######################
###MAIN APPLICATION###
######################
if __name__ == '__main__':
    app.run(port=8000,debug=True)
