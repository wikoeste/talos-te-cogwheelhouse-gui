from liono.common import settings
import mysql.connector

def htmltable(data):
    homelink = ''
    #print(data)
    fileout = open(settings.acehtml, "w")
    table = "<table>\n"
    # add css
    css = "<!DOCTYPE html>\n" \
          "<html lang='en'>\n" \
          "<head>\n" \
          "<meta charset='utf-8'>\n" \
          "<meta name='viewport' content='width=device-width, initial-scale=1'>\n" \
          "<meta name='theme-color' content='#1f1f21'>\n" \
          "<title>Analyst Console Tickets | Talos TE Toolbox</title>\n" \
          "<link rel='stylesheet' href = '{{ url_for('static', filename='css/main.css') }}'>\n" \
          "</head>\n" \
          "<body>\n" \
          "{% include \"partials/navigation.html\" %}\n" \
          "<h1 class='logo'>Analyst Console Assigned Tickets</h1>\n"
    table = css
    ticket_count = sum("<a " in item for item in data)
    table += "<details class='ticket-list' open>\n" \
             "<summary><span>Analyst Console tickets</span>" \
             "<span class='ticket-list-hint'>" + str(ticket_count) + " ticket links</span></summary>\n" \
             "<div class='ticket-list-content'>\n" \
             "<table>\n"

    # Add links for menu
    table += homelink
    # Create the table's column headers
    header = ['ACE-Links']
    table += "  <tr>\n"
    for column in header:
        table += "    <th>{0}</th>\n".format(column.strip())
    # Create the table's row data
    for line in data:
        row = line.split(",")
        table += " <tr>\n"
        for column in row:
            if "Unassigned" in column:
                table += "    <td>"+column+"</td>\n"
                #table += "    <td>{0}</td>\n".format(column.strip())
            elif "Tickets" in column:
                table += "    <td>{0}</td>\n".format(column.strip())
            else:
                table += "    <td>{0}</td>\n".format(column.strip())
                #pass
        table += "  </tr>\n"
    table += "</table>\n</div>\n</details>\n"
    table += "<br><br>"
    # add footer to webpage
    footer = "<div class=footer>\n" \
             "<p>Copyright (c) 2022 wikoeste, Cisco Internal Use Only</p>\n" \
             "</div>\n"
    table += footer
    table += "</body>\n</html>"
    fileout.writelines(table)
    fileout.close()

def get_ace_dispute():
    cecuser    = settings.uname
    uid        = ''
    data,links = ([],[])
    connection = mysql.connector.connect(host=settings.acedbhost,database=settings.acedatabase,user='ace_ro',password='WU3icQds+U9LXnQsJ')
    if connection.is_connected():
        db_Info = connection.get_server_info()
        print("Connected to MySQL Server version ", db_Info)
        cursor = connection.cursor()
        cursor.execute("select database();")
        record = cursor.fetchone()
        print("You're connected to database: ", record)
        # Get userid from username
        useridqry   = "select id from users where cec_username = %(cec_username)s"
        cursor.execute(useridqry, {'cec_username':cecuser})
        users       = cursor.fetchall()
        for row in users:
            uid = row[0]
        #////////////////
        # Get table details
        #cursor.execute("desc snort_escalations")
        #results = cursor.fetchall()
        #for r in results:
        #    print(r)
        # Get assigned web disputes to the user by user id
        caseids     = "select id from disputes where user_id= %(user_id)s and status='assigned'"
        cursor.execute(caseids,{'user_id':uid})
        records     = cursor.fetchall()
        data.append("Web Tickets:{}".format(len(records)))
        for row in records:
            cid = row[0]
            data.append("<a href=https://analyst-console.vrt.sourcefire.com/escalations/webrep/disputes/"+str(cid)+" target=_blank>"+str(cid)+"</a>")
        #webtixqry   = ("SELECT case_opened_at,updated_at FROM disputes where user_id = %(user_id)s and status='ASSIGNED'")
        #cursor.execute(webtixqry, {'user_id':uid})
        print("Total assigned Web Rep tickets ", len(records))
        print("================")
        #/////////////////////////////
        #Get AMP assigned tickets files_reputation_disputes
        filetixqry  = ("SELECT id FROM file_reputation_disputes where user_id = %(user_id)s and status='ASSIGNED'")
        cursor.execute(filetixqry, {'user_id':uid})
        records = cursor.fetchall()
        data.append("File Tickets:{}".format(len(records)))
        print("Total assigned File Rep tickets ", len(records))
        for row in records:
            fid = row[0]
            data.append("<a href=https://analyst-console.vrt.sourcefire.com/escalations/file_rep/disputes/"+str(fid)+" target=_blank>"+str(fid)+"</a>")
        print("================")
        # ///////////////////
        # Get SDR assigned tickets sender_domain_reputation_disputes
        sdrtixqry = ("SELECT id FROM sender_domain_reputation_disputes where user_id = %(user_id)s and status='ASSIGNED'")
        cursor.execute(sdrtixqry, {'user_id':uid})
        records = cursor.fetchall()
        print("Total assigned SDR Rep tickets ", len(records))
        data.append("SDR Tickets:{}".format(len(records)))
        for row in records:
            sdrid = row[0]
            data.append("<a href=https://analyst-console.vrt.sourcefire.com/escalations/sdr/disputes/"+str(sdrid)+" target=_blank>"+str(sdrid)+"</a>")
        print("================")
        #/////////////////////
        # Get Snort assigned tickets snort_escalations
        snortixqry = ("SELECT id FROM snort_escalations where (researcher_id = %(user_id)s or assignee_id = %(user_id)s) and status='ASSIGNED' or status='CUSTOMER_PENDING'")
        cursor.execute(snortixqry, {'user_id': uid})
        records = cursor.fetchall()
        print(records)
        print("Total assigned Snort Rep tickets ", len(records))
        data.append("Snort Tickets:{}".format(len(records)))
        for row in records:
            snortid = row[0]
            data.append("<a href=https://analyst-console.vrt.sourcefire.com/snort_escalations/" + str(
                snortid) + " target=_blank>" + str(snortid) + "</a>")
        print("================")
        # /////////////////////
        # Get ALL reopened tickets,wbrs,sdr,file,snort; and display
        webreopened  = ("SELECT id FROM disputes where user_id = %(user_id)s and status='RE-OPENED'")
        filereopened = ("SELECT id FROM file_reputation_disputes where user_id = %(user_id)s and status='RE-OPENED'")
        sdrreopened  = ("SELECT id FROM sender_domain_reputation_disputes where user_id = %(user_id)s and status='RE-OPENED'")
        snrtreopened = ("SELECT id FROM snort_escalations where (researcher_id = %(user_id)s or assignee_id = %(user_id)s) and status='RE-OPENED'")
        #Execute the mysql statements
        cursor.execute(webreopened, {'user_id':uid})
        webrecords   = cursor.fetchall()
        cursor.execute(filereopened, {'user_id':uid})
        filerecords  = cursor.fetchall()
        cursor.execute(sdrreopened, {'user_id':uid})
        sdrrecords  = cursor.fetchall()
        cursor.execute(snrtreopened, {'user_id': uid})
        snrtrecords = cursor.fetchall()
        reopened  = len(webrecords) + len(filerecords) + len(sdrrecords) + len(snrtrecords)
        print("Re-Opened Tickets {}".format(reopened))
        print("================")
        data.append("Re-Opened Tickets:{}".format(reopened))
        for row in webrecords:
            webid = row[0]
            data.append("<a href=https://analyst-console.vrt.sourcefire.com/escalations/webrep/disputes/" + str(
                webid) + " target=_blank>" + str(webid) + "</a>")
        for row in filerecords:
            fid = row[0]
            data.append("<a href=https://analyst-console.vrt.sourcefire.com/escalations/file_rep/disputes/" + str(
                fid) + " target=_blank>" + str(fid) + "</a>")
        for row in sdrrecords:
            sdrid = row[0]
            data.append("<a href=https://analyst-console.vrt.sourcefire.com/escalations/sdr/disputes/" + str(
                sdrid) + " target=_blank>" + str(sdrid) + "</a>")
        for row in snrtrecords:
            snrtid = row[0]
            data.append("<a href=https://analyst-console.vrt.sourcefire.com/snort_escalations/" + str(
                snrtid) + " target=_blank>" + str(snrtid) + "</a>")
        #htmltable(data)

        # ///////////////////
        # Get ALL unassigned tickets, wbrs,sdr,file; and display
        webunassigned   = ("SELECT id FROM disputes where status='NEW'")
        fileunassigned  = ("SELECT id,status,resolution FROM file_reputation_disputes where status like 'NEW'")
        sdrunassigned   = ("SELECT id,status FROM sender_domain_reputation_disputes where status like 'NEW'")
        snortunassigned = ("SELECT id,status FROM snort_escalations where status='NEW'")
        cursor.execute(webunassigned)
        webrecords      = cursor.fetchall()
        cursor.execute(fileunassigned)
        filerecords     = cursor.fetchall()
        if len(filerecords) == 1:# and '3026953' in filerecords:
            filerecords = []
        cursor.execute(sdrunassigned)
        sdrrecords      = cursor.fetchall()
        if len(sdrrecords) == 3:# and '3026563' in sdrrecords:
            sdrrecords = []
        cursor.execute(snortunassigned)
        snrtrecords     = cursor.fetchall()
        unassigned = len(webrecords)+len(filerecords)+len(sdrrecords)+len(snrtrecords)
        print("Unassigned Web:   {}".format(len(webrecords)))
        print("Unassigned File:  {}".format(len(filerecords)))
        print("Unassigned SDR:   {}".format(len(sdrrecords)))
        print("Unassigned Snort: {}".format(len(snrtrecords)))
        print("Total Unassigned: {}".format(unassigned))
        print("========================================")
        data.append("ALL Unassigned ACE tickets:{}".format(unassigned))
        data.append("Snort Unassigned:{}".format(len(snrtrecords)))
        for row in snrtrecords:
            sid = row[0]
            data.append("<a href=https://analyst-console.vrt.sourcefire.com/snort_escalations/"+str(sid)+" target=_blank>"+str(sid)+"</a>")
        data.append("File Unassigned:{}".format(len(filerecords)))
        for row in filerecords:
            fid = row[0]
            data.append("<a href=https://analyst-console.vrt.sourcefire.com/escalations/file_rep/disputes/"+str(fid)+" target=_blank>"+str(fid)+"</a>")
        data.append("SDR Unassigned:{}".format(len(sdrrecords)))
        for row in sdrrecords:
            sdrid = row[0]
            data.append("<a href=https://analyst-console.vrt.sourcefire.com/escalations/sdr/disputes/"+str(sdrid)+" target=_blank>"+str(sdrid)+"</a>")
        data.append("Web Unassigned:{}".format(len(webrecords)))
        for row in webrecords:
            webid = row[0]
            data.append("<a href=https://analyst-console.vrt.sourcefire.com/escalations/webrep/disputes/"+str(webid)+" target=_blank>"+str(webid)+"</a>")
        # Close the DB connection
        cursor.close()
        connection.close()
        htmltable(data)
        #settings.acedata.append(data)
