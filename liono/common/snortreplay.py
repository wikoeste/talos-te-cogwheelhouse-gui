from liono.common import settings
import asyncio
import os
from pathlib import Path
import re
import subprocess
import time

import pyshark

def getsnortversion():
    version_check = subprocess.run(
        ['snort', '-V'],
        check=True,
        capture_output=True,
        text=True,
    )
    return (version_check.stdout or version_check.stderr).strip()

def list_pcaps(pcap_dir=None):
    """Return sorted PCAP filenames from the configured replay directory."""
    directory = Path(pcap_dir or settings.pcapDir)
    if not directory.is_dir():
        return []
    return sorted(
        path.name for path in directory.iterdir()
        if path.is_file() and path.suffix.lower() == '.pcap'
    )


def build_snort_command(rules, pcap=None, pcap_dir=None):
    """Build a Snort 3 command for one PCAP or an entire PCAP directory."""
    if bool(pcap) == bool(pcap_dir):
        raise ValueError("Choose exactly one PCAP file or one PCAP directory")

    lua = Path(settings.projDir) / 'pigreplay/snortfiles/lua/snort.lua'
    rules_dir = Path(settings.rulesDir)
    command = ['snort']
    if rules != 'debug':
        command.append('-q')
    command.extend(['-c', str(lua)])

    if pcap_dir:
        command.extend([
            '--pcap-dir', str(Path(pcap_dir)),
            '--pcap-filter', '*.[pP][cC][aA][pP]',
        ])
    else:
        command.extend(['-r', str(Path(settings.pcapDir) / pcap)])

    if rules == 'lcl':
        command.extend(['-R', str(rules_dir / 'local.rules')])
    else:
        tweaks = {
            'max': 'max_detect',
            'sec': 'security',
            'bal': 'balanced',
            'con': 'connectivity',
            'debug': 'security',
        }
        if rules not in {*tweaks, 'all'}:
            raise ValueError(f'Unsupported Snort policy: {rules}')
        command.extend(['--rule-path', str(rules_dir)])
        if rules in tweaks:
            command.extend(['--tweaks', tweaks[rules]])

    command.extend(['-A', 'alert_talos'])
    return command


def s3(rules, pcap=None, pcap_dir=None):
    command = build_snort_command(rules, pcap=pcap, pcap_dir=pcap_dir)
    snortrun = subprocess.run(command, check=True, capture_output=True)

    # write snort output to snort.log
    with open(settings.projDir+"pigreplay/snort.log", "w") as f:
        f.write(str(snortrun))
    f.close()
    res = readsnortlogs()
    return res

#Reads the snort alert log and prints the results or no results for the user
def readsnortlogs():
    results     = []                                               # snort++/3
    if os.path.isfile(settings.projDir+'pigreplay/snort.log'):
        # append the snort run log results
        with open(settings.projDir+'pigreplay/snort.log') as f:
            flines = f.readlines()
            f.close()
        list2str = ''.join(map(str, flines))
        newstr   = re.sub(r'.*snort.lua:','',list2str)
        teststr  = newstr.replace(r'\n', '\n')
        teststr  = re.sub(r'--------------------------------------------------','',teststr)
        teststr  = teststr.replace(r'\t','')
        teststr  = teststr.replace("', stderr=b'')",'\n')
        newlst   = teststr.split('\n')
        #del newlst[-1]
        #del newlst[-1]
        results.append("====SNORT3 RUNTIME LOG DATA====")
        for i in newlst:
            results.append(i)
        results.extend(["===Replay Edited Rule===",settings.rule])
    # remove the current snort.log & local.rules file for next replay
    try:
        os.remove(settings.projDir+'pigreplay/snort.log')
    except OSError:
        pass
    try:
        os.remove(settings.rulesDir+'local.rules')
    except:
        pass
    # print to cli for debugging
    #for r in results:
    #    print(r)
    return results                                              # return the snort.log data and alerts if any

#replay a packet wiht pyshark to get ip and protocol data
def replay(pcap):
    lcltime, proto, sip, dip, sport, dport = (None,None,None,None,None,None)
    data   = []
    event_loop = asyncio.new_event_loop()
    capture = pyshark.FileCapture(
        str(Path(settings.pcapDir) / pcap),
        eventloop=event_loop,
    )
    try:
        for pkt in capture:
            lcltime = time.asctime(time.localtime(time.time()))
            proto   = "Protocol: {}".format(pkt.transport_layer)
            sip     = "Source IP: {}".format(pkt.ip.src)
            dip     = "Dest IP: {}".format(pkt.ip.dst)
            if "tcp" in pkt:
                sport = "Source Port: {}".format(pkt.tcp.srcport)
                dport = "Dest Port: {}".format(pkt.tcp.dstport)
            else:
                sport = "Source Port: {}".format(pkt.udp.srcport)
                dport = "Dest Port: {}".format(pkt.udp.dstport)
        data.extend((lcltime,proto,sip,dip,sport,dport))
        return data
    finally:
        try:
            capture.close()
        finally:
            event_loop.close()


def replay_directory(pcap_dir=None):
    """Summarize the PCAP directory selected for a Snort directory replay."""
    directory = Path(pcap_dir or settings.pcapDir)
    pcaps = list_pcaps(directory)
    return [
        f"PCAP Directory: {directory}",
        f"PCAP Files: {len(pcaps)}",
        *pcaps,
    ]
