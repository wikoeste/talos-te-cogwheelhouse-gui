from liono.common import settings
import os,re
from pathlib import Path


MAX_RULE_FILE_BYTES = 128 * 1024 * 1024
CVE_REFERENCE_PATTERN = re.compile(
    r"(?:\bCVE\s*[-_:, ]\s*|\breference\s*:\s*cve\s*,\s*)"
    r"(?P<year>\d{4})\s*[-_:]\s*(?P<number>\d{4,})(?!\d)",
    re.IGNORECASE,
)
SID_PATTERN = re.compile(r"\bsid\s*:\s*(?P<sid>\d+)\s*;", re.IGNORECASE)


def _rule_roots(directories=None):
    candidates = directories if directories is not None else getattr(
        settings, "rulesDirs", (settings.rulesDir,)
    )
    roots, seen = [], set()
    for directory in candidates:
        root = Path(directory).expanduser().resolve()
        if root not in seen:
            roots.append(root)
            seen.add(root)
    return roots


def find_cve_signatures(cves, directories=None):
    requested = []
    for cve in cves:
        value = str(cve).strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", value):
            raise ValueError("CVE values must use the format CVE-YYYY-NNNN.")
        if value not in requested:
            requested.append(value)
    requested_set, found, identities = set(requested), {cve: [] for cve in requested}, set()
    for root in _rule_roots(directories):
        if not root.is_dir():
            continue
        for rule_file in sorted(root.rglob("*.rules")):
            if rule_file.name == "local.rules" or rule_file.is_symlink():
                continue
            try:
                source_path = rule_file.resolve(strict=True)
                source_path.relative_to(root)
                if source_path.stat().st_size > MAX_RULE_FILE_BYTES:
                    continue
                with source_path.open(encoding="utf-8", errors="replace") as source:
                    for line_number, line in enumerate(source, start=1):
                        matched_cves = {
                            "CVE-{}-{}".format(match.group("year"), match.group("number")).upper()
                            for match in CVE_REFERENCE_PATTERN.finditer(line)
                        } & requested_set
                        if not matched_cves:
                            continue
                        sid_match = SID_PATTERN.search(line)
                        sid, rule = sid_match.group("sid") if sid_match else "Unknown", line.strip()
                        for cve in matched_cves:
                            identity = (cve, str(source_path), line_number, sid, rule)
                            if identity in identities:
                                continue
                            identities.add(identity)
                            found[cve].append({
                                "cve": cve, "sid": sid, "rule": rule,
                                "source_name": source_path.name, "source_path": str(source_path),
                                "line_number": line_number,
                                "enabled": not line.lstrip().startswith("#"),
                                "match_source": "CVE reference",
                            })
            except (OSError, ValueError):
                continue
    return [match for cve in requested for match in found[cve]]


def find_signatures(sids, directories=None):
    requested = []
    for sid in sids:
        value = str(sid).strip()
        if not value.isdigit() or int(value) < 1:
            raise ValueError("Snort SID must be a positive integer.")
        if value not in requested:
            requested.append(value)
    if not requested:
        return []
    matcher = re.compile(r"\bsid\s*:\s*(?P<sid>{})\s*;".format("|".join(re.escape(sid) for sid in requested)))
    found = {}
    for root in _rule_roots(directories):
        if not root.is_dir():
            continue
        for rule_file in sorted(root.rglob("*.rules")):
            if rule_file.name == "local.rules" or rule_file.is_symlink():
                continue
            try:
                with rule_file.open(encoding="utf-8", errors="replace") as source:
                    for line in source:
                        match = matcher.search(line)
                        if not match or match.group("sid") in found:
                            continue
                        source_path = rule_file.resolve()
                        found[match.group("sid")] = {
                            "sid": match.group("sid"), "rule": line.strip(),
                            "source_name": source_path.name, "source_path": str(source_path),
                        }
            except OSError:
                continue
    return [found[sid] for sid in requested if sid in found]

# open local rules and remove the keywords for local replay
def writelocal(rule):
    with open(settings.rulesDir + 'local.rules', 'r+') as fw:
        text = fw.read()
        rule = re.sub('^#', '', text)
        rule = re.sub('detection_filter.+?;', '', rule)
        rule = re.sub('flowbits.+?;', '', rule)
        rule = re.sub('flow:.+?;', '', rule)
        settings.rule = rule
        fw.seek(0)
        fw.write(rule)
        fw.truncate()
    fw.close()

# get snort rule text
def snortsig(sid):
    found = None
    sid.strip()
    rules = "local.rules"
    rule  = None
    path  = settings.rulesDir
    if sid.isdigit() is False:  # sid is raw rule text and not an integer
        with open(path + 'local.rules', 'w') as f:
            f.write(sid)
            settings.unedited = sid
            rule = sid
            f.close()
        writelocal(rule)
    elif int(sid) < 1000000:           # search for any sid < one million
        ruleid = (f"sid:{sid};")
        print(ruleid)
        for file in os.listdir(path):
            fname = os.path.join(path,file)
            if ruleid in open(fname).read():
                print("Rule found in, "+ file)              # print the rule file name
                found = fname
                for line in open(found):
                    for match in re.finditer(ruleid, line):
                        with open (path+'local.rules', 'w') as f:
                            f.write(line)
                            settings.unedited = line        # write the rule to return
                            rule              = line
                            f.close()
                writelocal(rule)                            # write a local copy of the rule to test with as a backup
    else:                                                   # Error in finding the rule
        settings.unedited   = rule
        settings.rule       = rule
        print(sid + ":Not Found in Snort Rules")
    print(rule)                                             #print what rule we found for debugging
