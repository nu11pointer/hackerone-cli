#!/usr/bin/env python3

import requests
import os
import sys
import json
import mdv
import re
import csv as csvmod
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

__version__ = "1.0.0"

load_dotenv()
USERNAME = os.getenv("HACKERONE_USERNAME")
TOKEN = os.getenv("HACKERONE_API_KEY")
auth = HTTPBasicAuth(USERNAME, TOKEN)

def help():
    print("""Modules:
    balance                         Check your balance
    burp <handle>                   Download the burp configuration file (only from public programs)
    csv <handle>                    Download CSV scope file (only from public programs)
    earnings                        Check your earnings
    help                            Help page
    payouts                         Get a list of your payouts
    profile                         Your profile on HackerOne
    program <handle>                Get information from a program
    programs [<max>]                Get a list of current programs (optional: <max> = maximum number of results)
    report <id>                     Get a specific report
    reports                         Get a list of your reports
    scope <csv> [<outfile>]         Extract in-scope domains/URLs/wildcards/IPs/CIDRs from a csv scope file and save it to a text file""")

def burp():
    if (len(sys.argv) != 3):
        print("Invalid arguments provided!")
        return
    
    handler = sys.argv[2]

    r = requests.get(f"https://hackerone.com/teams/{handler}/assets/download_burp_project_file.json")
    if (r.status_code != 200 and r.status_code != 404):
        print(f"Request returned {r.status_code}!")
        sys.exit()
    if (not r.headers["Content-Disposition"].startswith("attachment")):
        print(f"Could not find program '{handler}'!")
        return
    
    print("Filename: " + r.headers["Content-Disposition"].split("\"")[1])
    with open(r.headers["Content-Disposition"].split("\"")[1], "wb") as fp:
        fp.write(r.content)

def csv():
    if (len(sys.argv) != 3):
        print("Invalid arguments provided!")
        return
    
    handler = sys.argv[2]

    r = requests.get(f"https://hackerone.com/teams/{handler}/assets/download_csv.csv")
    if (r.status_code != 200 and r.status_code != 404):
        print(f"Request returned {r.status_code}!")
        sys.exit()
    if (not r.headers["Content-Disposition"].startswith("attachment")):
        print(f"Could not find program '{handler}'!")
        return
    
    print("Filename: " + r.headers["Content-Disposition"].split("\"")[1])
    with open(r.headers["Content-Disposition"].split("\"")[1], "wb") as fp:
        fp.write(r.content)

def reports():
    r = requests.get("https://api.hackerone.com/v1/hackers/me/reports", auth=auth)
    if (r.status_code != 200):
        print(f"Request returned {r.status_code}!")
        sys.exit()
    data = json.loads(r.text)

    if (len(data["data"]) == 0):
        print("You have no reports.")
        return

    print("Reports")
    print("----------------------------------------")
    for rep in data["data"]:
        print("ID: " + rep["id"])
        print("Title: " + rep["attributes"]["title"])
        print("State: " + rep["attributes"]["state"])
        print("Date: " + rep["attributes"]["created_at"])
        print("Program: " + rep["relationships"]["program"]["data"]["attributes"]["handle"])
        try:
            print("Severity: " + rep["relationships"]["severity"]["data"]["attributes"]["rating"])
        except:
            print("Severity: none")
        if ("cve_ids" in rep["attributes"] and rep["attributes"]["cve_ids"] not in [None, "", []]):
            print("CVE: " + ", ".join(rep["attributes"]["cve_ids"]))
        try:
            print("CWE: " + str.upper(rep["relationships"]["weakness"]["data"]["attributes"]["external_id"]))
            print("Weakness: " + rep["relationships"]["weakness"]["data"]["attributes"]["name"])
        except:
            print("CWE: none")
            print("Weakness: none")
        try:
            print("CVSS: " + str(rep["relationships"]["severity"]["data"]["attributes"]["score"]))
        except:
            pass
        print("----------------------------------------")

def report():
    if (len(sys.argv) != 3):
        print("Invalid arguments provided!")
        return
    
    if (not sys.argv[2].isdigit()):
        print(f"Invalid ID provided '{sys.argv[2]}'!")
        return

    id = sys.argv[2]

    r = requests.get(f"https://api.hackerone.com/v1/hackers/reports/{id}", auth=auth)
    if (r.status_code != 200 and r.status_code != 404):
        print(f"Request returned {r.status_code}!")
        sys.exit()
    data = json.loads(r.text)

    if (r.status_code == 404):
        print("Report not found!")
        return

    if (len(data["data"]) == 0):
        print("You have no reports.")
        return

    rep = data["data"]

    print("Report")
    print("----------------------------------------")
    print("ID: " + rep["id"])
    print("Title: " + rep["attributes"]["title"])
    print("State: " + rep["attributes"]["state"])
    print("Date: " + rep["attributes"]["created_at"])
    print("Program: " + rep["relationships"]["program"]["data"]["attributes"]["handle"])
    try:
        print("Severity: " + rep["relationships"]["severity"]["data"]["attributes"]["rating"])
    except:
        print("Severity: none")
    if ("cve_ids" in rep["attributes"] and rep["attributes"]["cve_ids"] not in [None, "", []]):
        print("CVE: " + ", ".join(rep["attributes"]["cve_ids"]))
    try:
        print("CWE: " + str.upper(rep["relationships"]["weakness"]["data"]["attributes"]["external_id"]))
        print("Weakness: " + rep["relationships"]["weakness"]["data"]["attributes"]["name"])
    except:
        print("CWE: none")
        print("Weakness: none")
    
    try:
        print("Asset: " + rep["relationships"]["structured_scope"]["data"]["attributes"]["asset_identifier"])
        print("Asset Type: " + rep["relationships"]["structured_scope"]["data"]["attributes"]["asset_type"])
    except:
        pass
    try:
        print("CVSS: " + str(rep["relationships"]["severity"]["data"]["attributes"]["score"]))
    except:
        pass

    if ("vulnerability_information" in rep["attributes"]):
        print("\nContent")
        print("--------------------")
        mdv.term_columns = os.get_terminal_size()[0]
        print(mdv.main(rep["attributes"]["vulnerability_information"]))


    print("\nComments")
    for comment in rep["relationships"]["activities"]["data"]:
        print("--------------------")
        if ("username" in comment["relationships"]["actor"]["data"]["attributes"]):
            entity = comment["relationships"]["actor"]["data"]["attributes"]["username"]
        elif ("handle" in comment["relationships"]["actor"]["data"]["attributes"]):
            entity = comment["relationships"]["actor"]["data"]["attributes"]["handle"]
        else:
            entity = "someone"
        try:
            match comment["type"]:
                case "activity-report-severity-updated":
                    print("\x1B[3m@" + entity + "\x1B[23m updated the severity of the report!")
                case "activity-bug-pending-program-review":
                    print("\x1B[3m@" + entity + "\x1B[23m" + ("\n\n" + comment["attributes"]["message"] if "message" in comment["attributes"] and comment["attributes"]["message"] not in [None, ""] else " changed the report status to 'Pending for review'!"))
                case "activity-comment":
                    print("\x1B[3m@" + entity + "\x1B[23m" + ("\n\n" + comment["attributes"]["message"] if "message" in comment["attributes"] and comment["attributes"]["message"] not in [None, ""] else " posted a comment! (Not visible)"))
                case "activity-bug-triaged":
                    print("\x1B[3m@" + entity + "\x1B[23m" + ("\n\n" + comment["attributes"]["message"] if "message" in comment["attributes"] and comment["attributes"]["message"] not in [None, ""] else " changed the report status to 'Triaged'!"))
                case "activity-bug-resolved":
                    print("\x1B[3m@" + entity + "\x1B[23m" + ("\n\n" + comment["attributes"]["message"] if "message" in comment["attributes"] and comment["attributes"]["message"] not in [None, ""] else " changed the report status to 'Resolved'!"))
                case "activity-bug-duplicate":
                    print("\x1B[3m@" + entity + "\x1B[23m" + ("\n\n" + comment["attributes"]["message"] if "message" in comment["attributes"] and comment["attributes"]["message"] not in [None, ""] else " changed the report status to 'Duplicate'!"))
                case "activity-bounty-awarded":
                    print("\x1B[3m@" + rep["relationships"]["program"]["data"]["attributes"]["handle"] + "\x1B[23m" + f" awarded a bounty ({comment['attributes']['bounty_amount']} + {comment['attributes']['bonus_amount']})!" + ("\n\n" + comment["attributes"]["message"] if "message" in comment["attributes"] and comment["attributes"]["message"] not in [None, ""] else ""))
                case "activity-bug-retesting":
                    print("\x1B[3m@" + entity + "\x1B[23m changed the status of the report to 'Retesting'!")
                case "activity-hacker-requested-mediation":
                    print("\x1B[3m@" + entity + "\x1B[23m has requested mediation from HackerOne Support!")
                case "activity-user-completed-retest":
                    print("\x1B[3m@" + entity + "\x1B[23m" + ("\n\n" + comment["attributes"]["message"] if "message" in comment["attributes"] and comment["attributes"]["message"] not in [None, ""] else " completed retesting!"))
                case "activity-report-retest-approved":
                    print("\x1B[3m@" + entity + "\x1B[23m approved the retesting!")
                case "activity-report-collaborator-invited":
                    print("\x1B[3m@" + entity + "\x1B[23m invited a collaborator!")
                case "activity-report-collaborator-joined":
                    print("\x1B[3m@" + entity + "\x1B[23m joined as a collaborator!")
                case "activity-agreed-on-going-public":
                    print("\x1B[3m@" + entity + "\x1B[23m" + ("\n\n" + comment["attributes"]["message"] if "message" in comment["attributes"] and comment["attributes"]["message"] not in [None, ""] else " agreed on the report going public!"))
                case "activity-report-became-public":
                    print("\x1B[3m@" + entity + "\x1B[23m changed the report visibility to public!")
                case "activity-cancelled-disclosure-request":
                    print("\x1B[3m@" + entity + "\x1B[23m" + ("\n\n" + comment["attributes"]["message"] if "message" in comment["attributes"] and comment["attributes"]["message"] not in [None, ""] else " requested to cancel disclosure!"))
                case "activity-report-title-updated":
                    print("\x1B[3m@" + entity + "\x1B[23m changed the report title!")
                case "activity-bug-needs-more-info":
                    print("\x1B[3m@" + entity + "\x1B[23m changed the report status to 'Needs more info'!")
                case "activity-bug-new":
                    print("\x1B[3m@" + entity + "\x1B[23m changed the report status to 'New'!")
                case "activity-cve-id-added":
                    print("\x1B[3m@" + entity + "\x1B[23m added a CVE id!")
                case "activity-external-user-joined":
                    print("\x1B[3m@" + entity + "\x1B[23m joined this report as a participant!")
                case "activity-manually-disclosed":
                    print("\x1B[3m@" + entity + "\x1B[23m disclosed this report!")
                case "activity-report-vulnerability-types-updated":
                    print("\x1B[3m@" + entity + "\x1B[23m updated the vulnerability type/weakness!")
                case _:
                    raise Exception()
        except:
            print(comment)
            print("\x1B[3m@" + entity + "\x1B[23m participated on the report! (Could not get more details)")
        print()
    print("----------------------------------------")

def balance():
    r = requests.get("https://api.hackerone.com/v1/hackers/payments/balance", auth=auth)
    if (r.status_code != 200):
        print(f"Request returned {r.status_code}!")
        sys.exit()
    data = json.loads(r.text)
    print("Balance: " + str(data["data"]["balance"]))

def earnings():
    r = requests.get("https://api.hackerone.com/v1/hackers/payments/earnings", auth=auth)
    if (r.status_code != 200):
        print(f"Request returned {r.status_code}!")
        sys.exit()
    data = json.loads(r.text)

    if (len(data["data"]) == 0):
        print("You have no earnings.")
        return

    print("Earnings")
    print("----------------------------------------")
    for earn in data["data"]:
        print("Amount: " + earn["relationships"]["bounty"]["data"]["attributes"]["amount"] + " " + earn["relationships"]["bounty"]["data"]["attributes"]["awarded_currency"])
        print("Date: " + earn["attributes"]["created_at"])
        print("Program: " + earn["relationships"]["program"]["data"]["attributes"]["name"])
        print("Report: " + earn["relationships"]["bounty"]["data"]["relationships"]["report"]["data"]["attributes"]["title"])
        print("----------------------------------------")

def payouts():
    r = requests.get("https://api.hackerone.com/v1/hackers/payments/payouts", auth=auth)
    if (r.status_code != 200):
        print(f"Request returned {r.status_code}!")
        sys.exit()
    data = json.loads(r.text)

    if (len(data["data"]) == 0):
        print("You have no payouts.")
        return

    print("Payouts")
    print("----------------------------------------")
    for payout in data["data"]:
        print("Amount: " + str(payout["amount"]))
        print("Status: " + payout["status"])
        print("Date: " + payout["paid_out_at"])
        print("Provider: " + payout["payout_provider"])

def programs():
    max = 10
    if (len(sys.argv) == 3):
        if (sys.argv[2].isdigit() and int(sys.argv[2]) > 0):
            max = sys.argv[2]
        else:
            print(f"Invalid maximum value '{sys.argv[2]}'!")
            return
        
    max = int(max)
    c = 0

    programs = []

    while True:
        r = requests.get(f"https://api.hackerone.com/v1/hackers/programs?page[size]=100&page[number]={c}", auth=auth)
        if (r.status_code != 200 and r.status_code != 404):
            print(f"Request returned {r.status_code}!")
            sys.exit()
        data = json.loads(r.text)

        if (r.status_code == 404):
            break
    
        if (len(data["data"]) == 0):
            break

        for program in data["data"]:
            programs.append(program)
        
        c += 1
    
    programs = programs[::-1]
    count = 0

    print("Programs")

    for program in programs:
        if (count == max):
            break
        print("----------------------------------------")
        print("Program: " + program["attributes"]["name"])
        print("Handle: " + program["attributes"]["handle"])
        print("State: " + program["attributes"]["submission_state"])
        print("Availability: " + ("Public" if program["attributes"]["state"] == "public_mode" else "Private"))
        print("Available since: " + program["attributes"]["started_accepting_at"])
        print("Bounty Splitting: " + ("yes" if program["attributes"]["allows_bounty_splitting"] else "no"))
        print("Bookmarked: " + ("yes" if program["attributes"]["bookmarked"] else "no"))
        count += 1
    
    print("----------------------------------------\n")
    print(f"Got {count} results!")

def profile():
    r = requests.get("https://api.hackerone.com/v1/hackers/me/reports", auth=auth)
    if (r.status_code != 200):
        print(f"Request returned {r.status_code}!")
        sys.exit()
    data = json.loads(r.text)

    if (len(data["data"]) == 0):
        print("Could not check your profile!")
        return

    user = data["data"][0]["relationships"]["reporter"]["data"]

    print("Profile")
    print("----------------------------------------")
    print("ID: " + user["id"])
    print("Username: " + user["attributes"]["username"])
    print("Reputation: " + str(user["attributes"]["reputation"]))
    print("Name: " + user["attributes"]["name"])
    print("Creation Date: " + user["attributes"]["created_at"])
    print("Bio: " + (user["attributes"]["bio"] if "bio" in user["attributes"] and user["attributes"]["bio"] not in [None, ""] else ""))
    print("Website: " + (user["attributes"]["website"] if "website" in user["attributes"] and user["attributes"]["website"] not in [None, ""] else ""))
    print("Location: " + (user["attributes"]["location"] if "location" in user["attributes"] and user["attributes"]["location"] not in [None, ""] else ""))
    print("----------------------------------------")

def program():
    if (len(sys.argv) < 3):
        print("No handle provided!")
        return
    handle = sys.argv[2]

    r = requests.get(f"https://api.hackerone.com/v1/hackers/programs/{handle}", auth=auth)
    if (r.status_code != 200):
        print(f"Request returned {r.status_code}!")
        sys.exit()
    data = json.loads(r.text)

    print("Program")
    print("----------------------------------------")
    print("Name: " + data["attributes"]["name"])
    print("Handle: " + data["attributes"]["handle"])
    print("State: " + data["attributes"]["submission_state"])
    print("Availability: " + ("Public" if data["attributes"]["state"] == "public_mode" else "Private"))
    print("Creation date: " + data["attributes"]["started_accepting_at"])
    print("Bounty: " + ("yes" if data["attributes"]["offers_bounties"] else "no"))
    print("Bounty Splitting: " + ("yes" if data["attributes"]["allows_bounty_splitting"] else "no"))
    print("Bookmarked: " + ("yes" if data["attributes"]["bookmarked"] else "no"))
    
    print("\nScope")
    for scope in data["relationships"]["structured_scopes"]["data"]:
        print("--------------------")
        print("Asset: " + scope["attributes"]["asset_identifier"])
        print("Type: " + scope["attributes"]["asset_type"])
        print("State: " + ("In-Scope" if scope["attributes"]["eligible_for_submission"] else "Out-of-Scope"))
        if ("eligible_for_bounty" in scope["attributes"] and scope["attributes"]["eligible_for_bounty"]):
            print("Bounty: " + ("yes" if scope["attributes"]["eligible_for_bounty"] else "no"))
        if (scope["attributes"]["instruction"]):
            print("Instruction: " + scope["attributes"]["instruction"])
        print("Max Severity: " + scope["attributes"]["max_severity"] if scope["attributes"]["max_severity"] is not None else "None")
    print("----------------------------------------")

def scope():
    if (len(sys.argv) not in [3,4]):
        print(sys.argv)
        print("Invalid arguments provided!")
        return
    
    handle = sys.argv[2]
    outfile = sys.argv[3] if len(sys.argv) == 4 else "inscope.txt"
    inscope = []
    try:
        with open(sys.argv[2], "r") as fp:
            reader = csvmod.reader(fp)
            try:
                next(reader)
            except:
                raise Exception()
            print("In-Scope")
            print("----------------------------------------")
            for row in reader:
                if (not row[4] or row[1] not in ["URL", "DOMAIN", "OTHER", "WILDCARD", "CIDR"]):
                    continue
                if (re.match(r"^(\*\.)?([a-zA-Z0-9\*]([a-zA-Z0-9\-\*]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,256}$", row[0]) or re.match(r"^(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}(\/[0-3]?[0-9])?$", row[0])):
                    inscope.append(row[0] + "\n")
                    print(row[0])
            print("----------------------------------------")
    except:
        print(f"Failed to read file '{sys.argv[2]}'!")
        return
    
    try:
        with open(f"{outfile}", "a") as fp:
            fp.writelines(sorted(inscope))
            print(f"File '{outfile}' saved!")
    except:
        print(f"Failed to write to file '{outfile}'!")
        return

def main():
    print()
    if USERNAME is None:
        print("Environment variable HACKERONE_USERNAME is not set!")
        sys.exit()
    if TOKEN is None:
        print("Environment variable HACKERONE_API_KEY is not set!")
        sys.exit()
    
    if (len(sys.argv) < 2):
        print("No argument provided!\n")
        print(f"Usage: {__file__} help")
        sys.exit()
    
    match sys.argv[1]:
        case "csv":
            csv()
        case "help":
            help()
        case "reports":
            reports()
        case "report":
            report()
        case "balance":
            balance()
        case "earnings":
            earnings()
        case "payouts":
            payouts()
        case "profile":
            profile()
        case "programs":
            programs()
        case "program":
            program()
        case "burp":
            burp()
        case "scope":
            scope()
        case _:
            print(f"Invalid module '{sys.argv[1]}'")
            sys.exit()
    
if __name__ == "__main__":
    main()