# HackerOne CLI Utility

## Index

1. [Description](#description)
2. [Usage](#usage)  
    2.1. [Windows](#windows)  
    2.2. [Unix](#unix)
3. [Installation](#installation)  
    3.1. [Requirements](#requirements)  
    3.2. [Windows](#windows-1)  
    3.3. [Unix](#unix-1)  
    3.4. [Tests](#tests)  
4. [Modules](#modules)  
    4.1. [balance](#balance)  
    4.2. [burp](#burp)  
    4.3. [csv](#csv)  
    4.4. [earnings](#earnings)  
    4.5. [help](#help)  
    4.6. [payouts](#payouts)  
    4.7. [profile](#profile)  
    4.8. [program](#program)  
    4.9. [programs](#programs)  
    4.10. [report](#report)  
    4.11. [reports](#reports)  
    4.12. [scope](#scope)  
5. [License](#license)

## Description

This is an (unofficial) utility that works as a client to the HackerOne platform. It allows you to perform multiple operations directly from the command-line.  
The tool uses the official [HackerOne API](https://api.hackerone.com/) to access the data it needs.  
It contains several modules so you manage and view information related to your profile, reports, programs, payments, etc and it's really easy to use.

## Usage

### Windows

After installing, just run `python3 hackerone.py` to use the utility.

### Unix

After installing, you can call `hackerone` directly from the command-line (since a symbolic link will be created during installation) or use python (`python3 hackerone.py`).

## Installation

### Requirements

- Python >= 3.10
- Git
- HackerOne API Key (you can get it from [here](https://hackerone.com/settings/api_token/edit))

### Windows

1. Open Powershell in the same directory as the project
2. Run the installation file:

    ```ps1
    .\install.ps1
    ```

3. Export the required environment variables (don't forget to replace the values between double quotes):

    ```ps1
    echo 'HACKERONE_USERNAME="<username>"' > .env
    echo 'HACKERONE_API_KEY="<api-key>"' >> .env
    ```

    or

    ```ps1
    $env:HACKERONE_USERNAME = "<username>"
    $env:HACKERONE_API_KEY = "<api-key>"
    ```

### Unix

1. Open a shell in the same directory as the project
2. Run the installation file:

    ```sh
    chmod +x install.sh
    ./install.sh
    ```

3. Export the required environment variables (don't forget to replace the values between double quotes):

    ```sh
    echo 'HACKERONE_USERNAME="<username>"' > .env
    echo 'HACKERONE_API_KEY="<api-key>"' >> .env
    ```

    or

    ```sh
    export HACKERONE_USERNAME="<username>"
    export HACKERONE_API_KEY="<api-key>"
    ```

4. Optionally, you can set the environment variables permanently (if you're not using the first option, in the previous process):

    (using ZSH shell)

    ```sh
    echo 'export HACKERONE_USERNAME="<username>"' >> .zshrc
    echo 'export HACKERONE_API_KEY="<api-key>"' >> .zshrc
    ```

    (using Bash shell)

    ```sh
    echo 'export HACKERONE_USERNAME="<username>"' >> .bashrc
    echo 'export HACKERONE_API_KEY="<api-key>"' >> .bashrc
    ```

### Tests

This tool was tested (and performed well) on:

- Kali Linux 2023.2 + Python 3.11.4
- Windows 11 (Powershell 7.3.5) + Python 3.11.4
- Android (with Termux) + Python 3.11.4

## Modules

```txt
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
scope <handle> [<outfile>]      Save a program's scope into a text file (optional: <outfile> = output file to store results)
```

### balance

Check your money balance. The value provided is in the currency provided on your profile.

```txt
hackerone balance

Balance: 1337.0
```

### burp

Downloads the burp configuration file from public programs. This is <u>not</u> done through the HackerOne API, since there's no such feature, that's why it only works with public programs.  
You need to pass the program's handle to use this module. You can find the program handle using the module `programs` or by checking the URL in the browser, while using the HackerOne platform (example: `https://hackerone.com/<handle>/policy_scopes` in any program)

```txt
hackerone burp security

Filename: security-(...).json
```

### csv

Downloads the CSV scope file from public programs. This is <u>not</u> done through the HackerOne API, since there's no such feature, that's why it only works with public programs.  
You need to pass the program's handle to use this module. You can find the program handle using the module `programs` or by checking the URL in the browser, while using the HackerOne platform (example: `https://hackerone.com/<handle>/policy_scopes` in any program)

```txt
hackerone csv security

Filename: scopes_for_security_(...).csv
```

### earnings

Check your earnings from the programs you have been.

```txt
hackerone earnings

Earnings
----------------------------------------
Amount: 1337
Date: 2016-02-02T04:05:06.000Z
Program: HackerOne
Report: RXSS at example.hackerone.com
----------------------------------------
```

### help

Shows the help page, listing the modules available, their descriptions, and the parameters to be passed.

### payouts

Lists all the payouts you had.

```txt
hackerone payouts

Payouts
----------------------------------------
Amount: 1337
Status: sent
Date: 2016-02-02T04:05:06.000Z
Provider: Paypal
----------------------------------------
```

### profile

Gets your profile information. It only works if you have any reports, since this module actually checks for the 'reporter' from a report you submitted (there is no user searching / profile feature in the - hacker - API). Unfortunatly it is not possible to get the Signal, Impact or Rank data.

```txt
hackerone profile

Profile
----------------------------------------
ID: 1234567
Username: example
Reputation: 1337
Name: Hacker Man
Creation Date: 2020-11-24T16:20:24.066Z
Bio: My beautiful bio
Website: https://example.com/
Location: Right here
----------------------------------------
```

### program

Allows you to get information from a program (public or private - if you have authorization) such as the program handle, name, state, creation date, privacy, scope, bounty splitting, bookmarked status and bounty.

```txt
hackerone program security

Program
----------------------------------------
Name: HackerOne
Handle: security
State: open
Availability: Public
Creation date: 2013-11-06T00:00:00.000Z
Bounty: yes
Bounty Splitting: yes
Bookmarked: no

Scope
--------------------
Asset: hackerone.com
Type: URL
State: In-Scope
Bounty: yes
Instruction: This is our main application that hackers and customers use to interact with each other. It connects with a database that contains information about vulnerability reports, users, and programs. This system’s backend is written in Ruby and exposes data to the client through GraphQL, rendered pages, and JSON endpoints.
Max Severity: critical
--------------------
```

### programs

Gets a list of the most recently updated programs (including the private programs you are in) and some extra information from each. You can pass an extra argument that filters the number of results. The default value is `10`.

```txt
hackerone programs 2

Programs
----------------------------------------
Program: Example 1
Handle: example_1
State: open
Availability: Public
Available since: 2027-07-10T17:10:05.936Z
Bounty Splitting: no
Bookmarked: yes
----------------------------------------
Program: Example 2
Handle: example_2
State: open
Availability: Public
Available since: 2027-05-16T16:00:37.600Z
Bounty Splitting: yes
Bookmarked: no
----------------------------------------

Got 2 results!
```

### report

Get most of the information available from a report, including the severity, asset, title, comments, content (only if the report is yours), CVE, CWE, bounties (normal bounty + extra bounty), participants, weakness, etc.  
You need to pass the report ID which you can find by using the module `reports` (to get the IDs from your reports) or in a report in the HackerOne website (`https://hackerone.com/reports/<ID>`).

```txt
hackerone report 1234567

Report
----------------------------------------
ID: 1234567
Title: Stored XSS on example.com
State: resolved
Date: 2027-06-01T00:54:43.308Z
Program: example
Severity: medium
CWE: CWE-79
Weakness: Cross-site Scripting (XSS) - Stored

Comments
--------------------
@triager

Hi!
Thanks for the report, @hacker. We're looking into it.

--------------------
@triager

This should now be fixed. Marking as resolved.

--------------------
@example awarded a bounty (1337.00 + 0.00)!

--------------------
@hacker

Hi @triager
Can we disclosure full ?
Thanks

--------------------
@triager agreed on the report going public!

--------------------
@triager changed the report visibility to public!

----------------------------------------
```

### reports

Get a list of your reports with some information about each one, including the title, ID, state, creation date, CWE, CVSS, weakness, program and severity.

```txt
hackerone reports

Reports
----------------------------------------
ID: 1234567
Title: Information Exposure through phpinfo() at example.com
State: triaged
Date: 2027-03-13T16:48:17.286Z
CWE: CWE-200
Program: example
Severity: low
CVSS: 3.7
----------------------------------------
ID: 1234568
Title: RXSS on https://example.com/ via id parameter
State: duplicate
Date: 2027-01-06T12:23:36.605Z
CWE: CWE-79
Program: example
Severity: high
CVSS: 8.3
----------------------------------------
```

### scope

Save a list of in-scope domains, URLs, IP addresses, CIDR addresses, and wildcards in a text file (to use on external tools). This module extracts this info from the csv file available for each program. You need to download it (using the HackerOne website or the `csv` module) and pass the filename as an argument to this module.  
Optionally, you can pass the name of the output file as a second argument (default: `inscope.txt`).

```txt
hackerone scope scopes_for_example.csv out.txt

In-Scope
----------------------------------------
*.example.com
127.0.0.0/24
test.example.com
----------------------------------------
File 'out.txt' saved!
```

## License

License is available [here](./LICENSE).
