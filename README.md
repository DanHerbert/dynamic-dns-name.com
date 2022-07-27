# Dynamic IP Updater for name.com DNS

Minimal script for checking a machine's external IP and updating its DNS when the IP address changes using the name.com APIs.

## Features

*  Simple yaml driven config
*  Uses name.com's publicly documented APIs for managing DNS
*  Avoids making excessive calls to name.com's APIs by storing the last known public IP and only trying to make updates if there are changes.
*  Low-noise stdout logging
*  Optionally sends email updates when an IP changes
*  Optionally sends email updates when an error happens
*  Avoids repeat error emails if the script rapidly fails during repeated runs.


## Dependencies & Usage

Requires `python3` and `pip3` to be installed on the machine running the script.

Make sure the script's dependencies are installed with the following command:
```bash
pip3 install python-dateutil pyyaml requests
```

Usage:

1.  Copy `config.example.yaml` as `config.yaml` into the same directory the script is in.
1.  Run the script. Set it as a chron job  to update as often as you'd like.
