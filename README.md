# Dynamic IP Updater for name.com DNS

Minimal script for checking a machine's external IP and updating its DNS when
the IP address changes using the name.com APIs.

## Features

- Simple yaml driven config
- Uses name.com's publicly documented APIs for managing DNS
- Avoids making excessive calls to name.com's APIs by storing the last known
  public IP and only trying to make updates if there are changes.
- Low-noise default logging (for info level & above)
- Optionally sends email updates when an IP changes
- Optionally sends email updates when an error happens
- Avoids repeat error emails if the script rapidly fails during repeated runs.

## Dependencies & Usage

Requires `python` and `pip` to be installed on the machine running the script.

Usage:

1. Clone this repo
1. From within the repository's root folder, setup a python venv to install
   dependencies with the following commands:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install .
   ```
1. Copy `config.example.yaml` as `config.yaml` into the same directory the
   script is located and configure your settings.
1. Run the script. Set it as a chron job or Systemd timer to update as often as
   you'd like. Systemd unit files are included in this repository and require
   setting the DYNDNS_WORKING_DIR [environment variable so the systemd service
   can reference it](https://serverfault.com/a/413408/10973).
