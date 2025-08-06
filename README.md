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
   creating symlinks for the `dynip.service` and `dynip.timer` files, along with
   overriding a few environment variables for `dynip.service` to work on your
   system. It is recommended to run this service/timer as a user service, since
   it requires no system-level access. The commands to set it up as a user
   service are below.

   ```bash
   mkdir -p "$XDG_CONFIG_DIR/systemd/user/dynip.service.d"
   ln -s "$PWD/dynip.timer" "$XDG_CONFIG_DIR/systemd/user/dynip.timer"
   ln -s "$PWD/dynip.service" "$XDG_CONFIG_DIR/systemd/user/dynip.service"
   # Rename dynip.service.environment.example.conf to dynip.service.environment.conf
   # and edit the values inside the file before running the following line.
   ln -s "$PWD/dynip.service.environment.conf" "$XDG_CONFIG_DIR/systemd/user/dynip.service.d/environment.conf"
   systemctl --user enable --now dynip.timer
   # You will need to run the following command if not already configured.
   sudo loginctl enable-linger $USER
   ```

   If setting it up as a system service, replace all occurrences of
   `$XDG_CONFIG_DIR/systemd/user` with `$(systemd-path systemd-system-conf)`.

   ```bash
   mkdir -p "$(systemd-path systemd-system-conf)/dynip.service.d"
   ln -s "$PWD/dynip.timer" "$(systemd-path systemd-system-conf)/dynip.timer"
   ln -s "$PWD/dynip.service" "$(systemd-path systemd-system-conf)/dynip.service"
   # Rename dynip.service.environment.example.conf to dynip.service.environment.conf
   # and edit the values inside the file before running the following line.
   ln -s "$PWD/dynip.service.environment.conf" "$(systemd-path systemd-system-conf)/dynip.service.d/environment.conf"
   sudo systemctl enable --now dynip.timer
   ```
