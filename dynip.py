#!/usr/bin/env python3
import requests
import yaml
import json
import sys
import os
import smtplib
import ssl
import dateutil.parser

from datetime import datetime
from datetime import timedelta
from os.path import exists


def last_email_older_than(minutes):
  # Just an arbitrary datetime in the past as a fallback for missing value.
  last_notified=datetime(2022, 1, 1, 0, 0, 0, 0)
  lastmail_str = state['last_fatal_mail_sent']
  if lastmail_str is not None and len(lastmail_str) > 0:
    last_notified = dateutil.parser.isoparse(lastmail_str)
  X_mins_ago = datetime.now() - timedelta(minutes=minutes)
  return last_notified < X_mins_ago


def log(str):
  print(datetime.now().isoformat() + ' ' + str)


def send_mail(subject, body):
  ctx = ssl.create_default_context()
  host = config['mail_host']
  port = config['mail_port']
  from_addr = config['from_email']
  to_addr = config['to_email']
  with smtplib.SMTP_SSL(host, port, context=ctx) as server:
    # My mail server requires from/to headers included both here
    # and in the sendmail() method below
    msg = """\
From: {0}
To: {1}
Subject: {2}

{3}""".format(from_addr, to_addr, subject, body)
    server.login(config['mail_user'], config['mail_pass'])
    server.sendmail(from_addr, to_addr, msg)


def abort_on_failure(label, resp):
  if resp.status_code != 200:
    log('FATAL HTTP ERROR...')
    log('Non-200 status code from ' + label + ' api.')
    log('url: ' + resp.url)
    log('status_code: ' + str(resp.status_code))
    log('elapsed: ' + str(resp.elapsed))
    log('resp body: ' + resp.text)
    if config['send_emails'] and last_email_older_than(120):
      subj = config['domain_being_updated'] + ' Dynamic DNS Fatal API Call For ' + label + ' API'
      body = """
FATAL HTTP ERROR
Non-200 status code from {0} api
url: {1}
status_code: {2}
elapsed: {3}
resp body: {4}
""".format(label, resp.url, str(resp.status_code), str(resp.elapsed), resp.text)
      send_mail(subj, body)
      state['last_fatal_mail_sent'] = datetime.now().isoformat()
      with open(STATE_PATH, mode='wt', encoding='utf-8') as file:
        yaml.dump(state, file)
    sys.exit(0)


BLANK_STATE={'wan_ip': '127.0.0.1', 'last_updated':datetime.now().isoformat(), 'last_fatal_mail_sent': '2022-01-01T00:00:00.000000'}
SCRIPT_PATH=os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH=os.path.join(SCRIPT_PATH, 'config.yaml')
STATE_PATH=os.path.join(SCRIPT_PATH, 'state.yaml')

if not exists(CONFIG_PATH):
  log('Could not find {0}'.format(CONFIG_PATH))
  sys.exit(1)

config=yaml.safe_load(open(CONFIG_PATH))

if not exists(STATE_PATH):
  state=BLANK_STATE
else:
  state=yaml.safe_load(open(STATE_PATH))
  if state is None or not state:
    state=BLANK_STATE

old_wan_ip=(state['wan_ip'])

ip_api_resp=requests.get('https://ip4.seeip.org/')
abort_on_failure('seeip', ip_api_resp)

wan_ip=ip_api_resp.text

if wan_ip == old_wan_ip:
  sys.exit(0)

state['wan_ip']=wan_ip
state['last_updated']=datetime.now().isoformat()

record_api_fmt='{api_origin}/v4/domains/{domain_name}/records/{domain_id}'
record_api_url=record_api_fmt.format(
      api_origin='https://' + config['api_host'],
      domain_name=config['domain_name'],
      domain_id=str(config['domain_id'])
    )
auth_params=(config['username'], config['token'])
get_resp=requests.get(record_api_url, auth=auth_params)
abort_on_failure('GETRECORD', get_resp)

existing_record=get_resp.json()
existing_record['answer']=wan_ip
# name.com enforces 5 minutes as the minimum.
# Assert that minimum, since this is for a dynamic IP.
existing_record['ttl']=300
put_resp=requests.put(
        record_api_url,
        auth=auth_params,
        headers={'Content-Type': 'application/json'},
        data=json.dumps(existing_record)
    )
abort_on_failure('UPDATERECORD', put_resp)

log('Updated IP to ' + wan_ip)
if config['send_emails']:
  subj = config['domain_being_updated'] + ' IP Address has changed'
  body = 'Old IP: {0}\nNew IP: {1}'.format(old_wan_ip, wan_ip)
  send_mail(subj, body)

with open(STATE_PATH, mode='wt', encoding='utf-8') as file:
  yaml.dump(state, file)
