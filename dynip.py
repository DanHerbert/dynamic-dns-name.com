#!/usr/bin/env python3
"""Update DNS records for dynamic IP."""

import json
import logging
import os
import smtplib
import ssl
import sys
import time

from datetime import datetime
from datetime import timedelta
from os.path import exists

import dateutil.parser
import yaml
import requests



BLANK_STATE = {
    'wan_ip': '127.0.0.1',
    'last_ip_change': datetime.now().isoformat(),
    'last_successful_run': datetime.now().isoformat(),
    'last_failed_run': '1970-01-01T00:00:00.000000',
    'last_fatal_mail_sent': '1970-01-01T00:00:00.000000'
}
SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_PATH, 'config.yaml')
STATE_PATH = os.path.join(SCRIPT_PATH, 'state.yaml')


def get_config():
    """Gets the config object from disk."""
    with open(CONFIG_PATH, mode='rt', encoding='utf-8') as file_handle:
        return yaml.safe_load(file_handle)


def get_state():
    """Gets the state object from disk."""
    if not exists(STATE_PATH):
        state = BLANK_STATE
    else:
        with open(STATE_PATH, encoding='utf-8') as file_handle:
            state = yaml.safe_load(file_handle)
        if state is None or not state:
            state = BLANK_STATE
    return state


def write_state(state):
    """Writes state object to disk."""
    with open(STATE_PATH, mode='wt', encoding='utf-8') as state_file:
        yaml.dump(state, state_file)


def last_email_older_than(minutes):
    """Check the state yaml to see if the last email sent happened longer than.

    <minutes> ago from now.
    """
    # Just an arbitrary datetime in the past as a fallback for missing value.
    state = get_state()
    last_notified = datetime(2022, 1, 1, 0, 0, 0, 0)
    lastmail_str = state['last_fatal_mail_sent']
    if lastmail_str is not None and len(lastmail_str) > 0:
        last_notified = dateutil.parser.isoparse(lastmail_str)
    x_mins_ago = datetime.now() - timedelta(minutes=minutes)
    return last_notified < x_mins_ago

logger = logging.getLogger(__name__)


def send_mail(subject, body):
    """Send an email using settings from config.yaml."""
    config = get_config()
    ctx = ssl.create_default_context()
    host = config['mail_host']
    port = config['mail_port']
    from_addr = config['from_email']
    to_addr = config['to_email']
    with smtplib.SMTP_SSL(host, port, context=ctx) as server:
        # My mail server requires from/to headers included both here
        # and in the sendmail() method below
        msg = f"""\
From: {from_addr}
To: {to_addr}
Subject: {subject}

{body}"""
        server.login(config['mail_user'], config['mail_pass'])
        server.sendmail(from_addr, to_addr, msg)


def abort_on_failure(label, resp):
    """Abort this script completely if the response is non 200 status."""
    config = get_config()
    state = get_state()
    if resp.status_code != 200:
        logger.info('FATAL HTTP ERROR...')
        logger.info('Non-200 status code from %s api.', label)
        logger.info('url: %s', resp.url)
        logger.info('status_code: %s', resp.status_code)
        logger.info('elapsed: %s', resp.elapsed)
        logger.info('resp body: %s', resp.text)
        if config['send_emails'] and last_email_older_than(120):
            mail_subj = (config['domain_being_updated'] +
                         ' Dynamic DNS Fatal API Call For ' + label + ' API')
            mail_body = f"""
FATAL HTTP ERROR
Non-200 status code from {label} api
url: {resp.url}
status_code: {str(resp.status_code)}
elapsed: {str(resp.elapsed)}
resp body: {resp.text}
"""
            send_mail(mail_subj, mail_body)
            state['last_fatal_mail_sent'] = datetime.now().isoformat()
            write_state(state)

        if config['send_emails'] and not last_email_older_than(120):
            logger.info('Last email sent less than 2 hours ago. Intentionally not sending another')
        fail_exit()


def timeout_abort(label, url):
    """Abort this script and log it as a timeout error."""
    config = get_config()
    state = get_state()
    reqs_timeout = config['requests_timeout_seconds']
    logger.info('FATAL TIMEOUT ERROR...')
    logger.info('Timeout from %s api.', label)
    logger.info('url: %s', url)
    logger.info('timeout seconds: %s', reqs_timeout)
    logger.info('retries: %s', config['getreq_retry_limit'])
    if config['send_emails'] and last_email_older_than(120):
        subj = config['domain_being_updated'] + \
            ' Dynamic DNS Fatal API Call For ' + label + ' API'
        body = f"""
FATAL TIMEOUT ERROR
Timeout from {label} api
url: {url}
timeout_seconds: {reqs_timeout}
retries: {config['getreq_retry_limit']}
"""
        send_mail(subj, body)
        state['last_fatal_mail_sent'] = datetime.now().isoformat()
        write_state(state)

    if config['send_emails'] and not last_email_older_than(120):
        logger.info('Last email sent less than 2 hours ago. Intentionally not sending another')
    fail_exit()


def get_with_retry(url, label, api_auth=None):
    """Gets the specified URL and retries if there's a timeout."""
    config = get_config()
    reqs_timeout = config['requests_timeout_seconds']
    retry_limit = config['getreq_retry_limit']
    tries = 0
    while True:
        try:
            resp = requests.get(url, auth=api_auth, timeout=reqs_timeout)
            break
        except requests.exceptions.ReadTimeout:
            tries += 1
            if tries < retry_limit:
                time.sleep(reqs_timeout)
                continue
            timeout_abort(label, url)
        except requests.exceptions.ConnectionError:
            tries += 1
            if tries < retry_limit:
                time.sleep(reqs_timeout)
                continue
            timeout_abort(label, url)

    abort_on_failure(label, resp)
    return resp


def get_wan_ip():
    """Gets the current wan IP."""
    config = get_config()
    wan_ip = get_with_retry(config['wanip_endpoint'],
                            'wan_ip_endpoint').text
    return wan_ip


def success_exit():
    """Updates state yaml and exits with OK exit code."""
    state = get_state()
    state['last_successful_run'] = datetime.now().isoformat()
    write_state(state)
    sys.exit(0)


def fail_exit():
    """Updates state yaml and exits with error exit code."""
    state = get_state()
    state['last_failed_run'] = datetime.now().isoformat()
    write_state(state)
    sys.exit(1)


def main():
    """Main app execution code."""

    if not exists(CONFIG_PATH):
        logger.info('Could not find %s', CONFIG_PATH)
        fail_exit()

    with open(CONFIG_PATH, encoding='utf-8') as file_handle:
        config = yaml.safe_load(file_handle)

    logging.basicConfig(
        format=config['log_format'],
        datefmt=config['log_datefmt'],
        level=logging.getLevelName(get_config()['log_level'])
    )

    startup_state = get_state()

    old_wan_ip = startup_state['wan_ip']
    reqs_timeout = config['requests_timeout_seconds']

    wan_ip = get_wan_ip()
    if wan_ip == old_wan_ip:
        success_exit()

    record_api_url = (f"https://{config['api_host']}/v4/domains/"
                      f"{config['domain_name']}/records/"
                      f"{str(config['domain_id'])}")
    auth_params = (config['username'], config['token'])
    get_resp = get_with_retry(record_api_url,
                              'record_list_api',
                              api_auth=auth_params)

    existing_record = get_resp.json()
    existing_record['answer'] = wan_ip
    # name.com enforces 5 minutes as the minimum.
    # Assert that minimum, since this is for a dynamic IP.
    existing_record['ttl'] = 300
    try:
        put_resp = requests.put(
            record_api_url,
            auth=auth_params,
            headers={'Content-Type': 'application/json'},
            data=json.dumps(existing_record),
            timeout=reqs_timeout
        )
    except requests.exceptions.ReadTimeout:
        timeout_abort('UPDATERECORD', record_api_url)
    except requests.exceptions.ConnectionError:
        timeout_abort('UPDATERECORD', record_api_url)
    abort_on_failure('UPDATERECORD', put_resp)

    new_state = get_state()
    new_state['wan_ip'] = wan_ip
    new_state['last_ip_change'] = datetime.now().isoformat()
    write_state(new_state)

    logger.info('Updated IP to %s', wan_ip)
    if config['send_emails']:
        updated_ip_subj = config['domain_being_updated'] + \
            ' IP Address has changed'
        updated_ip_body = f'Old IP: {old_wan_ip}\nNew IP: {wan_ip}'
        send_mail(updated_ip_subj, updated_ip_body)

    success_exit()


if __name__ == '__main__':
    main()
