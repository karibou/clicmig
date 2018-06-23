#!/usr/bin/python3

import os
import requests
import hashlib
import getpass
import argparse


api = {
        'prod': {
            'baseurl': 'https://www.clicrdv.com/api/v1',
            'apikey': '',
            },
        }


def _date_before(date_1, date_2):
    return True


def consume_paginate(session, uri):
    """ Consume pagination and yield every items """
    response = session.request("GET", uri)
    response.raise_for_status()
    rec_total = response.json().get('totalRecords')
    index = 0
    while index < rec_total:
        for item in response.json()['records']:
            yield item
            index += 1

        if '?' in uri:
            response = session.request("GET", uri+'&startIndex=%d' % index)
        else:
            response = session.request("GET", uri+'?startIndex=%d' % index)
        response.raise_for_status()


def get_clicrdv_creds():
    '''
    Get username/password pair and API key either from env variable
    or from the keyboard
    '''
    username = os.environ.get('user')
    pwd = os.environ.get('pwd')
    apikey = os.environ.get('apikey')
    if not username:
        username = input('Username: ')
    if not pwd:
        pwd = getpass.getpass('Password: ')
    hashpwd = hashlib.sha1(pwd.encode('utf-8')).hexdigest()
    if not apikey:
        apikey = input('API Key: ')
    return {'user': username, 'pwd': hashpwd, 'apikey': apikey}


class clicrdv():
    def __init__(self, inst):
        self.ses = None
        self.service = None
        self.tz = 'Europe/Paris'
        self.inst = inst
        self.create_new_agenda_entries = False
        self.clic_agenda = []
        self.google_agenda = {}
        self.stats = {
                'found_clic_agenda_entries': 0,
                }

    def clic_session_open(self, clic_auth):
        '''
        Open session to clicrdv API
        '''
        payload = {
                'apikey': clic_auth['apikey'],
                'pro[email]': clic_auth['user'],
                'pro[password]': clic_auth['pwd'],
                }
        self.ses = requests.session()
        resp = self.ses.post(api[self.inst]['baseurl'] +
                             '/sessions/login.json?apikey=' +
                             api[self.inst]['apikey'], data=payload)
        if resp.status_code != 200:
            print('Unable to establish session %d : %s - %s' %
                  (resp.status_code, resp.reason, resp.text))
            self.ses = None
            self.group_id = None
            return
        self.group_id = str(resp.json()['pro']['group_id'])
        return

    def get_clic_appointments(self):
        '''
        Get existing ClicRDV entries that will be deleted
        '''
        appointments = consume_paginate(self.ses, api[self.inst]['baseurl'] +
                                        '/groups/' + self.group_id +
                                        '/appointments.json?include_past=1' +
                                        '&sort=start')
        for entry in appointments:
            self.clic_agenda += [entry]
            self.stats['found_clic_agenda_entries'] += 1
        return

    def print_clic_appointments(self):
        for entry in self.clic_agenda:
            print("start: %s\tend: %s\tid: %s" % (entry['start'],
                                                  entry['end'],
                                                  entry['id']))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-F', '--Force', action='store_true',
                        help='Force the deletion of old appointments')
    parser.add_argument('-d', '--date', nargs=1,
                        help='Date until when to delete old appointments')
    args = parser.parse_args()
    clic_instance = 'prod'
    auth = get_clicrdv_creds()

    api[clic_instance]['apikey'] = auth['apikey']

    clic = clicrdv(clic_instance)
    clic.create_new_agenda_entries = args.Force

    print('Opening session to ClicRDV %s instance...' % clic_instance)
    clic.clic_session_open(auth)
    if clic.ses is not None:
        clic.get_clic_appointments()
        clic.print_clic_appointments()
    else:
        return

    print('### Sommaire ###')
    print('RV ClicRDV                    : %d' %
          clic.stats['found_clic_agenda_entries'])


if __name__ == '__main__':
    main()
