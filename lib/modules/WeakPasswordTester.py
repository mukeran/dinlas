# coding:utf-8

import re
import random

from lib.core.Dictionary import Dictionary
from lib.exceptions import NoRequestsException

import requests


class WeakPasswordTester:
    def __init__(self, results, reports, **kwargs):
        self.results = results
        self.args = kwargs
        self.reports = reports

    @staticmethod
    def meta():
        return {
            'name': 'Weak Password Tester for all',
            'version': '1.0'
        }

    def exec(self):
        if 'requests' not in self.results:
            raise NoRequestsException
        self.results['weak_passwords'] = []
        for uuid in self.results['requests']:
            request = self.results['requests'][uuid]
            if request['content-type'] == 'text/plain':
                continue
            regex = ['.*log.*in.*', '.*sign.*in.*', '.*opt.*in.*', '.*index.*']
            flag = False
            for r in regex:
                if re.match(r, request['url']):
                    flag = True
                    break
            if not flag:
                continue
            username_aliases = ['username', 'user', 'user_name', 'handle', 'login_name']
            password_aliases = ['password', 'pass', 'pass_word', 'key', 'secret']
            flag1 = flag2 = False
            username_alias = password_alias = ''
            for alias in username_aliases:
                if alias in request['fields']:
                    flag1 = True
                    username_alias = alias
                    break
            for alias in password_aliases:
                if alias in request['fields']:
                    flag2 = True
                    password_alias = alias
                    break
            if flag1 and flag2:
                dict_username = Dictionary.preset(self.args['root'], 'weak_username')
                dict_password = Dictionary.preset(self.args['root'], 'weak_password')

                def get_pair():
                    limit = self.args['limit']
                    if self.args['random']:
                        if self.args['username'] is not None:
                            for _password in dict_password.random(limit):
                                yield (self.args['username'], _password)
                        else:
                            for _username in dict_username.random(limit):
                                for _password in dict_password.random(limit):
                                    yield (_username, _password)
                    else:
                        if limit == 0:
                            limit = max(len(dict_username.entries), len(dict_password.entries))
                        if self.args['username'] is not None:
                            for _password in dict_password.entries[:min(limit, len(dict_username.entries))]:
                                yield (self.args['username'], _password)
                        else:
                            for _username in dict_username.entries[:min(limit, len(dict_username.entries))]:
                                for _password in dict_password.entries[:min(limit, len(dict_password.entries))]:
                                    yield (_username, _password)
                    yield (hex(random.randrange(1e10, 1e20)), hex(random.randrange(1e10, 1e20)))

                status = []
                result2xx = result3xx = 0
                for username, password in get_pair():
                    params = {}
                    r = None
                    for field in request['fields']:
                        if field == username_alias:
                            params[field] = username
                        elif field == password_alias:
                            params[field] = password
                        else:
                            if 'default' in request['fields'][field]:
                                params[field] = request['fields'][field]['default']
                            elif 'values' in request['fields'][field]:
                                params[field] = request['fields'][field]['values'][0]
                            elif 'value' in request['fields'][field]:
                                params[field] = request['fields'][field]['value']
                            else:
                                params[field] = ''
                    if request['method'] == 'GET':
                        r = requests.get(request['url'], params=params)
                    elif request['method'] == 'POST':
                        if request['content-type'] == 'application/x-www-form-urlencoded':
                            r = requests.post(request['url'], data=params)
                        elif request['content-type'] == 'multipart/form-data':
                            r = requests.post(request['url'], files=params)
                    if r.status_code == 200:
                        status.append({
                            'username': username,
                            'password': password,
                            'status_code': 200,
                            'content': r.content
                        })
                        result2xx += 1
                    elif r.status_code in [301, 302, 306]:
                        location = r.headers['Location'] if 'Location' in r.headers else\
                            (r.headers['location'] if 'location' in r.headers else None)
                        status.append({
                            'username': username,
                            'password': password,
                            'status_code': r.status_code,
                            'location': location
                        })
                        result3xx += 1
                last = status[-1]
                status.pop()
                if last['status_code'] == 200:
                    if result3xx > 0:
                        for stat in status:
                            if stat['status_code'] in [301, 302, 306]:
                                self.results['weak_passwords'].append({
                                    'url': request['url'],
                                    'username': stat['username'],
                                    'password': stat['password']
                                })
                    else:
                        for stat in status:
                            if stat['content'] != last['content']:
                                self.results['weak_passwords'].append({
                                    'url': request['url'],
                                    'username': stat['username'],
                                    'password': stat['password']
                                })
                else:
                    if result2xx > 0:
                        for stat in status:
                            if stat['status_code'] == 200:
                                self.results['weak_passwords'].append({
                                    'url': request['url'],
                                    'username': stat['username'],
                                    'password': stat['password']
                                })
                    else:
                        for stat in status:
                            if stat['location'] != last['location']:
                                self.results['weak_passwords'].append({
                                    'url': request['url'],
                                    'username': stat['username'],
                                    'password': stat['password']
                                })
        self.reports.append({
            'title': 'Weak Passwords',
            'overview': 'Found {} weak password pairs'.format(len(self.results['weak_passwords'])),
            'header': ['URL', 'Username', 'Password'],
            'entries': list(map(lambda x: [x['url'], x['username'], x['password']], self.results['weak_passwords']))
        })
