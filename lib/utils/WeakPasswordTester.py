# coding:utf-8

import re

from lib.core import Dictionary
from lib.exceptions import NoRequestsException

import requests


class WeakPasswordTester:
    def __init__(self, results, **kwargs):
        self.results = results
        self.args = kwargs

    @staticmethod
    def meta():
        return {
            'name': 'Weak Password Tester for all',
            'version': '1.0'
        }

    def exec(self):
        if 'requests' not in self.results:
            raise NoRequestsException
        for request in self.results['requests']:
            if request['content-type'] == 'text/plain':
                continue
            regex = ['log.*in', 'sign.*in', 'opt.*in']
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
                dict_username = Dictionary.preset('weak_username')
                dict_password = Dictionary.preset('weak_password')

                def get_pair():
                    limit = self.args['limit']
                    if self.args['random']:
                        for _username in dict_username.random(limit):
                            for _password in dict_password.random(limit):
                                yield (_username, _password)
                    else:
                        if limit == 0:
                            limit = max(len(dict_username.fields), len(dict_password.fields))
                        for _username in dict_username.fields[:min(limit, len(dict_username.fields))]:
                            for _password in dict_password.fields[:min(limit, len(dict_password.fields))]:
                                yield (_username, _password)

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
                        pass
                    elif r.status_code in [301, 302, 306]:
                        pass
