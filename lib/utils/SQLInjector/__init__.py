# coding:utf-8

import time
from urllib import parse

from .SQLMap import SQLMap, CONTENT_STATUS, CONTENT_TYPE
from lib.core.Logger import Logger

DEFAULT_LEVEL = 1

class SQLInjector:
    def __init__(self, results, **kwargs):
        self.args = kwargs
        self.results = results
        self.sqlmap = SQLMap()
        self.scanList = {}
        self.running = []
        self.vulnerable = []


    @staticmethod
    def meta():
        return {
            'name': 'SQL Injector for all',
            'version': '1.0'
        }
    def launch(self):
        self.sqlmap.launch()

    def result(self):
        """
        check all results of running scanning
        :return:
        """
        for task in self.running:
            res = self.sqlmap.task("status", task["taskid"])
            if (res['status'] != 'running'):
                Logger.debug("[scan status: {}]: ID: {}".
                          format(res["status"], task["taskid"]))
                task['status'] = res
                task['log'] = self.sqlmap.task("log", task["taskid"])
                task['data'] = self.sqlmap.task("data", task["taskid"])
                Logger.debug(task["url"])
                self.parse_task(task)
                Logger.debug(res)
                task['log'] = res
                self.running.remove(task)

    def wait_result(self):
        while self.running:
            self.result()
            Logger.info("{} task still running".format(len(self.running)))
            Logger.debug(self.running)
            time.sleep(3)
        Logger.info("SQLMap Tasks are all finished !")

    def parse_task(self, task):
        if task['data']['data']:
            self.vulnerable.append(task)
            Logger.critical('SQL injection found!')
            Logger.info(task['data'])
            datas = task['data']['data']
            report = {'title': 'SQL Injection','overview':'SQL injection vulnerabilities allow an attacker to alter the queries executed on the backend database. An attacker may then be able to extract or modify informations stored in the database or even escalate his privileges on the system.'}
            report['header'] = ['URL', 'method', 'Parameter', 'Type', 'Payload']
            entries = []
            for ent in datas:
                if(ent['type'] == CONTENT_TYPE.TARGET):
                    continue
                elif(ent['type'] == CONTENT_TYPE.TECHNIQUES):
                    value = ent['value']
                    for vuln in value:
                        url = task['url']
                        method = task['option']['method']
                        parameter = vuln['parameter']
                        for d in vuln['data'].values():
                            title = d['title']
                            payload = d['payload']
                            entries.append([url, method, parameter, title, payload])
            report['entries'] = entries

        rep = "%s" % task["log"]
        if 'CRITICAL' in rep:
            if 'all tested parameters do not appear to be injectable.' in rep:
                # The detection process was error-free but didn't found a SQLi
                Logger.info('Not appear to be injectable.')

    def flush_all(self):
        res = self.sqlmap.admin("flush")
        Logger.debug("SQLMap tasks flushed.")

    def add(self, form):
        options = self.parse_form(form)
        respond, taskid = self.sqlmap.scan(options)
        url = form['url']
        task = {"option": options, "taskid": taskid, "url": url}
        self.scanList[url] = task
        self.running.append(task)

    # TODO referer headers cookie
    def parse_form(self, form):
        # option = {"url": url, "cookie": "PHPSESSID=muihhepaqno9bn31mhfrgstk00; security=low"}
        option = {}

        def value(field):
            if 'default' in field and field['default']:
                return field['default']
            if field['type'] in ('text', 'username', 'password', 'hidden'):
                return 'abc'
            if field['type'] in ('email',):
                return '123abc@abc.com'
            if field['type'] in ('number', 'range'):
                return '1'
            if field['type'] in ('select',):
                return field['values'][0]
            if field['type'] in ('checkbox',):
                if field['required']:
                    return 'on'
            Logger.error('Unknown input type {}'.format(field))

        option['randomAgent'] = True
        option['level'] = DEFAULT_LEVEL
        option['url'] = form['url']
        option['method'] = form['method']
        if 'https' in option['url']:
            option['forceSSL'] = True
        if form['content-type'] == 'application/x-www-form-urlencoded':
            data = {field['name']:value(field) for field in form['fields'].values() if value(field)}
            if option['method'] == 'GET':
                option['url'] = option['url'].split('?')[0]
                option['url'] += '?' + parse.urlencode(data)
            else:
                option['data'] = parse.urlencode(data)
        else:
            Logger.error("Unimplemented form encoding {} in url {}".format(form['content-type'], option['url']))
        return option


    def exec(self):
        self.launch()
        for i in self.results['requests']:
            self.add(i)
        self.wait_result()


'''
if __name__ == '__main__':
    sql = SQLInjector()
    sql.launch()
    dict = {'requests': [{'url': 'http://127.0.0.1/login.php', 'method': 'POST', 'content-type': 'application/x-www-form-urlencoded', 'fields': {'username': {'type': 'text', 'name': 'username', 'required': False, 'default': ''}, 'password': {'type': 'password', 'name': 'password', 'required': False, 'default': ''}, 'Login': {'type': 'submit', 'name': 'Login', 'required': False, 'default': 'Login'}, 'user_token': {'type': 'hidden', 'name': 'user_token', 'required': False, 'default': 'b979e6b3bea746d1139ec7b97158e1e7'}}}]}
    sql.exec(dict)
'''