# coding:utf-8

import time
from urllib import parse
import logging

from .SQLMap import SQLMap, CONTENT_STATUS, CONTENT_TYPE

DEFAULT_LEVEL = 1


class SQLMapInjector:
    def __init__(self, results, reports, **kwargs):
        report = {'title': 'SQL Injection',
                  'overview': 'SQL injection vulnerabilities allow an attacker to'
                              ' alter the queries executed on the backend database. '
                              'An attacker may then be able to extract or modify informations stored in the database'
                              ' or even escalate his privileges on the system.',
                  'entries': [], 'header': ['URL', 'method', 'Parameter', 'Type', 'Payload']}
        self.sql_report = report
        self.args = kwargs
        self.reports = reports
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
            if res['status'] != 'running':
                logging.info("[scan status: {}]: ID: {}".
                            format(res["status"], task["taskid"]))
                task['status'] = res
                task['log'] = self.sqlmap.task("log", task["taskid"])
                task['data'] = self.sqlmap.task("data", task["taskid"])
                logging.debug(task["url"])
                self.parse_task(task)
                # logging.debug(res)
                task['log'] = res
                self.running.remove(task)

    def wait_result(self):
        while self.running:
            self.result()
            logging.info("{} task still running".format(len(self.running)))
            # logging.debug(self.running)
            time.sleep(3)
        self.sql_report['overview'] = 'Found {} Injections. <br>'.format(len(self.sql_report['entries'])) + \
                                      self.sql_report['overview']
        self.reports.append(self.sql_report)
        logging.info("SQLMap Tasks are all finished !")

    def parse_task(self, task):
        if task['data']['data']:
            self.vulnerable.append(task)
            logging.critical('SQL injection found!')
            logging.info(task['data'])
            data = task['data']['data']
            entries = []
            for ent in data:
                if ent['type'] == CONTENT_TYPE.TARGET:
                    continue
                elif ent['type'] == CONTENT_TYPE.TECHNIQUES:
                    value = ent['value']
                    for vuln in value:
                        url = task['url']
                        method = task['option']['method']
                        parameter = vuln['parameter']
                        for d in vuln['data'].values():
                            title = d['title']
                            payload = d['payload']
                            entries.append([url, method, parameter, title, payload])
            self.sql_report['entries'] += entries

        rep = "%s" % task["log"]
        if 'CRITICAL' in rep:
            if 'all tested parameters do not appear to be injectable.' in rep:
                # The detection process was error-free but didn't found a SQLi
                logging.info('Not appear to be injectable.')

    def flush_all(self):
        self.sqlmap.admin("flush")
        logging.debug("SQLMap tasks flushed.")

    def add(self, form):
        options = self.parse_form(form)
        respond, taskid = self.sqlmap.scan(options)
        url = form['url']
        task = {"option": options, "taskid": taskid, "url": url}
        self.scanList[url] = task
        self.running.append(task)

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
            logging.error('Unknown input type {}'.format(field))

        option['randomAgent'] = True
        option['level'] = DEFAULT_LEVEL
        option['url'] = form['url']
        option['method'] = form['method']
        if 'cookie' in self.args:
            logging.debug('Cookie Set {}'.format(self.args['cookie']))
            option['cookies'] = self.args['cookie']
        if 'https' in option['url']:
            option['forceSSL'] = True
        if form['content-type'] == 'application/x-www-form-urlencoded':
            data = {field['name']: value(field) for field in form['fields'].values() if value(field)}
            if option['method'] == 'GET':
                option['url'] = option['url'].split('?')[0]
                option['url'] += '?' + parse.urlencode(data)
            else:
                option['data'] = parse.urlencode(data)
        else:
            logging.error("Unimplemented form encoding {} in url {}".format(form['content-type'], option['url']))
        return option

    def exec(self):
        self.launch()
        # logging.debug('requests: {}'.format(self.results))
        for i in self.results['requests']:
            self.add(i)
        self.wait_result()
        # logging.debug(report)
