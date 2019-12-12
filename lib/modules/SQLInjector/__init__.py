# coding:utf-8

import requests, re, time
from http.cookies import SimpleCookie
from urllib import parse
from requests.exceptions import ConnectionError, ReadTimeout, RequestException
import logging

from .SQLMapInjector import SQLMapInjector

USE_SQLMAP = False


def mutate(form):
    o_data = form['data']
    payloads = ["\xBF'\"("]
    for payload in payloads:
        for para in o_data:
            data = form['data'].copy()
            # logging.debug('data copy: {}'.format(data is form['data']))
            data[para] += payload  # add payload rear
            form['mutated'] = data
            yield form, para


def blind_payloads():
    f = open('./dictionary/blind_sql_Payloads.txt')
    line = f.readline()
    while line:
        yield line
        line = f.readline()
    f.close()


class SQLInjector:
    def __init__(self, results, reports, **kwargs):
        report = {'title': 'SQL Injection',
                  'overview': 'SQL injection vulnerabilities allow an attacker to'
                              ' alter the queries executed on the backend database. '
                              'An attacker may then be able to extract or modify informations stored in the database'
                              ' or even escalate his privileges on the system.',
                  'entries': [], 'header': ['URL', 'method', 'Parameter', 'Type', 'Payload']}
        self.headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36"}
        self.sql_report = report
        self.args = kwargs
        self.reports = reports
        self.results = results
        self.scanList = {}
        self.running = []
        self.vulnerable = []
        self._session = requests.session()
        self.timeout = 3
        if 'cookie' in self.args and self.args['cookie']:
            self.cookie = SimpleCookie()
            self.cookie.load(self.args['cookie'])
            self.cookie = {key: val for key, val in self.cookie.items()}
            for key in self.cookie:
                self._session.cookies.set(*[key, self.cookie[key]])

    @staticmethod
    def meta():
        return {
            'name': 'SQL Injector for all',
            'version': '1.0'
        }

    def craft_request(self, form, original=False):

        if original:
            data = form['data']
        else:
            data = form['mutated']

        headers = self.headers.copy()
        headers['referer'] = form['location']

        try:
            if form['method'].upper() == 'GET':
                response = self._session.get(form['url'],
                                             params=data,
                                             headers=self.headers,
                                             allow_redirects=False,
                                             timeout=self.timeout)
            elif form['method'].upper() == 'POST':
                if form.get("content-type", "application/x-www-form-urlencoded") != "application/x-www-form-urlencoded":
                    logging.error('Unknown content-type: {}'.format(form["content-type"]))
                response = self._session.post(form['url'],
                                              data=data,
                                              headers=self.headers,
                                              allow_redirects=False,
                                              timeout=self.timeout)
            else:
                logging.error('Wired HTTP Method: {}'.format(form['method']))
                response = self._session.request(form['method'], form['url'],
                                                 data=data,
                                                 headers=self.headers,
                                                 allow_redirects=False,
                                                 timeout=self.timeout)
        except ConnectionError as e:
            if "Read timed out" in str(e):
                raise ReadTimeout("Request time out")
            else:
                raise e

        logging.debug('request url: ' + str(response.request.method) + ' ' + str(response.request.url))
        # logging.debug('request body:' + str(response.request.body))
        logging.debug('request headers: ' + str(response.request.headers))
        return response

    def mutate_blind(self, form):
        o_data = form['data']
        for payload in blind_payloads():
            payload = payload.replace("[TAB]", "\t").replace("[LF]", "\n").replace("[TIME]", str(self.timeout + 1))
            for para in o_data:
                data = form['data'].copy()
                if "[VALUE]" in payload:
                    payload = payload.replace("[VALUE]", para)
                    data[para] = payload
                else:
                    data[para] = payload
                # to replace or to add
                form['mutated'] = data
                yield form, para

    @staticmethod
    def find_pattern(response):
        data = response.text
        if "You have an error in your SQL syntax" in data:
            return "MySQL Injection"
        if "supplied argument is not a valid MySQL" in data:
            return "MySQL Injection"
        if "Warning: mysql_fetch_array()" in data:
            return "MySQL Injection"
        if "mysqli_fetch_assoc() expects parameter 1 to be" in data:
            return "MySQL Injection"
        if "com.mysql.jdbc.exceptions" in data:
            return "MySQL Injection"
        if "MySqlException (0x" in data:
            return "MySQL Injection"
        if ("[Microsoft][ODBC Microsoft Access Driver]" in data or
                "Syntax error in string in query expression " in data):
            return "MSAccess-Based SQL Injection"
        if "[Microsoft][ODBC SQL Server Driver]" in data:
            return "MSSQL-Based Injection"
        if 'Microsoft OLE DB Provider for ODBC Drivers</font> <font size="2" face="Arial">error' in data:
            return "MSSQL-Based Injection"
        if "Microsoft OLE DB Provider for ODBC Drivers" in data:
            return "MSSQL-Based Injection"
        if "java.sql.SQLException: Syntax error or access violation" in data:
            return "Java.SQL Injection"
        if "java.sql.SQLException: Unexpected end of command" in data:
            return "Java.SQL Injection"
        if "PostgreSQL query failed: ERROR: parser:" in data:
            return "PostgreSQL Injection"
        if "Warning: pg_query()" in data:
            return "PostgreSQL Injection"
        if "XPathException" in data:
            return "XPath Injection"
        if "Warning: SimpleXMLElement::xpath():" in data:
            return "XPath Injection"
        if "supplied argument is not a valid ldap" in data or "javax.naming.NameNotFoundException" in data:
            return "LDAP Injection"
        if "DB2 SQL error:" in data:
            return "DB2 Injection"
        if "Dynamic SQL Error" in data:
            return "Interbase Injection"
        if "Sybase message:" in data:
            return "Sybase Injection"
        if "Unclosed quotation mark after the character string" in data:
            return ".NET SQL Injection"
        if "error '80040e14'" in data and "Incorrect syntax near" in data:
            return "MSSQL-Based Injection"
        if "StatementCallback; bad SQL grammar" in data:
            return "Spring JDBC Injection"

        ora_test = re.search(r"ORA-[0-9]{4,}", data)
        if ora_test is not None:
            return "Oracle Injection" + " " + ora_test.group(0)

        return ""

    def check_sql(self, mutated_form):
        try:
            response = self.craft_request(mutated_form)
        except ReadTimeout:  # not usual
            pass
        else:
            if self.find_pattern(response):
                return True
        logging.warning('Double check failed in check_sql: {}'.format(mutated_form['url']))
        return False

    def check_timeout(self, mutated_form):
        try:
            self.craft_request(mutated_form, True)  # response =
        except ReadTimeout:
            logging.warning('Double check failed in check_timeout')
            return False
        except RequestException:
            pass
        return True

    def report(self, mutated_form, parameter, vuln_info, response):
        if response == '':
            pass
        url = mutated_form['url']
        method = mutated_form['method']
        type_ = vuln_info
        if method.upper() == 'GET':
            payload = parse.urlencode(mutated_form['mutated'])
        else:
            payload = parse.urlencode(mutated_form['mutated'])
        self.sql_report['entries'].append([url, method, parameter, type_, payload])

    def exec(self):
        if USE_SQLMAP:
            smi = SQLMapInjector(self.results, self.reports, **self.args)
            smi.exec()
            return
        for form in self.results['requests'].values():
            craft_fields(form)
            timeout = 0
            skip_current = False
            saw_server_error = False
            current_parameter = None
            vuln_parameters = set()
            start_time = time.time()

            logging.debug('testing {}'.format(form['url']))
            for mutated_form, parameter in mutate(form):
                if current_parameter != parameter:
                    current_parameter = parameter
                if current_parameter in vuln_parameters:
                    continue
                if timeout >= 2 or (time.time() - start_time) > 15:
                    continue

                try:
                    response = self.craft_request(mutated_form)
                except ReadTimeout:  # not usual
                    logging.warning("[+] timeout on request {}".format(form['url']))
                    timeout += 1
                else:
                    timeout = 0
                    vuln_info = self.find_pattern(response)
                    if vuln_info and self.check_sql(mutated_form):
                        self.report(mutated_form, parameter, vuln_info, response)
                        vuln_parameters.add(parameter)
                    if response.status_code == 500 and not saw_server_error:  # server error?
                        saw_server_error = True
                        logging.warning("[+] server error on request {}".format(form['url']))

            for mutated_form, parameter in self.mutate_blind(form):
                if current_parameter != parameter:
                    current_parameter = parameter
                if current_parameter in vuln_parameters:
                    continue
                if skip_current:
                    continue

                try:
                    response = self.craft_request(mutated_form)
                except ReadTimeout:
                    logging.debug('found possible injection, start to double check')
                    logging.debug('parameter: {} mutated form: {}'.format(parameter, mutated_form,))
                    if not self.wait_till_response():
                        logging.warning("Can't test server connection by get the url...or the server dead? ")
                        skip_current = True
                    if not self.check_timeout(mutated_form):
                        logging.warning("Too much lag from website, can't reliably test time based blind SQLi")
                        skip_current = True
                        continue
                    logging.info("Blind SQL Injection found.")
                    self.report(mutated_form, parameter, "Blind SQL Injection vulnerability", '')
                    vuln_parameters.add(parameter)
                else:
                    if response.status_code == 500 and not saw_server_error:
                        saw_server_error = True
                        logging.warning("[+] server error on request {}".format(form['url']))

        self.sql_report['overview'] = 'Found {} Injections. <br>'.format(len(self.sql_report['entries'])) + \
                                      self.sql_report['overview']
        self.reports.append(self.sql_report)
        logging.info("SQLInjector Tasks finished !")

    def wait_till_response(self):
        url = self.args['url']
        times = 1
        time_start = time.time()
        while times < 6:
            try:
                self._session.get(url, headers=self.headers, allow_redirects=False, timeout=(self.timeout+1))
            except ReadTimeout:
                times += 1
            else:
                break
        if times == 6:
            return False
        lag = time.time() - time_start
        logging.warning('A lag of {} seconds detected...{}times'.format(lag, times))
        return True


def value(field):
    """
    default values for a form
    :param field
    :return: value
    """
    defaults = {
        "color": "#bcda55",
        "date": "2019-03-03",
        "datetime": "2019-03-03T20:35:34.32",
        "datetime-local": "2019-03-03T22:41",
        "email": "dinlas2019@mailinator.com",
        "file": ["pix.gif", "GIF89a", "image/gif"],
        "hidden": "default",
        "month": "2019-03",
        "number": "1337",
        "password": "Leet3in_",  # 8 characters with uppercase, digit and special char for common rules
        "radio": "beton",
        "range": "37",
        "search": "default",
        "submit": "submit",
        "tel": "0606060606",
        "text": "default",
        "textarea": "default",
        "time": "13:37",
        "url": "http://dinlas.com/",
        "week": "2019-W24"
    }
    if 'default' in field and field['default']:
        return field['default']
    if field['type'] == 'text' and 'mail' in field['name']:
        return defaults['email']
    if field['type'] == 'text' and 'pass' in field['name'] or 'pwd' in field['name']:
        return defaults['email']
    if field['type'] in ('select',):
        return field['values'][0] if 'values' in field and len(field['values']) > 0 else 'default'
    if field['type'] in ('checkbox',):
        if field['checked']:
            return field['value'] or 'on'
    if field['type'] in defaults:
        return defaults[field['type']]
    logging.error('Unknown input type {}'.format(field))
    return None


def craft_fields(form):
    logging.debug('form: {}'.format(form))
    form['data'] = {field['name']: value(field) for field in form['fields'].values() if value(field)}
