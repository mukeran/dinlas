# coding:utf-8
if __name__ == '__main__':
    import sqlmap.sqlmapapi
    sqlmap.sqlmapapi.main()
    exit(0)

from multiprocessing import Process
if __name__ == '__main__':
    def sqlmapapi():
        import sqlmap.sqlmapapi
        sqlmap.sqlmapapi.main()


    process = Process(target=sqlmapapi)
    process.start()
    exit(0)

import urllib
import urllib.request
import urllib.error
import time
import psutil
import base64


import json
from lib.core.Logger import Logger
import subprocess

# Default REST-JSON API server listen address
RESTAPI_DEFAULT_ADDRESS = "127.0.0.1"

# Default REST-JSON API server listen port
RESTAPI_DEFAULT_PORT = 8775


class SQLMap:
    def __init__(self, host=RESTAPI_DEFAULT_ADDRESS, port=RESTAPI_DEFAULT_PORT, username = '', password = '', **kwargs):
        self.args = kwargs
        self.api_url = "http://%s:%d" % (host, port)
        self.tasks = []
        self.username = username
        self.password = password
        # cookies = dict(cookies_are='working')
        # self.session = requests.session()
        # self.session.cookies.set('??','')
        # self.session.hooks = {  # 错误的状态码直接报错
        #     'response': lambda r, *args, **kwargs: r.raise_for_status()
        # }

    @staticmethod
    def meta():
        return {
            'name': 'SQL map controller',
            'version': '1.0'
        }

    # TODO 找端口号
    def sqlmapapi_launch(self):
        """ launches sqlmapapi in another process and make sure it launched """

        def background():
            if self.username or self.password:
                sta = execute(['python', 'lib/utils/SQLInjector/SQLMap.py', '-s', '--username=%s'%self.username, '--password=%s'%self.password], None, None,
                              None)
            else:
                sta = execute(['python', 'lib/utils/SQLInjector/SQLMap.py', '-s'], None, None,
                          None)

            if 'Address already in use' in sta:
                Logger.critical('sqlmapapi.py said: {}'.format(sta))

            if 'bash' in sta:
                Logger.critical('bash error: {}'.format(sta))

        self.process = Process(target=background)
        self.process.start()

        time.sleep(5)

        if not self.is_sqlmapapi_launched:
            Logger.critical("sqlmapapi.py couldn't be launched")

    @property
    def is_sqlmapapi_launched(self):
        """ return True if sqlmapapi is launched, otherwise False """
        launched = False
        launched = 'SQLMap.py' in str({p.pid: p.info for p in
                                          psutil.process_iter(attrs=['cmdline'])})

        return launched

    def sqlmapapi_check(self):
        """ verify if sqlmapi is launched, if not launch it """
        Logger.info("Checking if sqlmapapi is already launched")

        if not self.is_sqlmapapi_launched:
            Logger.info("Launching sqlmapapi")
            self.sqlmapapi_launch()

    def _client(self, url, options=None):
        # logger.debug("Calling '%s'" % url)
        try:
            data = None
            if options is not None:
                data = jsonize(options)
                data = bytes(data, 'utf8')
            headers = {"Content-Type": "application/json"}

            if self.username or self.password:
                headers["Authorization"] = "Basic %s" % base64.b64encode(
                    "%s:%s" % (self.username or "", self.password or ""))

            req = urllib.request.Request(url, data, headers)
            response = urllib.request.urlopen(req)
            text = response.read()
        except:
            if options:
                Logger.error("Failed to load and parse %s" % url)
            raise
        return text

    def __del__(self):
        # self.session.close()
        pass

    def test_connection(self):
        try:
            self._client(self.api_url)
        except Exception as ex:
            if not isinstance(ex, urllib.error.HTTPError):
                errMsg = "There has been a problem while connecting to the "
                errMsg += "REST-JSON API server at '%s' " % self.api_url
                errMsg += "(%s)" % ex
                Logger.critical(errMsg)
                return False
        return True

    def launch(self):
        self.sqlmapapi_check()
        return self.test_connection()

    def _new_task_id(self):
        raw = self._client("%s/task/new" % self.api_url)
        res = dejsonize(raw)
        if not res["success"]:
            Logger.error("Failed to create new task")
            return False
        else:
            taskid = res["taskid"]
            Logger.info("New task ID is '%s'" % taskid)
            self.tasks.append(taskid)
            return taskid

    def _scan_start(self, taskid, options):
        raw = self._client("%s/scan/%s/start" % (self.api_url, taskid), options)
        res = dejsonize(raw)
        if not res["success"]:
            Logger.error("Failed to start scan")
            return res
        Logger.info("Scanning started")
        return res

    def scan(self, options):
        taskid = self._new_task_id()
        return self._scan_start(taskid, options), taskid

    def admin(self, command):
        if not command in ('list', 'flush'):
            Logger.error("Invalid call to sqlmapapi admin")
        raw = self._client("%s/admin/%s" % (self.api_url, command))
        res = dejsonize(raw)
        if not res["success"]:
            Logger.error("Failed to execute sqlmap API admin command %s" % command)
        return res

    def task(self, command, taskid):
        if not taskid:
            Logger.error("No task ID")
        if command in ("data", "log", "status", "stop", "kill"):
            raw = self._client("%s/scan/%s/%s" % (self.api_url, taskid, command))
            res = dejsonize(raw)
            if not res["success"]:
                Logger.error("Failed to execute command %s" % command)
            return res
        elif command in ('option'):
            raw = self._client("%s/option/%s/list" % (self.api_url, taskid))
            res = dejsonize(raw)
            if not res["success"]:
                Logger.error("Failed to execute command %s" % command)
            return res

    def option(self, taskid, options):
        """
            Get value of option(s) for a certain task ID
            options is a array
        """
        raw = self._client("%s/option/%s/get" % (self.api_url, taskid), options)
        res = dejsonize(raw)
        if not res["success"]:
            Logger.error("Failed to get option for task %s" % taskid)
        return res

    def exec(self):
        pass



class CONTENT_TYPE(object):
    TARGET = 0
    TECHNIQUES = 1
    DBMS_FINGERPRINT = 2
    BANNER = 3
    CURRENT_USER = 4
    CURRENT_DB = 5
    HOSTNAME = 6
    IS_DBA = 7
    USERS = 8
    PASSWORDS = 9
    PRIVILEGES = 10
    ROLES = 11
    DBS = 12
    TABLES = 13
    COLUMNS = 14
    SCHEMA = 15
    COUNT = 16
    DUMP_TABLE = 17
    SEARCH = 18
    SQL_QUERY = 19
    COMMON_TABLES = 20
    COMMON_COLUMNS = 21
    FILE_READ = 22
    FILE_WRITE = 23
    OS_CMD = 24
    REG_READ = 25
    STATEMENTS = 26


class CONTENT_STATUS(object):
    IN_PROGRESS = 0
    COMPLETE = 1


INJECTION_TYPE = {
    '1': 'Boolean-based blind',
    '2': 'Error-based',
    '3': 'Union query-based',
    '4': 'Stacked queries',
    '5': 'Time-based blind',
    '6': 'Inline queries'
}


def jsonize(data):
    """
    Returns JSON serialized data

    >>> jsonize({'foo':'bar'})
    '{\\n    "foo": "bar"\\n}'
    """
    return json.dumps(data, sort_keys=False, indent=4)


def dejsonize(data):
    """
    Returns JSON deserialized data

    >>> dejsonize('{\\n    "foo": "bar"\\n}') == {u'foo': u'bar'}
    True
    """

    return json.loads(data)


# TODO 待理解修改
def execute(command, cwd=None, timeout=None, background=False):
    command_str = ''
    for i in command:
        command_str += ' ' + i
    command_str = "'" + command_str.replace("'", "\\'") + "'"
    # command_str = ['bash -c {}'.format(command_str)]
    command_str = ['gnome-terminal -e {}'.format(command_str)]
    shellmode = True
    Logger.debug("command: {}; cwd: {}; timeout: {}; shellmode: {}".format(
        command_str, cwd, timeout, shellmode))
    result = subprocess.run(
        command_str,
        stdout=subprocess.PIPE,
        cwd=cwd,
        timeout=timeout,
        shell=shellmode)
    return result.stdout.decode('utf-8')
