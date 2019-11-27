
import json
from lib.core.Logger import Logger
import subprocess

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
    command_str = "'" + command_str.replace("'", "\\'")
    command_str = ['bash -c {}'.format(command_str)]
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