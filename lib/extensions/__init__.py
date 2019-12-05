# coding:utf-8

from .api import API
from .default import Default
from .dynamic import Dynamic
from .static import Static
from .php import PHP
from .python_dynamic import PythonDynamic
from .python_static import PythonStatic

extensions = [API, Default, Dynamic, Static, PHP, PythonDynamic, PythonStatic]
mappings = {
    'api': API,
    'default': Default,
    'dynamic': Dynamic,
    'static': Static,
    'php': PHP,
    'python_dynamic': PythonDynamic,
    'python_static': PythonStatic
}
