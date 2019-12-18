# coding:utf-8

from .api import API
from .default import Default
from .dynamic import Dynamic
from .static import Static

extensions = [API, Default, Dynamic, Static]
mappings = {
    'api': API,
    'default': Default,
    'dynamic': Dynamic,
    'static': Static
}
