# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii, zlib, math

from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple, Counter, OrderedDict
from itertools import ifilterfalse

from p_wrapper import BasePattern


logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(filename)s: %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#logger.addHandler(ch)

try:
    from bs4 import BeautifulSoup, Comment
except ImportError:
    print('Can\'t find bs4 module, probably, it isn\'t installed.')
    print('try: "easy_install beautifulsoup4" or install package "python-beautifulsoup4"')

#from m_wrapper import BeautifulBody

class FeatureTrigger(object):

    def __init__(self, aClass):
        self.aClass = aClass

    def __call__(self, *args):
        self.wrapped = self.aClass(*args)
        return self

class SpamDecorator(object):
    pass


class Validator(object):
    pass