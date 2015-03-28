# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii, zlib, math

from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple, Counter, OrderedDict
from itertools import ifilterfalse


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

from m_wrapper import BeautifulBody




class BasePattern(BeautifulBody):
    '''
    Base parent class for created all other four pattern classes.
    Provides some basic checks and metrics for email's headers and bodies.
    Keeps Frankenstein's DNAs.
    '''
    print('BASEPATTERN ----------> FILL CLASS ATTRIBUTE TABLE')
    INIT_SCORE = 0 # can redifine for particular set of instanses, => use cls./self._INIT_SCORE in code

    EX_MIME_ATTRS_LIST=['boundary=','charset=']

    print('BASEPATTERN ----------> CLASS OBJ CREATED')

    def __init__(self, score, **kwds):

        print('IN BASEPATTERN CONSTRUCTOR, FILL INSTANCE ATTRIBUTE TABLE')

        self._penalty_score = score


        super(BasePattern, self).__init__(**kwds)


        logger.debug('BasePattern instance was created'.upper()+': '+str(id(self)))
        #logger.debug(self.__dict__)

        logger.debug("================")
        #logger.debug(BasePattern.__dict__)
        logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))


    @staticmethod
    # use it only here for dirty particular needs
    def __unpack_arguments(*args, **kwargs):
        '''
        :todo: + common value validator
        '''
        print(args)
        print(type(args))
        attrs_to_set = [name for name in args if kwargs.has_key(name)]
        print('__unpack_arguments: '+str(attrs_to_set))
        if len(attrs_to_set) == 0:
            return

        attrs_to_set = [(n.upper(), kwargs.get(n)) for n in attrs_to_set]
        [self.__setattr__(key,value) for key,value in attrs_to_set]

        return

    @staticmethod
    def _get_regexp(regexp_list, compilation_flag=None):
        '''
        :param regexp_list: list of scary regexes
        :param compilation_flag: re.U, re.M, etc
        :return: list of compiled RE.objects, check this trash faster and easier
        '''
        # todo: also make it as iterator
        compiled_list = []

        for exp in regexp_list:
            #logger.debug(exp)
            if compilation_flag is not None:
                exp = re.compile(exp, compilation_flag)
            else:
                exp = re.compile(exp)

            compiled_list.append(exp)

        return compiled_list


