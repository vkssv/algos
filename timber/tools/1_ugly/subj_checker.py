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




class SubjectChecker(BeautifulBody):
    '''
    Base parent class for created all other four pattern classes.
    Provides some basic checks and metrics for email's headers and bodies.
    Keeps Frankenstein's DNAs.
    '''
    print('SUBJECTCHECKER ----------> CREATE CLASS OBJ TABLE')

    print('SUBJECTCHECKER ----------> FINISH CLASS ATTRIBUTE TABLE')
    # BASE_FEATURES = ('rcvd_traces_num','rcpt_smtp_to', 'rcpt_body_to', 'list', 'avg_entropy')

    def __init__(self, **kwds):


        print('SUBJECTCHECKER INSTANCE CREATE ----------> FILL INSTANCE TABLE')
        #self._penalty_score = score

        super(SubjectChecker, self).__init__(**kwds)



        logger.debug('SubjectChecker was created'.upper()+': '+str(id(self)))

        logger.debug("================")
        logger.debug(self.__dict__)

        logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))


    def get_subj_score(self):

        logger.debug('3. >>> SUBJ_CHECKS')
        print(self.__dict__)


        return

if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)
