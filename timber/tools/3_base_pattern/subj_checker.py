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


class SubjectChecker(BasePattern):
    '''
    Base parent class for created all other four pattern classes.
    Provides some basic checks and metrics for email's headers and bodies.
    Keeps Frankenstein's DNAs.
    '''
    print('SUBJECTCHECKER ----------> CREATE CLASS OBJ TABLE')

    print('SUBJECTCHECKER ----------> FINISH CLASS ATTRIBUTE TABLE')
    # BASE_FEATURES = ('rcvd_traces_num','rcpt_smtp_to', 'rcpt_body_to', 'list', 'avg_entropy')

    def __init__(self,**kwds):


        print('SUBJECTCHECKER INSTANCE CREATE ----------> FILL INSTANCE TABLE')
        #self._penalty_score = score

        super(SubjectChecker, self).__init__(**kwds)
        print(self.__class__)
        self.subj_line, self.subj_tokens, self.encodings_list = self.get_decoded_subj()
        #self.subj_rules = BasePattern.get_regexp(pattern_obj.SUBJ_RULES)
        #self.score = pattern_obj._penalty_score

        logger.debug('SubjectChecker was created'.upper()+': '+str(id(self)))

        logger.debug("================")
        logger.debug(self.__dict__)


        logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))


    def get_subj_score(self):

        logger.debug('3. >>> SUBJ_CHECKS')

        print('compiled_regs: '+str(self.SUBJ_RULES))
        # check by regexp rules
        matched = filter(lambda r: r.search(self.subj_line, re.I), self.subj_rules)
        subj_score = self.score*len(matched)
        print('subj_score: '+str(subj_score))

        return subj_score


if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)
