# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii, zlib, math

from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple, Counter, OrderedDict
from itertools import ifilterfalse, izip_longest

from nltk.tokenize import RegexpTokenizer
from nltk.corpus import stopwords
from nltk.stem import SnowballStemmer
from nltk.probability import FreqDist, ConditionalFreqDist

logger = logging.getLogger('')
#logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(filename)s: >> %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#logger.addHandler(ch)

try:
    from bs4 import BeautifulSoup, Comment
except ImportError:
    logger.debug('Can\'t find bs4 module, probably, it isn\'t installed.')
    logger.debug('try: "easy_install beautifulsoup4" or install package "python-beautifulsoup4"')

from msg_wrapper import BeautifulBody


class BasePattern(BeautifulBody):
    '''
    Base parent class for created all other four pattern classes.
    Provides some basic checks and metrics for email's headers and bodies.
    Keeps Frankenstein's DNAs.
    '''

    INIT_SCORE = 0.0
    PENALTY_SCORE = 1.0

    EX_MIME_ATTRS_LIST = ['boundary=','charset=']
    BASE_FEATURES = ['all_heads_checksum','rcpt_score']

    def __init__(self, score, **kwds):

        self.PENALTY_SCORE = score

        super(BasePattern, self).__init__(**kwds)

        methods_names = ['get_'+name for name in self.BASE_FEATURES]
        methods = [ (name.lstrip('get_'), getattr(self, name, lambda x: self.INIT_SCORE)) for name in methods_names ]
        # default "lambda x" here in getattr() just intercepts unexisted any method from self.BASE_FEATURES,
        # to avoid AttributeError exception

        for n, pair in enumerate(methods, start=1):
            name, f = pair
            logger.debug(str(n)+'. Add '+name.upper()+' attribute to '+str(self.__class__))
            value = self.INIT_SCORE
            # if attribute-method was found in BasePattern, setup it's default value before call, because
            # if later we will have an exception => anyway vector will have defined set of features
            logger.debug('called method : '+str(f))
            try:
                value = f()
            except Exception as err:
                logger.error(str(f)+' : '+str(err).upper())
                pass

            logger.debug((name+' ==> '+str(value)).upper())
            self.__setattr__(name, value)

        self.rcvd_num = self.msg.keys().count('Received')
        self.get_rcvd_checksum()

        logger.debug('BasePattern was created'.upper()+': '+str(id(self)))
        #logger.debug(self.__dict__)
        for (k,v) in self.__dict__.iteritems():
            logger.debug(str(k).upper()+' ==> '+str(v).upper())
        logger.debug("================")
        logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))
    
    @staticmethod
    def get_regexp(regexp_list, compilation_flag=None):
        '''
        :param regexp_list: list of scary regexes
        :param compilation_flag: re.U, re.M, etc
        :return: list of compiled RE.objects, check this trash faster and easier
        '''
        # todo: also make it as iterator
        compiled_list = []

        for exp in regexp_list:
            logger.debug(u'get_regexp : for compiling => '+exp)
            # cause mostly use unicoded lines and unicoded regexps
            # => re doesn't support re.I flag for them
            #logger.debug(exp)
            if compilation_flag is not None:
                exp = re.compile(exp, compilation_flag)
            else:
                exp = re.compile(exp)

            compiled_list.append(exp)

        return compiled_list


    def get_smtp_sender_domain(self):

        sender_domain = False
        while not (sender_domain):
            sender_domain = self.get_smtp_originator_domain()
            originator = self.get_addr_values(self.msg.get_all('From'))
            if not originator:
                return self.list_score

            orig_name, orig_addr = reduce(add, originator)
            sender_domain = (orig_addr.split('@')[1]).strip()



    def get_all_heads_checksum(self):

        '''
        :param excluded_list: uninteresting headers like ['Received', 'From', 'Date', 'X-.*']
        :return: < CRC32 from headers names >
        '''
        #logger.debug(self.msg.items())

        heads_vector = tuple(map(itemgetter(0), self.msg.items()))
        #print(heads_vector)
        heads_dict = dict(self.msg.items())
        #logger.debug('excluded heads list from '+str(self.__class__)+' : ')
        #logger.debug(self.EXCLUDED_HEADS)

        for ex_head in self.EXCLUDED_HEADS:
            heads_vector = tuple(filter(lambda h_name: not re.match(ex_head, h_name, re.I), heads_vector[:]))
        #print(heads_vector)
        all_heads_checksum = binascii.crc32(''.join(heads_vector))
        #logger.debug('all_heads_checksum ==> '.upper()+str(self.all_heads_checksum))
        return all_heads_checksum

    # can be called from each particular pattern with particular rcvds_num

    def get_rcvd_checksum(self):
        '''
        :param rcvds_num: N curious Received headers from \CRLF\CRFL to top
        :return: dict {'rcvd_N': CRC32 } from line, formed by parsed values,
                 parser is interested only in servers IPs-literals, domains, etc
        '''

        logger.debug('rcvds num from '+str(self.__class__)+' : '+str(self.RCVDS_NUM))
        rcvds_vect = self.get_rcvds(self.RCVDS_NUM)
        logger.debug('rcvds_vect :'+str(rcvds_vect))
        rcvd_checksum = {}

        for rcvd_line, n in izip_longest(rcvds_vect, range(self.RCVDS_NUM),fillvalue=''):
            self.__dict__['rcvd_'+str(n)] = self.INIT_SCORE
            logger.debug('rcvd_line : '+rcvd_line)
            trace = map(lambda x: rcvd_line.replace(x,''),['from','by',''])[2]
            trace = trace.strip().lower()
            trace = binascii.crc32(trace)

            self.__dict__['rcvd_'+str(n)] = trace
            rcvd_checksum['rcvd_'+str(n)] = trace

        #logger.debug('rcvd_checksum ==> '.upper()+str(rcvd_checksum))
        return rcvd_checksum

    def get_rcpt_score(self):

        #:param score:
        #:return: tuple with penalizing scores for To-header value from body,
        #and RCPT TO value from Received headers

        #for debut works only with To-header values

        name_addr_tuples = self.get_addr_values(self.msg.get_all('To'))
        only_addr_list = map(itemgetter(1), name_addr_tuples)
        logger.debug('only_addr_list : '+str(only_addr_list))

        parsed_rcvds = [ rcvd.partition(';')[0] for rcvd in self.get_rcvds() ]
        logger.debug('parsed_rcvds : '+str(parsed_rcvds))
        smtp_to_list = [ x for x in ( r.partition('for')[2].strip() for r in parsed_rcvds ) if x ]
        smtp_to_addr = re.findall(r'<(.*@.*)?>', ''.join(smtp_to_list))

        if not (smtp_to_list or only_addr_list):
            # can't check without data => leave zeros
            #return self.rcpt_smtp_to, self.rcpt_body_to
            logger.debug('rcpt_score ==> '.upper()+str(self.INIT_SCORE))
            return self.INIT_SCORE

        rcpt_score = len([value for value in smtp_to_list + only_addr_list if re.search(r'undisclosed-recipients', value, re.I)])*self.PENALTY_SCORE

        if len(only_addr_list) == 1 and ''.join(smtp_to_addr) != ''.join(only_addr_list):
            rcpt_score += self.PENALTY_SCORE

        elif len(only_addr_list) > 2 and smtp_to_addr != '<multiple recipients>':
            rcpt_score += self.PENALTY_SCORE

        logger.debug('rcpt_score ==> '.upper()+str(self.INIT_SCORE))
        return rcpt_score

if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)
