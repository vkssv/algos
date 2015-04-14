# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii, zlib, math

from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple, Counter, OrderedDict
from itertools import ifilterfalse

from nltk.tokenize import RegexpTokenizer
from nltk.corpus import stopwords
from nltk.stem import SnowballStemmer
from nltk.probability import FreqDist, ConditionalFreqDist

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

from msg_wrapper import BeautifulBody


class BasePattern(BeautifulBody):
    '''
    Base parent class for created all other four pattern classes.
    Provides some basic checks and metrics for email's headers and bodies.
    Keeps Frankenstein's DNAs.
    '''

    INIT_SCORE = 0 # can redifine for particular set of instanses, => use cls./self._INIT_SCORE in code
    EX_MIME_ATTRS_LIST=['boundary=','charset=']

    def __init__(self, score, **kwds):

        self._penalty_score = score

        super(BasePattern, self).__init__(**kwds)

        features_map = {
                            'base'  : ['all_heads_checksum','rcpt_score'],
                            'dmarc' : ['spf','score'],
                            'mime'  : ['nest_level','checksum']

        }

        for key in features_map.iterkeys():
            logger.debug('Add '+key+'features to '+str(self.__class__))

            if key == 'base':
                features = ['get_'+name for name in features_map[key]]
            else:
                features = ['get_'+key+'_'+name for name in features_map[key]]

            functions = [getattr(self, name, lambda : INIT_SCORE) for name in features]
            print(functions)
            #functions = [self.__getattribute__(name) for name in features]
            [f() for f in functions]
        

        self.rcvd_num = self.msg.keys().count('Received')
        self.get_rcvd_checksum()

        logger.debug('BasePattern was created'.upper()+': '+str(id(self)))
        #logger.debug(self.__dict__)
        for (k,v) in self.__dict__.iteritems():
            logger.debug(str(k).upper()+' ==> '+str(v).upper())
        logger.debug("================")
        #logger.debug(BasePattern.__dict__)
        for (k,v) in BasePattern.__dict__.iteritems():
            logger.debug(str(k).upper()+' ==> '+str(v).upper())
        logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))

    @staticmethod
    # use it only here for dirty particular needs
    def __unpack_arguments(*args, **kwargs):
        '''
        #:todo: + common value validator
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
    def get_regexp(regexp_list, compilation_flag=None):
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

    '''''
    def get_sender_domain(self):

        sender_domain = False
        while not (sender_domain):
            sender_domain = self.get_smtp_originator_domain()
            originator = self.get_addr_values(self.msg.get_all('From'))
            if not originator:
                return self.list_score

            orig_name, orig_addr = reduce(add, originator)
            sender_domain = (orig_addr.split('@')[1]).strip()

    # can be called from each particular pattern with particular excluded_list
    '''''
    def get_all_heads_checksum(self):
        #, excluded_list=None):
        '''
        :param excluded_list: uninteresting headers like ['Received', 'From', 'Date', 'X-.*']
        :return: <CRC32 from headers names>
        '''
        logger.debug(self.msg.items())
        #self.__unpack_arguments('excluded_heads', **kwargs)

        heads_vector = tuple(map(itemgetter(0), self.msg.items()))
        heads_dict = dict(self.msg.items())
        logger.debug(self.EXCLUDED_HEADS)

        #if cls.excluded_list:
        for ex_head in self.EXCLUDED_HEADS:
            # can use match - no new lines in r_name
            heads_vector = tuple(filter(lambda h_name: not re.match(ex_head, h_name, re.I), heads_vector[:]))

        self.all_heads_checksum = binascii.crc32(''.join(heads_vector))
        logger.debug('all_heads_checksum ==> '.upper()+str(self.all_heads_checksum))

        return self.all_heads_checksum

    # can be called from each particular pattern with particular rcvds_num
    def get_rcvd_checksum(self):
        '''
        :param rcvds_num: N curious Received headers from \CRLF\CRFL to top
        :return: dict {'rcvd_N': CRC32 } from line, formed by parsed values,
                 parser is interested only in servers IPs-literals, domains, etc
        '''

        logger.debug('self.RCVDS_NUM: '+str(self.RCVDS_NUM))
        rcvds_vect = self.get_rcvds(self.RCVDS_NUM)
        logger.debug('rcvds_vect:'+str(rcvds_vect))
        rcvd_checksum = {}

        for rcvd_line, n in zip(rcvds_vect, range(len(rcvds_vect))):
            self.__dict__['rcvd_'+str(n)] = self.INIT_SCORE
            logger.debug(rcvd_line)
            trace = map(lambda x: rcvd_line.replace(x,''),['from','by',' '])[2]
            trace = trace.strip().lower()
            trace = binascii.crc32(trace)

            self.__dict__['rcvd_'+str(n)] = trace
            rcvd_checksum['rcvd_'+str(n)] = trace

        logger.debug('rcvd_checksum :'+str(rcvd_checksum))
        return rcvd_checksum

    '''''
    def get_dkim_domain(self):

         if filter(lambda value: re.search(from_domain, value), [self.msg.get(h) for h in ['DKIM', 'DomainKey-Signature']]):
            logger.debug(from_domain)
            logger.debug(str([self.msg.get(h) for h in ['DKIM', 'DomainKey-Signature']]))
            self.dkim_domain = from_domain


        return self.dkim_domain
    '''''
    def get_dmarc_spf(self):

        self.dmarc_spf = self.INIT_SCORE

        if self.msg.keys().count('Received-SPF') and re.match(r'^\s*pass\s+', self.msg.get('Received-SPF'), re.I):
            self.dmarc_spf += self._penalty_score

        return self.dmarc_spf

    def get_dmarc_score(self):

        #:param score:
        #:param dmarc_heads: list of headers, described in RFC 6376, RFC 7208
        #:return: <DMARC metrics dict>

        self.dmarc_score = self.INIT_SCORE

        # RFC 7001, this header has always to be included
        if not (self.msg.keys()).count('Authentication-Results'):
            self.dmarc_score += self._penalty_score
        #    return (self.dmarc_spf, self.dmarc_score)

        dmark_heads = [ 'Received-SPF', 'DKIM-Signature', 'DomainKey-Signature']
        found = [ head for head in self.msg.keys() if head in dmark_heads ]
        logger.debug('TOTAL:'+str(found))

        self.dmarc_score += (len(dmark_heads) - len(found))*self._penalty_score

        # simple checks for Received-SPF and DKIM/DomainKey-Signature

        return self.dmarc_score

    def get_rcpt_score(self):

        #:param score:
        #:return: tuple with penalizing scores for To-header value from body,
        #and RCPT TO value from Received headers

        #for debut works only with To-header values

        name_addr_tuples = self.get_addr_values(self.msg.get_all('To'))
        only_addr_list = map(itemgetter(1), name_addr_tuples)
        logger.debug(only_addr_list)

        parsed_rcvds = [ rcvd.partition(';')[0] for rcvd in self.get_rcvds() ]
        print('parsed_rcvds >>'+str(parsed_rcvds))
        smtp_to_list = [ x for x in ( r.partition('for')[2].strip() for r in parsed_rcvds ) if x ]
        smtp_to_addr = re.findall(r'<(.*@.*)?>', ''.join(smtp_to_list))

        if not (smtp_to_list or only_addr_list):
            # can't check without data => leave zeros
            #return self.rcpt_smtp_to, self.rcpt_body_to
            return self.INIT_SCORE

        self.rcpt_score = len([value for value in smtp_to_list + only_addr_list if re.search(r'undisclosed-recipients', value, re.I)])*self._penalty_score

        if len(only_addr_list) == 1 and ''.join(smtp_to_addr) != ''.join(only_addr_list):
            self.rcpt_score += self._penalty_score
            logger.debug('\t----->'+str(self.rcpt_score))

        elif len(only_addr_list) > 2 and smtp_to_addr != '<multiple recipients>':
            self.rcpt_score += self._penalty_score
            logger.debug('\t----->'+str(self.rcpt_score))

        return self.rcpt_score

    def get_mime_nest_level(self):

        mime_parts = self.get_mime_struct()
        self.mime_nest_level = len(filter(lambda n: re.search(r'(multipart|message)\/',n,re.I), mime_parts.keys()))

        logger.debug('mime_nest_level: '.upper()+str(self.mime_nest_level))
        return self.mime_nest_level

    def get_mime_checksum(self):

        '''
        self.EX_MIME_ATTRS_LIST: values of uninteresting mime-attrs
        :return: 42
        '''

        self.mime_checksum = self.INIT_SCORE

        #self.__unpack_arguments('ex_mime_attrs_list', **kwargs)
        logger.debug('EXL:'+str(self.EX_MIME_ATTRS_LIST))

        for prefix in self.EX_MIME_ATTRS_LIST:
            items = [[k, list(ifilterfalse(lambda x: x.startswith(prefix),v))] for k,v in self.get_mime_struct().items()]

            if items:
                items = reduce(add, items)

            self.mime_checksum = binascii.crc32(''.join([''.join(i) for i in items]))

        logger.debug('mime_checksum: '.upper()+str(self.mime_nest_level))
        return self.mime_checksum


if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)
