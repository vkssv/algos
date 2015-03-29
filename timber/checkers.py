# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii, zlib, math, string

from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple, Counter, OrderedDict
from itertools import ifilterfalse

from pattern_wrapper import BasePattern


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


class SubjectChecker(object):
    '''
    Base parent class for created all other four pattern classes.
    Provides some basic checks and metrics for email's headers and bodies.
    Keeps Frankenstein's DNAs.
    '''
    print('SUBJECTCHECKER ----------> CREATE CLASS OBJ TABLE')

    print('SUBJECTCHECKER ----------> FINISH CLASS ATTRIBUTE TABLE')
    # BASE_FEATURES = ('rcvd_traces_num','rcpt_smtp_to', 'rcpt_body_to', 'list', 'avg_entropy')

    def __init__(self, pattern_obj):

        print('SUBJECTCHECKER INSTANCE CREATE ----------> FILL INSTANCE TABLE')

        self.score = pattern_obj._penalty_score
        self.subj_line, self.subj_tokens, self.encodings_list = pattern_obj.get_decoded_subj()
        print(pattern_obj.__class__)
        self.subj_rules = BasePattern.get_regexp(pattern_obj.SUBJ_RULES)



        self.f = pattern_obj.SUBJ_FUNCTION
        print(self.f)

        # magic number !
        self.titles_threshold = pattern_obj.SUBJ_TITLES_THRESHOLD
        self.f = pattern_obj.SUBJ_FUNCTION
        print('func '+str(self.f))
        self.msg_heads_list = pattern_obj._msg.keys()

        logger.debug('SubjectChecker was created'.upper()+': '+str(id(self)))

        logger.debug("================")
        print(self.__dict__)

        logger.debug("================")


        logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))

    def get_subj_score(self):

        logger.debug('3. >>> SUBJ_CHECKS')

        print('compiled_regs: '+str(self.subj_rules))
        # check by regexp rules
        matched = filter(lambda r: r.search(self.subj_line, re.I), self.subj_rules)
        print(matched)
        subj_score = self.score*len(matched)
        print('subj_score: '+str(subj_score))

        prefix_heads_map = {
                                'RE' : ['In-Reply-To', 'Thread(-.*)?', 'References'],
                                'FW' : ['(X-)?Forward']
        }

        for k in prefix_heads_map.iterkeys():
            if re.match(ur''+k+'\s*:', self.subj_line, re.I):
                heads_list  = prefix_heads_map.get(k)

                for h_name in self.msg_heads_list:
                    found_heads = filter(lambda reg: re.match(reg, h_name, re.I), h_name)
                    subj_score += (len(prefix_heads_map.get(k)) - len(found_heads))*self.score

        return subj_score

    def get_subj_encoding(self):

        return len(set(self.encodings_list))

    def get_subj_style(self):

        subj_style = BasePattern.INIT_SCORE
        upper_count = len([w for w in self.subj_tokens if w.isupper()])
        title_count = len([w for w in self.subj_tokens if w.istitle()])

        if upper_count or (len(self.subj_tokens) - title_count) < self.titles_threshold:
            subj_style = self.score

        return subj_style

    def get_subj_checksum(self):
        # take crc32, make line only from words on even positions, not all

        tokens = self.subj_tokens
        # alchemy again
        if len(tokens) > 2:
            tokens = tuple([el for el in self.subj_tokens if self.f(el, self.subj_tokens)])

        subj_trace = ''.join(tuple([w.encode('utf-8') for w in tokens]))
        print(subj_trace)
        print(binascii.crc32(subj_trace))

        return binascii.crc32(subj_trace)


class URLChecker(object):

    def __init__(self, pattern_obj):
        print('URL CHECKER INSTANCE CREATE ----------> FILL INSTANCE TABLE')

        self.obj = pattern_obj
        self.urls = pattern_obj.get_url_obj_list()
        self.urls_domains = pattern_obj.get_net_location_list()
        self.score = pattern_obj._penalty_score
        #

        print(pattern_obj.__class__)

        logger.debug('URLChecker was created'.upper()+': '+str(id(self)))

        logger.debug("================")
        print(self.__dict__)

        logger.debug("================")

    def get_url_score(self):

        url_score = BasePattern.INIT_SCORE
        reg = namedtuple('reg', 'fqdn txt')
        regexes = reg(*(BasePattern.get_regexp(l, re.I) for l in (self.obj.URL_FQDN_REGEXP, self.obj.URL_TXT_REGEXP)))

        for reg in regexes.fqdn:
            url_score += len([domain for domain in self.urls_domains if reg.search(domain)])*self.score

        metainfo_list = list()
        for attr in ['path', 'query', 'fragment']:
            metainfo_list.extend([i.__getattribute__(attr) for i in self.urls])

        if metainfo_list:
            for reg in regexes.txt:
                url_score += len(filter(lambda metainfo: reg.search(metainfo), metainfo_list))*self.score

        return url_score

    def get_url_avg_len(self):
        # URL_AVG_LENGTH: they are short in general, cause of url-short services, etc

        # mostly thinking about shortened urls, created by tinyurl and other services,
        # but maybe this is weak feature
        avg_len = math.ceil(float(sum([len(s) for s in self.urls_domains]))/len(self.urls_domains))

        return avg_len

    def get_url_count(self):

        return len(self.urls)

    def get_url_distinct_count(self):

        return len(set([d.strip() for d in self.urls_domains]))

    def get_url_sender_count(self):

        sender_domain = False
        sender_count = BasePattern.INIT_SCORE
        while not (sender_domain):
            sender_domain = self.obj.get_smtp_originator_domain()
            originator = self.obj.get_addr_values(self.obj._msg.get_all('From'))
            if not originator:
                return sender_count

            orig_name, orig_addr = reduce(add, originator)
            sender_domain = (orig_addr.split('@')[1]).strip()


            pattern = ur'\.?'+sender_domain.decode('utf-8')+u'(\.\w{2,10}){0,2}'
            sender_count += len(filter(lambda d: re.search(pattern, d, re.I), self.urls_domains))

        return sender_count

    def get_url_uppercase(self):
        #URL_UPPER: presense of elements in upper-case/title-case in URL

        # 8. URL-checks
        logger.debug('>>> 8. URL_CHECKS:')
        uppercase = BasePattern.INIT_SCORE
        for method in [ unicode.isupper, unicode.istitle ]:
            uppercase += len(filter(lambda s: method(s), self.urls_domains))*self.score

        return uppercase

    def get_url_punicode(self):
        # PUNICORNS: respectively (very often for russian spams)
        puni_regex = ur'xn--[0-9a-z-]+(\.xn--[0-9a-z]+){1,3}'
        my_little_puni = len([domain for domain in self.urls_domains if re.search(puni_regex, domain, re.I)])*self.score

        return my_little_puni

    def get_url_fqdn(self):
        # DOMAIN NAME LEVEL: very often russian spams are send from third-level domains

        dots_counts = [s.count('.') for s in self.urls_domains]
        domain_name_level = len([count for count in dots_counts if count >=2 ])*self.score

        return domain_name_level

    def get_url_ascii(self):
        ascii = BasePattern.INIT_SCORE

        url_lines = [ ''.join(u._asdict().values()) for u in self.urls ]
        if list( x for x in  [line for line in url_lines] if x in string.printable ):
            ascii = self.score

        return ascii

    def get_url_sim(self):
        similarity = BasePattern.INIT_SCORE

        for attr in ['path','query']:
            obj_list = [ url.__getattribute__(attr) for url in self.urls ]
            if math.ceil(float(len(set(obj_list)))/float(len(urls_list))) < self.score:
                similarity += self.score

        return similarity

    def get_url_avg_query_len(self):

        avg_query_len = BasePattern.INIT_SCORE
        lengthes_list = [ len(url.query) for url in self.urls ]
        if lengthes_list:
            avg_query_len = sum(lengthes_list)/len(lengthes_list)

        return avg_query_len

    def get_url_repetitions(self):
        # REPETITIONS: presense of repetitions like:

        repet_regex = ur'(https?:\/\/|www\.)\w{1,61}(\.\w{2,10}){1,5}'
        urls = [x.geturl() for x in self.urls]

        urls_with_repetitions = map(lambda url: re.findall(repet_regex, url, re.I), urls)
        repetitions = len([l for l in urls_with_repetitions if len(l)>1])*self.score

        return repetitions

    def get_url_query_absence(self):
        # alchemi again
        query_absence = BasePattern.INIT_SCORE
        q_list = [u.query for u in self.urls]
        queries_count = float(len(filter(lambda line: line, [ u.query for u in self.urls ])))
        if math.floor(queries_count/float(len(self.urls_list))) == 0.0:
            query_absence = self.score

        return query_absence

'''''
    def get_url_hex(self):

        pass

    def get_url_onMouseOver(self):
        pass

'''''


if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)
