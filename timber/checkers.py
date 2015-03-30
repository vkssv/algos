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


class UrlChecker(object):

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

class AttachChecker(object):
    def __init__(self, pattern_obj):
        print('ATTACH CHECKER INSTANCE CREATE ----------> FILL INSTANCE TABLE')

        self.attach_rules = BasePattern.get_regexp(pattern_obj.ATTACH_RULES)
        self.mime_struct = reduce(add, pattern_obj.get_mime_struct())
        self.attach_attrs = filter(lambda name: re.search(r'(file)?name([\*[:word:]]{1,2})?=.*',name), self.mime_struct)
        self.score = pattern_obj._penalty_score
        #

        print(pattern_obj.__class__)

        logger.debug('URLChecker was created'.upper()+': '+str(id(self)))

        logger.debug("================")
        print(self.__dict__)

        logger.debug("================")

    def get_attach_count(self):

        logger.debug('MIME STRUCT >>>>>'+str(self.mime_struct())+'/n')
        attach_attrs = [( x.partition(';')[2]).strip('\r\n\x20') for x in self.attach_attrs ]

        return len(attach_attrs)

    def get_attach_in_score(self):

        in_score = self.score*len(filter(lambda value: re.search(r'inline\s*;', value, re.I), self.mime_struct))

        return in_score

    def get_attach_score(self):

        score = self.score*len(filter(lambda name: re.search(r'(file)?name(\*[0-9]{1,2}\*)=.*',name), self.attach_attrs))
        x = list()
        for regexp_obj in self.attach_rules:
            x.extend([value for value in self.attach_attrs if regexp_obj.search(value,re.M)])

        score += self.score*len(x)

        return score


class ListChecker(object):

    def __init__(self, pattern_obj):
        print('LIST CHECKER INSTANCE CREATE ----------> FILL INSTANCE TABLE')

        self.attach_rules = BasePattern.get_regexp(pattern_obj.ATTACH_RULES)
        self.mime_struct = reduce(add, pattern_obj.get_mime_struct())
        self.attach_attrs = filter(lambda name: re.search(r'(file)?name([\*[:word:]]{1,2})?=.*',name), self.mime_struct)
        self.score = pattern_obj._penalty_score
        #

        print(pattern_obj.__class__)

        logger.debug('URLChecker was created'.upper()+': '+str(id(self)))

        logger.debug("================")
        print(self.__dict__)

        logger.debug("================")


    def get_list_score(self):

        #:return: penalizing score for List-* headers

        if not filter(lambda list_field: re.search('(List|Errors)(-.*)?', list_field), self._msg.keys()):
            return self.list_score

        # check Reply-To only with infos, cause it is very controversial,
        # here are only pure RFC 2369 checks
        # leave Errors-To cause all russian email-market players
        # put exactly Errors-To in their advertising emails instead of List-Unsubscribe
        rfc_heads = ['List-Unsubscribe', 'Errors-To', 'Sender']
        presented = [ head for head in rfc_heads if self._msg.keys().count(head) ]

        # alchemy, probably was written just for fun, e.g this body doesn't support RFC 2369 in a proper way ))
        self.list_score += (len(rfc_heads)-len(presented))*self._penalty_score

        #body_from = re.compile(r'@.*[a-z0-9]{1,63}\.[a-z]{2,4}')
        sender_domain = False
        while not (sender_domain):
            sender_domain = self.get_smtp_originator_domain()
            originator = self.get_addr_values(self._msg.get_all('From'))
            if not originator:
                return self.list_score

            orig_name, orig_addr = reduce(add, originator)
            sender_domain = (orig_addr.split('@')[1]).strip()


        patterns = [
                        r'https?:\/\/.*'+sender_domain+'\/.*(listinfo|unsub|email=).*', \
                        r'mailto:.*@.*\.'+sender_domain+'.*'
        ]

        for uri in [ heads_dict.get(head) for head in presented ]:
            if not filter(lambda reg: re.search(reg, uri, re.M), patterns):
                self.list_score += self._penalty_score

        return self.list_score


    def get_delivered_to(self):
        pass

class OriginatorChecker(object):
    def get_from_checksum(self):
        logger.debug('>>> 2. ORIGINATOR_CHECKS:')

        if self._msg.get('From'):
            name_addr_tuples = self.get_addr_values(self._msg.get_all('From'))[:1]
            logger.debug('\tFROM:----->'+str(name_addr_tuples))
            print(name_addr_tuples)

            if len(name_addr_tuples) != 1:
                logger.warning('\t----->'+str(name_addr_tuples))

            if name_addr_tuples:
                from_value, from_addr = reduce(add, name_addr_tuples)
                self.from_checksum = binascii.crc32(from_value.encode(self.DEFAULT_CHARSET))
                logger.debug('\t----->'+str(self.from_checksum))

        return self.from_checksum

    # particular feature and method
    def get_originator_score(self):

        logger.debug('>>> 2. ORIG_CHECKS:')

        if not filter(lambda list_field: re.search('(List|Errors)(-.*)?', list_field), self._msg.keys()):
            if self._msg.keys().count('Sender') and self._msg.keys().count('From'):
                self.forged_sender = self._penalty_score
                # if we don't have List header, From value has to be equal to Sender value (RFC 5322),
                # MUA didn't generate Sender field cause of redundancy

        logger.debug('forged_sender '.upper()+str(self.forged_sender))
        return self.forged_sender


class ContentChecker(object):
    def get_text_score(self, **kwargs):

        #Maps input regexp list to each sentence one by one
        #:return: penalising score, gained by sentenses

        self.__unpack_arguments('text_regexp_list', **kwargs)

        # precise flag for re.compile ?
        regs_list = self._get_regexp(self.TEXT_REGEXP_LIST, re.M)

        sents_generator = self.get_sentences()
        print("sent_lists >>"+str(self.get_sentences()))

        while(True):
            try:
                for reg_obj in regs_list:
                    self.txt_score += len(filter(lambda s: reg_obj.search(s,re.I), next(sents_generator)))*self._penalty_score
                    print("text_score: "+str(self.txt_score))
            except StopIteration as err:
                break

        logger.debug('text_score: '.upper()+str(self.txt_score))
        return self.txt_score

    def get_html_score(self, **kwargs):

        #1. from the last text/html part creates HTML-body skeleton from end-tags,
        #    takes checksum from it, cause spammer's and info's/net's HTML patterns
        #    are mostly the same ;
        #2. if HTML-body includes table - analyze tags and values inside, cause
        #    info's and net's HTML-patterns mostly made up with pretty same <tables> ;

        #:param tags_map: expected <tags attribute="value">, described by regexes ;
        #:return: <penalizing score> and <checksum for body> ;

        self.__unpack_arguments('html_tags_map', **kwargs)
        attr_value_pair = namedtuple('attr_value_pair', 'name value')

        print("tags_map: "+str(self.HTML_TAGS_MAP))

        soups_list = self.get_html_parts()

        while(True):
            try:
                soup = next(soups_list)
            except StopIteration as err:
                return self.html_score

                if not soup.body.table:
                    continue

                # analyze tags and their attributes
                soup_attrs_list = filter(lambda y: y, [ x.attrs.items() for x in soup.body.table.findAll(tag) ])
                print(soup_attrs_list)
                logger.debug('soup_attrs_list '+str(soup_attrs_list))
                if not soup_attrs_list:
                    continue

                soup_attrs_list = [ attr_value_pair(*obj) for obj in reduce(add, soup_attrs_list) ]
                print(soup_attrs_list)
                print('type of parsing line in reg_obj: '+str(type(self.HTML_TAGS_MAP[tag])))
                compiled_regexp_list = self._get_regexp(self.HTML_TAGS_MAP.get[tag], re.U)

                pairs = list()
                for key_attr in compiled_regexp_list: # expected_attrs_dict:
                    print(key_attr)
                    pairs = filter(lambda pair: key_attr.match(pair.name, re.I), soup_attrs_list)
                    print(pairs)

                    check_values = list()
                    if pairs:
                        check_values = filter(lambda pair: re.search(ur''+expected_attrs_dict.get(key_attr), pair.value, re.I), soup_attrs_list)
                        self.html_score += self._penalty_score*len(check_values)

        return self.html_score

    def get_html_checksum(self):

        html_skeleton = list()
        soups_list = self.get_html_parts()

        for s in tuple(soups_list):
            # get table checksum
            comments = s.body.findAll( text=lambda text: isinstance(text, Comment) )
            [comment.extract() for comment in comments]
            # leave only closing tags struct
            reg = re.compile(ur'<[a-z]*/[a-z]*>',re.I)
            # todo: investigate the order of elems within included generators
            html_skeleton.extend(t.encode('utf-8', errors='replace') for t in tuple(reg.findall(s.body.prettify(), re.M)))

        self.html_checksum = binascii.crc32(''.join(html_skeleton))

        return self.html_checksum

    def get_text_parts_avg_entropy(self):

        #for fun
        #:return:

        n = 0
        txt_avg_ent = 0
        # todo: make n-grams
        for tokens in self.get_stemmed_tokens():
            n +=1
            freqdist = FreqDist(tokens)
            probs = [freqdist.freq(l) for l in FreqDist(tokens)]
            print('P >>> '+str(probs))
            txt_avg_ent += -sum([p * math.log(p,2) for p in probs])

        self.txt_avg_ent = txt_avg_ent/n
        logger.debug('avg_ent'.upper()+': '+str(self.txt_avg_ent))

        return self.txt_avg_ent

    def get_text_compress_ratio(self):

        #maybe
        #:return: compress ratio of stemmed text-strings from
        #all text/mime-parts

        all_text_parts = list(self.get_stemmed_tokens())
        for x in all_text_parts:
            logger.debug('>>>> '+str(x))
        if all_text_parts:
            all_text = ''.join(reduce(add, all_text_parts))
            print(type(all_text))
            self.txt_compressed_ratio = float(len(zlib.compress(all_text.encode(self.DEFAULT_CHARSET))))/len(all_text)

        return self.txt_compressed_ratio

if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)
