# -*- coding: utf-8 -*-
'''
    Classes with rules for email headers and MIME-parts
'''

import sys, os, importlib, logging, re, binascii, zlib, math, string, urlparse

from operator import add, itemgetter
from collections import namedtuple
from itertools import ifilterfalse

from pattern_wrapper import BasePattern
from decorators import Wrapper

try:
    from bs4 import Comment
    from nltk.tokenize import RegexpTokenizer
    from nltk.corpus import stopwords
    from nltk.stem import SnowballStemmer
    from nltk.probability import FreqDist, ConditionalFreqDist
except ImportError as err:
    logger.error(str(err))
    sys.exit(1)

INIT_SCORE = BasePattern.INIT_SCORE
get_regexp = BasePattern.get_regexp

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class BaseChecker(object):

    puni_regex = r'xn--[0-9a-z-]+(\.xn--[0-9a-z]+){1,3}'

    def __init__(self, pattern_obj):

        self.score = pattern_obj.PENALTY_SCORE
        self.msg = pattern_obj.msg
        self.pattern = pattern_obj

@Wrapper
class SubjectChecker(BaseChecker):
    '''
    vectorize Subject-header value by
    following feature set :

    SCORE       --> gained by applying rough regexp pattern_obj.SUBJ_RULES to Subject-value
                    + simple check for obligatory correlation between Subject value prefix
                    (RE/FW/TR) and appropriate headers ;
    ENCODING    --> presence of multiple encodings in Subject-value ;
    STYLE       --> count of uppercased/titled words, compared with a pattern_obj.SUBJ_THRESHOLD ;
    CHECKSUM    --> CRC32 from parts of Subject-value, each pattern keeps its own function
                    for crunching these parts ;
    LEN         --> len ;
    '''

    def __init__(self, pattern_obj):

        BaseChecker.__init__(self, pattern_obj)
        logger.debug(self.score)

        self.subj_line, self.subj_tokens, self.encodings_list = pattern_obj.get_decoded_subj()
        self.subj_rules = get_regexp(pattern_obj.SUBJ_RULES)
        #self.subj_rules = pattern_obj.SUBJ_RULES

    def get_subject_score(self):

        #logger.debug('compiled_regs : '+str(self.subj_rules))
        # check by regexp rules
        #logger.debug(self.subj_rules)
        matched = list()
        matched.extend(filter(lambda r: re.search(r, self.subj_line.lower()), self.subj_rules))
        #logger.debug('matched : '+str(matched))
        subj_score = self.score*len(matched)

        prefix_heads_map = {
                                'RE' : ['In-Reply-To', 'Thread(-.*)?', 'References'],
                                'FW' : ['(X-)?Forward'],
                                'TR' : ['(X-)?Forward'] # for french MUA
        }

        for k in prefix_heads_map.iterkeys():
            logger.info(self.subj_line.encode('utf8','replace'))
            if re.match(r''+k+'\s*:', self.subj_line.encode('utf8','replace'), re.I):
                heads_list = prefix_heads_map.get(k)

                for h_name in self.msg.keys():
                    found_heads = filter(lambda reg: re.match(reg, h_name, re.I), h_name)
                    subj_score += (len(prefix_heads_map.get(k)) - len(found_heads))*self.score

        return subj_score

    def get_subject_encoding(self):

        return len(set(self.encodings_list))


    def get_subject_upper(self):
        logger.debug(self.subj_tokens)

        return len([w for w in self.subj_tokens if w.isupper()])

    def get_subject_titled(self):
        logger.debug(self.subj_tokens)

        return len([w for w in self.subj_tokens if w.istitle()])


    def get_subject_checksum(self):
        # take crc32, make line only from words on even positions, not all

        tokens = self.subj_tokens
        # alchemy again
        if len(tokens) > 2:
            tokens = tuple([el for el in self.subj_tokens if self.pattern.SUBJ_FUNCTION(el, self.subj_tokens)])

        subj_trace = ''.join(tuple([w.encode('utf-8') for w in tokens]))
        logger.debug('subj_trace : '+str(subj_trace))


        return binascii.crc32(subj_trace)

    def get_subject_len(self):

        return len(self.subj_tokens)

@Wrapper
class DmarcChecker(BaseChecker):
    '''

    '''
    def __init__(self, pattern_obj):
        BaseChecker.__init__(self, pattern_obj)

    def get_dmarc_spf(self):

        dmarc_spf = INIT_SCORE

        if self.msg.keys().count('Received-SPF') and re.match(r'^\s*pass\s+', self.msg.get('Received-SPF'), re.I):
            dmarc_spf += self.score

        return dmarc_spf

    def get_dmarc_score(self):

        #:param score:
        #:param dmarc_heads: list of headers, described in RFC 6376, RFC 7208
        #:return: <DMARC metrics dict>

        dmarc_score = INIT_SCORE

        # RFC 7001, this header has always to be included
        if self.msg.keys().count('Authentication-Results'):
            dmarc_score += self.score

        dmark_heads = [ 'Received-SPF', 'DKIM-Signature', 'DomainKey-Signature']
        found = [ head for head in self.msg.keys() if head in dmark_heads ]
        logger.debug('found_dmarc_headers : '+str(found))

        dmarc_score += len(found)*self.score

        return dmarc_score

    def get_dmarc_x_score(self):

        dmarc_x_score = len(filter(lambda h: re.match(r'X-DMARC(-.*)?', h, re.I), self.msg.keys()))
        #logger.debug('dmarc_x_score ==> '.upper()+str(dmarc_x_score))
        return dmarc_x_score

@Wrapper
class EmarketChecker(BaseChecker):

    '''
    1. simply checks just presense or absence of emarket-headers,
    which are typical for info/nets-email-patterns --> fills  get_emarket_score() attribute
    (typical pattern's emarket-headers names are defined in pattern_instance.EMARKET_HEADS) ;
    2. creates list of existed emarket-headers for current msg-instance ;
    3. checks values of existed emarket-headers with regexp from KNOWN_MAILERS --> fills get_emarket_flag() attribute;
    '''

    def __init__(self, pattern_obj):
        BaseChecker.__init__(self, pattern_obj)

    def __match(self) : lambda x,y: re.match(x, y, re.I)

    def get_emarket_score(self):

        emarket_heads_list = set([header for header in self.pattern.keys() if self.__match(self.pattern.EMARKET_HEADS, header)])
        return len(emarket_heads_list)*self.score

    def get_emarket_flag(self):

        emarket_flag = INIT_SCORE
        x_mailer_pattern = r'X-Mailer-.*'
        mailer_names = [mailer_head for mailer_head in self.pattern.keys() if self.__match(x_mailer_pattern, mailer_head)]

        if [mailer_name for mailer_name in mailer_names if filter(lambda reg: re.search(reg, self.pattern.get(mailer_name), re.I), self.pattern.KNOWN_MAILERS)]:
            emarket_flag = self.score

        return emarket_flag

    def get_emarket_domains_score(self):

        known_domains_score = INIT_SCORE
        # believe onlu domains from DKIM
        for domain_name in self.pattern.get_dkim_domains():
            known_domains_score += len(filter(lambda regexp: re.search(regexp, domain_name, re.I), self.pattern.KNOWN_DOMAINS))*self.score

        return known_domains_score


@Wrapper
class UrlChecker(BaseChecker):
    '''
    returned features values are depended from presense or absence of
    self.urls (URL list from msg body):
    if we don't have self.urls => @validator(UrlChecker) initialiases dummy UrlChecker,
    which will return BasePattern.INIT_SCORE for each method-attribute call
    '''

    def __init__(self, pattern_obj):

        BaseChecker.__init__(self, pattern_obj)

        self.urls = pattern_obj.get_url_obj_list()
        self.urls_domains = pattern_obj.get_net_location_list()

    def get_url_score(self):

        url_score = INIT_SCORE
        fqdn_reg_obj_list = get_regexp(self.pattern.URL_FQDN_REGEXP)
        txt_reg_obj_list = get_regexp(self.pattern.URL_TXT_REGEXP)


        for reg in fqdn_reg_obj_list:
            url_score += len([domain for domain in self.urls_domains if reg.search(domain.lower())])*self.score

        metainfo_list = list()
        for attr in ['path', 'query', 'fragment']:
            metainfo_list.extend([i.__getattribute__(attr) for i in self.urls])

        if metainfo_list:
            for reg in txt_reg_obj_list:
                url_score += len(filter(lambda metainfo: reg.search(metainfo.lower()), metainfo_list))*self.score

        return url_score

    def get_url_avg_len(self):
        # URL_AVG_LENGTH: they are short in general, cause of url-short services, etc

        # mostly thinking about shortened urls, created by tinyurl and other services,
        # but maybe this is weak feature
        logger.info('urls_domains list : '+str(self.urls_domains))
        logger.info('urls_domains list : '+str(len(self.urls_domains)))
        avg_len = INIT_SCORE

        if len(self.urls_domains) ==0:
            return avg_len

        avg_len = math.ceil(float(sum([len(s) for s in self.urls_domains]))/len(self.urls_domains))

        return avg_len

    def get_url_count(self):

        return len(self.urls)

    def get_url_distinct_count(self):

        return len(set([d.strip() for d in self.urls_domains]))

    def get_url_sender_count(self):

        sender_domain = False
        sender_count = INIT_SCORE
        while not (sender_domain):
            sender_domain = self.pattern.get_smtp_originator_domain()
            originator = self.pattern.get_addr_values(self.msg.get_all('From'))
            if not originator:
                return sender_count

            orig_name, orig_addr = reduce(add, originator)
            sender_domain = (orig_addr.split('@')[1]).strip()


            pattern = ur'\.?'+sender_domain.decode('utf-8')+u'(\.\w{2,10}){0,2}'
            sender_count += len(filter(lambda d: re.search(pattern, d.lower()), self.urls_domains))

        return sender_count

    def get_url_uppercase(self):
        #URL_UPPER: presense of elements in upper-case/title-case in URL


        uppercase = INIT_SCORE
        for method in [ unicode.isupper, unicode.istitle ]:
            uppercase += len(filter(lambda s: method(s), self.urls_domains))*self.score

        return uppercase

    def get_url_punicode(self):
        # PUNICORNS: respectively (very often for russian spams)
        logger.debug('Type of strs for PUNI :'+str([type(domain.encode()) for domain in self.urls_domains ]))
        my_little_puni = len([domain for domain in self.urls_domains if re.search(self.puni_regex, domain.encode(), re.I)])*self.score

        return my_little_puni

    def get_url_sim(self):
        similarity = INIT_SCORE

        for attr in ['path','query']:
            obj_list = [ url.__getattribute__(attr) for url in self.urls ]
            if math.ceil(float(len(set(obj_list)))/float(len(urls_list))) < self.score:
                similarity += self.score

        return similarity

    def get_url_avg_query_len(self):

        avg_query_len = INIT_SCORE
        lengthes_list = [ len(url.query) for url in self.urls ]
        if lengthes_list:
            avg_query_len = sum(lengthes_list)/len(lengthes_list)

        return avg_query_len

    def get_url_repetitions(self):
        # REPETITIONS: presense of repetitions like:

        repet_regex = ur'(https?:\/\/|www\.)\w{1,61}(\.\w{2,10}){1,5}'
        urls = [x.geturl() for x in self.urls]

        urls_with_repetitions = map(lambda url: re.findall(repet_regex, url.lower()), urls)
        repetitions = len([l for l in urls_with_repetitions if len(l)>1])*self.score

        return repetitions

    def get_url_query_absence(self):
        # alchemi again
        query_absence = INIT_SCORE
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

@Wrapper
class AttachesChecker(BaseChecker):

    '''
    1. checks attachements count ;
    2. get_attach_in_score() --> how many "inline" attachements (Content-Disposition attribute value),
    inlined mailicious attachements are very often in russian spams ;
    3. check attachments attribute "filename/name" with pattern.ATTACH_RULES;

    returned values are depended from pattern_obj.get_mime_struct().
    if it returns empty < mime_sctruct > dict --> @validator returns BasePattern.INIT_SCORE for each method-attribute call
    '''

    def __init__(self, pattern_obj):

        BaseChecker.__init__(self, pattern_obj)

        self.attach_rules = get_regexp(pattern_obj.ATTACHES_RULES)
        self.mime_struct = reduce(add, pattern_obj.get_mime_struct())
        self.attach_attrs = filter(lambda name: re.search(r'(file)?name([\*[:word:]]{1,2})?=.*',name), self.mime_struct)

    def get_attaches_count(self):

        logger.debug('MIME STRUCT >>>>>'+str(self.mime_struct)+'/n')
        attach_attrs = [( x.partition(';')[2]).strip('\r\n\x20') for x in self.attach_attrs ]

        return len(attach_attrs)

    def get_attaches_in_score(self):

        in_score = self.score*len(filter(lambda value: re.search(r'inline\s*;', value, re.I), self.mime_struct))
        return in_score

    def get_attaches_score(self):

        score = self.score*len(filter(lambda name: re.search(r'(file)?name(\*[0-9]{1,2}\*)=.*',name), self.attach_attrs))
        x = list()
        for regexp_obj in self.attach_rules:
            x.extend([value for value in self.attach_attrs if regexp_obj.search(value,re.M)])

        score += self.score*len(x)

        return score

@Wrapper
class ListChecker(BaseChecker):
    '''

    '''
    def __init__(self, pattern_obj):

        BaseChecker.__init__(self, pattern_obj)


    def __get_orig_addrs(self, heads_names):

        # msg.get_all cause email.utils.getaddresses(msg.get_all('From')) works properly only with list-type args !
        raw_values = [ self.msg.get_all(key) for key in heads_names if self.msg.get_all(key)]
        logger.debug(raw_values)
        self.parsed_addr_list = [self.pattern.get_addr_values(value) for value in raw_values ]

        return self.parsed_addr_list

    def get_list_score(self):

        #:return: penalizing score for List-* headers
        list_score = INIT_SCORE
        if not filter(lambda list_field: re.search('(List|Errors)(-.*)?', list_field), self.msg.keys()):
            return list_score

        # check Reply-To only with infos, cause it is very controversial,
        # here are only pure RFC 2369 checks
        # leave Errors-To cause all russian email-market players
        # put exactly Errors-To in their advertising emails instead of List-Unsubscribe
        rfc_heads = ['List-Unsubscribe', 'Errors-To', 'Sender']
        presented = [ head for head in rfc_heads if self.msg.keys().count(head) ]

        # alchemy, probably was written just for fun, e.g this body doesn't support RFC 2369 in a proper way ))
        list_score += (len(rfc_heads)-len(presented))*self.score

        #body_from = re.compile(r'@.*[a-z0-9]{1,63}\.[a-z]{2,4}')
        sender_domain = False
        while not (sender_domain):
            sender_domain = self.pattern.get_smtp_originator_domain()
            originator = self.pattern.get_addr_values(self.msg.get_all('From'))
            if not originator:
                return list_score

            orig_name, orig_addr = reduce(add, originator)
            sender_domain = (orig_addr.split('@')[1]).strip()


        patterns = [
                        r'https?:\/\/.*'+sender_domain+'\/.*(listinfo|unsub|email=).*', \
                        r'mailto:.*@.*\.'+sender_domain+'.*'
        ]

        for uri in [ heads_dict.get(head) for head in presented ]:
            if not filter(lambda reg: re.search(reg, uri, re.M), patterns):
                list_score += self.score

        return list_score

    def get_list_ext_headers_set(self):
        ext_heads =  get_regexp([r'(List|Errors)(-.*)?',r'X-(.*-){0,2}Complaints(-To)?', r'X-(.*-){0,2}(Report-)?Abuse'], re.I)
        found_ext_headers = list()
        for regexp_obj in ext_heads:
            found_ext_headers.extend([ head for head in self.msg.keys() if regexp_obj.match(head) ])

        return len(found_ext_headers)*self.score

    def get_list_sender_flag(self):
        sender_flag = INIT_SCORE
        # rfc 2369, 5322, but doesn't support rfc6854
        originators = set(map(itemgetter(1), self.__get_orig_addrs(['Sender','From'])))
        # get_addr_values() strips '<>' on boundaries for address values
        if len(originators) > 1:
            sender_flag += self.score

        return sender_flag

    def get_list_precedence(self):
        precedence_flag = INIT_SCORE
        if self.msg.get('Precedence').strip() == 'bulk':
            precedence_flag += self.score

        return precedence_flag

    def get_list_reply_to(self):
        reply_to_flag = INIT_SCORE
        originators = map(itemgetter(1), self.__get_orig_addrs(['Sender','Reply-To']))
        domains = set([ orig.partition('@')[2] for address in originators ])
        if len(set(domains)) == 1:
            reply_to_flag += self.score

        return reply_to_flag

    def get_list_delivered_to(self):
        # in general nets are very personal, so check Delivered-To may be a feature
        delivered_to_flag = INIT_SCORE
        values = [self.pattern.get_addr_values(self.msg.get_all(name)) for name in ['Delivered-To','To']]
        if len(set(values)) == 1 :
            delivered_to_flag += self.score

        return delivered_to_flag

@Wrapper
class OriginatorChecker(BaseChecker):
    '''
    Class keeps trigger-methods for describing
    originators values by following features:
    ORIG_CHECKSUM:
    ORIG_SCORE:
    '''
    def __init__(self, pattern_obj):

        BaseChecker.__init__(self, pattern_obj)
        logger.info('>>>>>>>>>>')
        self.name_addr_tuples = self.pattern.get_addr_values(self.msg.get_all('From'))
        logger.info('name_addr_tuples'.upper()+str(self.name_addr_tuples))
        name_addr = namedtuple('addr_value', 'realname address')

        self.name_addr_list = (name_addr(*pair) for pair in self.name_addr_tuples)

        self.localnames = [pair.address.partition('@')[0] for pair in self.name_addr_list]
        self.domains = [pair.address.partition('@')[2] for pair in self.name_addr_list]
        self.mailboxes = [pair.realname.lower() for pair in self.name_addr_list]

        logger.info('localnames : '+str(self.localnames))
        logger.info('domains : '+str(self.domains))
        logger.info('mailboxes : '+str(self.mailboxes))

    def get_originator_checksum(self):
        '''
        :return: ORIG_CHECKSUM from mailbox element
        of field value (From: <mail-box> <address>)
        # this trigger is inverse to get_list_sender_flag(), and they are slightly different
        '''

        from_checksum = INIT_SCORE
        # todo: rfc6854 support of new format lists for From: values

        logger.debug('\tFROM:----->'+str(self.name_addr_tuples))

        if len(self.name_addr_tuples) != 1:
            logger.warning('\t----->'+str(self.name_addr_tuples))

        if self.name_addr_tuples:
            from_value, from_addr = reduce(add, self.name_addr_tuples[:1])
            from_checksum = binascii.crc32(from_value.encode(self.pattern.DEFAULT_CHARSET))
            logger.debug('\t----->'+str(from_checksum))

        return from_checksum

    def get_originator_forged_sender(self):
        '''
        :return: set FORGET_SENDER_FLAG
        '''
        forget_sender_flag = INIT_SCORE

        #todo: rfc6854 support of new format lists for From: values
        if not filter(lambda list_field: re.search('(List|Errors)(-.*)?', list_field), self.pattern.msg.keys()):
            if self.msg.keys().count('Sender') and self.msg.keys().count('From'):
                forget_sender_flag = self.score
                # if we don't have List header, From value has to be the one (RFC 5322),
                # MUA didn't generate Sender field with the same name, cause of redundancy

        return forged_sender_flag

    def get_originator_addr_score(self):
        '''
        1. check with pattern regexps u'box_name', localname from address, domain from address
        2. some spam-heuristics for domains from address
        3. compare domain from From with smpt_domain

        gain and return ADDR_SCORE
        '''
        addr_score = INIT_SCORE

        reg_compiled_list = get_regexp(self.pattern.ORIGINATOR_LOCALNAMES_RULES)
        for localname in self.localnames:
            addr_score += len([regexp for regexp in reg_compiled_list if regexp.search(localname, re.I)])*self.score

            if len(localname) >= self.pattern.ORIGINATOR_LOCAL_NAME_LEN and localname.count('.') == 0 \
                and re.search(r'[\d-]',localname):
                addr_score += self.score

        box_names_regs = get_regexp(self.pattern.ORIGINATOR_MAILBOX_RULES)
        for box_name in self.mailboxes:
            addr_score += len([regexp for regexp in box_names_regs if regexp.search(box_name)])*self.score

        addr_score += len([domain for domain in self.domains if re.search(self.puni_regex, domain, re.I)])*self.score

        valid_domains = [domain for domain in self.domains if domain == self.pattern.get_smtp_originator_domain()]
        if not valid_domains:
            addr_score += self.score

        return addr_score


@Wrapper
class MimeChecker(BaseChecker):
    '''

    '''
    def __init__(self, pattern_obj):

        BaseChecker.__init__(self, pattern_obj)

    def get_mime_nest_level(self):

        mime_parts = self.pattern.get_mime_struct()
        mime_nest_level = len(filter(lambda n: re.search(r'(multipart|message)\/', n, re.I), mime_parts.keys()))

        return mime_nest_level

    def get_mime_checksum(self):

        '''
        self.EX_MIME_ATTRS_LIST: values of uninteresting mime-attrs
        :return: 42
        '''

        mime_checksum = self.INIT_SCORE
        logger.debug('excluded mime-header\'s attributes list from : '+str(self.__class__))
        logger.debug(self.EX_MIME_ATTRS_LIST)

        for prefix in self.EX_MIME_ATTRS_LIST:
            items = [[k, list(ifilterfalse(lambda x: x.startswith(prefix),v))] for k,v in self.pattern.get_mime_struct().items()]
            if items:
                items = reduce(add, items)

            mime_checksum = binascii.crc32(''.join([''.join(i) for i in items]))

        return mime_checksum

@Wrapper
class ContentChecker(BaseChecker):
    '''
    Class keeps trigger-methods for describing
    <mime>/text-parts content by following features:
    ORIG_CHECKSUM:
    TXT_SCORE: for plain/text, html/text parts
    '''
    def __init__(self, pattern_obj):

        BaseChecker.__init__(self, pattern_obj)

    def get_content_txt_score(self):
        '''
        Maps input regexp list to each sentence one by one
        :return: penalising score, gained by sentense
        '''

        regs_list = get_regexp(self.pattern.TEXT_REGEXP_LIST)
        sents_generator = self.pattern.get_sentences()

        txt_score = INIT_SCORE
        while(True):
            try:
                for reg_obj in regs_list:
                    #logger.info(l)
                    txt_score += len(filter(lambda s: reg_obj.search(s.lower()), next(sents_generator)))*self.score
                    #logger.debug("text_score: ".upper()+str(txt_score))
            except StopIteration as err:
                break

        return txt_score

    def get_content_html_score(self):

        #1. from the last text/html part creates HTML-body skeleton from end-tags,
        #    takes checksum from it, cause spammer's and info's/net's HTML patterns
        #    are mostly the same ;
        #2. if HTML-body includes table - analyze tags and values inside, cause
        #    info's and net's HTML-patterns mostly made up with pretty same <tables> ;

        #:param tags_map: expected <tags attribute="value">, described by regexes ;
        #:return: <penalizing score> and <checksum for body> ;
        html_score = INIT_SCORE
        attr_value_pair = namedtuple('attr_value_pair', 'name value')

        #logger.debug("tags_map: "+str(self.pattern.HTML_TAGS_MAP))

        soups_list = self.pattern.get_html_parts()

        while(True):
            try:
                soup = next(soups_list)
            except StopIteration as err:
                return html_score

                if not soup.body.table:
                    continue

                # analyze tags and their attributes
                soup_attrs_list = filter(lambda y: y, [ x.attrs.items() for x in soup.body.table.findAll(tag) ])
                logger.debug(soup_attrs_list)
                logger.debug('soup_attrs_list '+str(soup_attrs_list))
                if not soup_attrs_list:
                    continue

                soup_attrs_list = [ attr_value_pair(*obj) for obj in reduce(add, soup_attrs_list) ]
                logger.debug(soup_attrs_list)
                logger.debug('type of parsing line in reg_obj: '+str(type(self.pattern.HTML_TAGS_MAP[tag])))
                compiled_regexp_list = get_regexp(self.pattern.HTML_TAGS_MAP.get[tag], re.U)

                pairs = list()
                for key_attr in compiled_regexp_list: # expected_attrs_dict:
                    #logger.debug(key_attr)
                    pairs = filter(lambda pair: key_attr.match(pair.name.lower()), soup_attrs_list)
                    #logger.debug(pairs)

                    check_values = list()
                    if pairs:
                        check_values = filter(lambda pair: re.search(ur''+expected_attrs_dict.get(key_attr), pair.value.lower()), soup_attrs_list)
                        html_score += self.score*len(check_values)

        return html_score

    def get_content_html_checksum(self):

        html_skeleton = list()
        soups_list = self.pattern.get_html_parts()

        for s in tuple(soups_list):
            body_line = s.body.lower()
            # get table checksum
            comments = s.body.findAll( text=lambda text: isinstance(text, Comment) )
            [comment.extract() for comment in comments]
            # leave only closing tags struct
            reg = re.compile(ur'<[a-z]*/[a-z]*>')
            # todo: investigate the order of elems within included generators
            html_skeleton.extend(t.encode('utf-8', errors='replace') for t in tuple(reg.findall(body_line.prettify(), re.M)))

        html_checksum = binascii.crc32(''.join(html_skeleton))

        return html_checksum

    def get_content_avg_entropy(self):

        #for fun
        #:return:

        n = 0
        txt_avg_ent = INIT_SCORE
        # todo: make n-grams
        for tokens in self.pattern.get_stemmed_tokens():
            n +=1
            freqdist = FreqDist(tokens)
            probs = [freqdist.freq(l) for l in FreqDist(tokens)]
            #logger.debug('P >>> '+str(probs))
            txt_avg_ent += -sum([p * math.log(p,2) for p in probs])

        txt_avg_ent = txt_avg_ent/n

        return txt_avg_ent

    def get_content_compress_ratio(self):

        #maybe
        #:return: compress ratio of stemmed text-strings from
        #all text/mime-parts

        txt_compressed_ratio = INIT_SCORE
        all_text_parts = list(self.pattern.get_stemmed_tokens())
        #for x in all_text_parts:
            #logger.debug('>>>> '+str(x))
        if all_text_parts:
            all_text = ''.join(reduce(add, all_text_parts))
            #logger.debug(type(all_text))
            txt_compressed_ratio = float(len(zlib.compress(all_text.encode(self.pattern.DEFAULT_CHARSET))))/len(all_text)

        return txt_compressed_ratio


if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)
