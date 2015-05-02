# -*- coding: utf-8 -*-
'''
    -Classes with rules for email headers and MIME-parts ;
    -Returned values of attribute-methods (which representing rules)
        are depended from pattern_obj sctructure ;
    -@Wrapper returns BasePattern.INIT_SCORE for each method-attribute call,
        in case of exceptions ;
'''

import sys, os, logging, re, binascii, zlib, math, string, urlparse

from operator import add, itemgetter
from collections import namedtuple
from itertools import ifilterfalse

from pattern_wrapper import BasePattern
from decorators import Wrapper
from timber_exceptions import NaturesError

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
#logger.setLevel(logging.DEBUG)


class BaseChecker(object):
    '''
    keeps and share between heirs
    basic objects from Pattern classes
    '''
    puni_regex = r'xn--[0-9a-z-]+(\.xn--[0-9a-z]+){1,3}'
    def_encoding = 'utf8'
    err_handling = 'replace'

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

        self.obj = pattern_obj
        self.subj_line, self.subj_tokens, self.encodings_list = pattern_obj.get_decoded_subj()
        self.subj_line = self.subj_line.lower()
        #logger.debug(type(self.subj_line))
        self.subj_rules = get_regexp(pattern_obj.SUBJ_RULES)

        #logger.debug(u'subj_line.lower(): '+self.subj_line)
        #logger.debug('subj_tokens: '+str(self.subj_tokens))
        #logger.debug('subj_encodings: '+str(self.encodings_list))

    def get_subject_score(self):

        #logger.debug(self.subj_line.lower())
        subj_score = INIT_SCORE

        for rule in self.subj_rules:
            if rule.search(self.subj_line):
                subj_score +=self.score*self.obj.AXIS_STRETCH

        #logger.debug('score:'+str(subj_score))

        prefix_heads_map = {
                                'RE' : ['(In-)?Reply-To', 'Thread(-.*)?', 'References'],
                                'FW' : ['(X-)?Forward'],
                                'TR' : ['(X-)?Forward'] # for french MUA
        }

        for k in prefix_heads_map.iterkeys():
            #logger.debug(self.subj_line.encode(self.def_encoding, errors=self.err_handling))
            if re.match(r''+k+'\s*:', self.subj_line.encode(self.def_encoding, errors=self.err_handling), re.I):
                heads_list = prefix_heads_map.get(k)

                for h_name in self.msg.keys():
                    found_heads = filter(lambda reg: re.match(reg, h_name, re.I), h_name)
                    subj_score += (len(prefix_heads_map.get(k)) - len(found_heads))*self.score
                    #logger.debug('score:'+str(subj_score))

        #logger.debug('score:'+str(subj_score))
        return subj_score

    def get_subject_encoding(self):

        return len(set(self.encodings_list))

    def get_subject_upper(self):
        #logger.debug(self.subj_tokens)

        return len([w for w in self.subj_tokens if w.isupper()])

    def get_subject_titled(self):
        #logger.debug(self.subj_tokens)

        return len([w for w in self.subj_tokens if w.istitle()])


    def get_subject_checksum(self):

        # take crc32, make line only from words selected by pattern.SUBJ_FUNCTION, not all
        tokens = self.subj_tokens
        if len(tokens) > 2:

            if self.obj.__str__() == 'SPAM':
                tokens = tuple( el for el in tokens if tokens.index(el)%2 )

            elif self.obj.__str__() == 'INFO':
                tokens = tokens[len(tokens)/2:]

        subj_trace = ''.join(tuple([w.encode(self.def_encoding, errors=self.err_handling) for w in tokens]))
        #logger.debug('subj_trace : '+str(subj_trace))

        return binascii.crc32(subj_trace)

    def get_subject_len(self):

        return len(self.subj_tokens)

@Wrapper
class DmarcChecker(BaseChecker):
    '''
    vectorize DMARC-related headers values by
    following feature set :

    DMARC_SPF      --> gained by checking 'Received-SPF' header value ;
    DMARC_SCORE    --> gained by checking the presence of 'Authentication-Results',
                        'DKIM-Signature', 'DomainKey-Signature' ;
    DMARC_X_SCORE  --> gained by checking the presence of additional 'X-DMARC-*'
                        headers ;
    '''
    def __init__(self, pattern_obj):
        BaseChecker.__init__(self, pattern_obj)

    def get_dmarc_spf(self):

        dmarc_spf = INIT_SCORE

        if self.msg.keys().count('Received-SPF') and re.match(r'^\s*pass\s+', self.msg.get('Received-SPF'), re.I):
            dmarc_spf += self.score

        return dmarc_spf

    def get_dmarc_score(self):

        dmarc_score = INIT_SCORE

        # RFC 7001, this header has always to be included
        if self.msg.keys().count('Authentication-Results'):
            dmarc_score += self.score

        dmark_heads = [ 'Received-SPF', 'DKIM-Signature', 'DomainKey-Signature']
        found = [ head for head in self.msg.keys() if head in dmark_heads ]
        #logger.debug('found_dmarc_headers : '+str(found))

        dmarc_score += len(found)*self.score

        return dmarc_score

    def get_dmarc_x_score(self):

        dmarc_x_score = len(filter(lambda h: re.match(r'X-DMARC(-.*)?', h, re.I), self.msg.keys()))
        #logger.debug('dmarc_x_score ==> '.upper()+str(dmarc_x_score))
        return dmarc_x_score

@Wrapper
class EmarketChecker(BaseChecker):

    '''
    vectorize EMARKET-specific headers values by
    following feature set :

    SCORE               --> gained by checking presense or absence of specific emarket-headers,
                            they are typical for info/nets-email-patterns ;
    EMARKET_FLAG        --> set if values of existed emarket-headers contain KNOWN_MAILERS names;
    KNOWN_DOMAINS_SCORE --> gained if domain value from 'DKIM-*' headers matches with list
                            of well-known SN-domains (Facebook, Google+, etc) ;
    '''

    def __init__(self, pattern_obj):
        BaseChecker.__init__(self, pattern_obj)

    def get_emarket_score(self):

        #logger.debug(self.pattern.EMARKET_HEADS)

        emarket_heads_list = set( [ header for header in self.msg.keys() if re.search(self.pattern.EMARKET_HEADS, header, re.I) ] )
        #logger.debug(emarket_heads_list)

        return len(emarket_heads_list)*self.score

    def get_emarket_flag(self):

        emarket_flag = INIT_SCORE
        x_mailer_pattern = r'X-Mailer-.*'
        mailer_names = [mailer_head for mailer_head in self.msg.keys() if re.search(x_mailer_pattern, mailer_head, re.I)]

        #logger.debug(mailer_names)
        #logger.debug(self.pattern.KNOWN_MAILERS)

        for mailer_name in mailer_names:
            if [pattern for pattern in self.pattern.KNOWN_MAILERS if re.search(pattern, self.msg.get(mailer_name), re.I)]:
                emarket_flag = self.score
                #logger.debug(emarket_flag)

        return emarket_flag

    def get_emarket_domains_score(self):

        known_domains_score = INIT_SCORE
        #logger.debug(self.pattern.KNOWN_DOMAINS)

        for domain_name in self.pattern.get_dkim_domains():
            #logger.debug(domain_name)
            known_domains_score += len(filter(lambda regexp: re.search(regexp, domain_name, re.I), self.pattern.KNOWN_DOMAINS))*self.score

        #logger.debug(known_domains_score)
        return known_domains_score


@Wrapper
class UrlChecker(BaseChecker):
    '''
    keeps trigger-methods for describing
    URLs from emails bodies by following features:

    SCORE           --> gained by checking each urlprse object with
                        list of regexp for domain-part and query-part,
                        regexp are defined in each particular pattern ;
    AVG_LENGTH      --> maybe usefull, cause often in spams URLS are short
                        in general, cause of url-short services, etc ;
    COUNT           --> 42 ;
    DISTINCT_COUNT  --> count of different domains in domain-parts of URLs,
                        for legitime emails it's usually not very big ;
    SENDER_COUNT    --> presence of smtp-originator domain in domain-parts of URLs ;
    UPPER_CASE      --> presense of elements in upper-case/title-case ;
    PUNCODE         --> prsence of punicode ;
    SIM             --> count of urls with same queries or pathes ;
    AVG_QUERY_LEN   --> avg query length for grabbed URLs list ;
    REPETITIONS     --> presence of repetitions in domain-part ;
    QUERY_ABSENCE   --> absence of query (only domain part or path or urlparse error :)) ;
    '''

    def __init__(self, pattern_obj):

        BaseChecker.__init__(self, pattern_obj)

        self.urls = pattern_obj.get_url_obj_list()
        self.urls_domains = pattern_obj.get_net_location_list()

    def get_url_score(self):

        url_score = INIT_SCORE
        if len(self.urls_domains) == 0:
            return url_score

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

        #logger.debug('urls_domains list : '+str(self.urls_domains))
        #logger.debug('urls_domains list : '+str(len(self.urls_domains)))

        avg_len = INIT_SCORE

        if len(self.urls_domains) == 0:
            return avg_len

        avg_len = math.ceil(float(sum([len(s) for s in self.urls_domains]))/len(self.urls_domains))

        return avg_len

    def get_url_count(self):

        return len(self.urls)

    def get_url_distinct_count(self):

        return len(set([d.strip() for d in self.urls_domains]))

    def get_url_sender_count(self):
        '''
        if found sender domain in url --> email slightly nets or infos
        if not found sender domain in url --> email is closer to spam or ham
        '''

        sender_domain = False
        sender_count = INIT_SCORE

        if len(self.urls_domains) == 0:
            return sender_count

        while not (sender_domain):
            sender_domain = self.pattern.get_smtp_originator_domain()
            #logger.debug('sender domain :'+str(sender_domain))

            originator = self.pattern.get_addr_values(self.msg.get_all('From'))
            #logger.debug('sender domain :'+str(originator))
            if not originator:
                return sender_count

            orig_name, orig_addr = reduce(add, originator)
            #logger.debug('originator address: '+str(orig_addr))
            if orig_addr.count('@') == 0:
                return sender_count

            sender_domain = (orig_addr.split('@')[1]).strip()
            sender_domain = (sender_domain.decode(self.def_encoding, self.err_handling)).lower()
            #logger.debug('sender_domain:'+str(sender_domain))

            pattern = ur'\.?'+sender_domain+u'(\.\w{2,10}){0,2}'
            sender_count += len(filter(lambda d: re.search(pattern, d.lower()), self.urls_domains))

            if not sender_count and self.pattern.__str__() in ['SPAM', 'HAM']:
                sender_count += self.score

        return sender_count

    def get_url_uppercase(self):

        uppercase = INIT_SCORE
        for method in [ unicode.isupper, unicode.istitle ]:
            uppercase += len(filter(lambda s: method(s), self.urls_domains))*self.score

        return uppercase

    def get_url_punicode(self):

        decoded = [domain.encode(self.def_encoding, self.err_handling) for domain in self.urls_domains]

        return len([domain for domain in decoded if re.search(self.puni_regex, domain, re.I)])*self.score

    def get_url_sim(self):

        similarity = INIT_SCORE
        if len(self.urls) == 0:
            return similarity

        for attr in ['path', 'query']:
            obj_list = [ url.__getattribute__(attr) for url in self.urls ]
            if math.ceil(float(len(set(obj_list)))/float(len(self.urls))) < self.score:
                similarity += self.score

        return similarity

    def get_url_avg_query_len(self):

        avg_query_len = INIT_SCORE
        lengthes_list = [ len(url.query) for url in self.urls ]
        if lengthes_list:
            avg_query_len = sum(lengthes_list)/len(lengthes_list)

        return avg_query_len

    def get_url_repetitions(self):

        repetitions = INIT_SCORE
        if len(self.urls) == 0:
            return repetitions

        repet_regex = ur'(https?:\/\/|www\.)\w{1,61}(\.\w{2,10}){1,5}'
        urls = [x.geturl() for x in self.urls]

        urls_with_repetitions = map(lambda url: re.findall(repet_regex, url.lower()), urls)
        repetitions = len([l for l in urls_with_repetitions if len(l)>1])*self.score

        return repetitions

    def get_url_query_absence(self):

        query_absence = INIT_SCORE
        if len(self.urls) == 0:
            return query_absence

        q_list = [u.query for u in self.urls]
        queries_count = float(len(filter(lambda line: line, [ u.query for u in self.urls ])))
        if math.floor(queries_count/float(len(self.urls))) == 0.0:
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
    keeps trigger-methods for describing
    attachements by following features:

    -COUNT    --> 42 ;
    -IN_SCORE --> count of inline attachements ;
    -SCORE    --> gained by applying regexp list from Pattern to attachements attributes ;
    '''

    def __init__(self, pattern_obj):

        BaseChecker.__init__(self, pattern_obj)

        self.mime_struct = pattern_obj.get_mime_struct()
        if len(self.mime_struct) == 0:
            attributes = list()
            #logger.warn('\tProbably, this email is not multipart, or can\'t parse it properly !')

        attributes = reduce(add, self.mime_struct.values())
        self.attributes = [v.strip() for v in attributes]
        self.attach_attrs = [x for x in attributes if x.startswith('attachment')]

    def get_attaches_count(self):
        '''
        checks attachements count
        '''
        return len(self.attach_attrs)

    def get_attaches_in_score(self):
        '''
        checks how many "inline" attachements (Content-Disposition attribute value),
        inlined mailicious attachements are very often in russian spams ;
        '''
        in_score = [x for x in self.attributes if x.startswith('inline')]

        return len(in_score)*self.score

    def get_attaches_score(self):
        '''
        checks attachments attribute "filename/name"
        with pattern.ATTACH_RULES;
        '''
        score = INIT_SCORE

        for line in self.attach_attrs:
            if filter(lambda x: re.search(x, line, re.I), self.pattern.ATTACHES_RULES):
                score += self.score

        return score

@Wrapper
class ListChecker(BaseChecker):
    '''
    keeps trigger-methods for describing
    'List-*' headers values by following features:

    LIST_SCORE          --> gained by checking values of 'List-*'
                                headers and presence of correlated
                                headers (see RFC for List) ;
    EXT_LIST_SCORE      --> check presence of different headers, mentioned in RFC 2369 ;
    PRECEDENCE_FLAG     --> check presence of 'Precedense' header ;
    REPLY_TO_FLAG       --> check value of 'Reply-To:' header ;
    SENDER_FLAG         --> check value of 'Sender:' header ;
    DELIVERED_TO_FLAG   --> check value of 'Delivered-To:' header, if it is presented ;
    '''
    def __init__(self, pattern_obj):

        BaseChecker.__init__(self, pattern_obj)

        self.decoded_values = dict()
        for h in ['Sender','From','Reply-To']:
            if not self.msg.get_all(h):
                self.decoded_values[h] = ((u'',''),)
            else:
                self.decoded_values[h] = self.pattern.get_addr_values(self.msg.get_all(h))

        #logger.debug(self.decoded_values)

    def get_list_score(self):
        '''
        :return: penalizing score for List-* headers
        '''

        list_score = INIT_SCORE
        if not filter(lambda list_field: re.search('(List|Errors)(-.*)?', list_field), self.msg.keys()):
            return list_score

        rfc_heads = ['List-Unsubscribe', 'Errors-To', 'Sender']
        presented = [ head for head in rfc_heads if self.msg.keys().count(head) ]

        list_score += (len(rfc_heads)-len(presented))*self.score

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

        for uri in [ self.msg.get(head) for head in presented ]:
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
        x = [self.decoded_values[name] for name in ['From','Sender']]
        if not x:
            return sender_flag
        x = reduce(add,x)
        originators = set(map(itemgetter(1), x))
        # get_addr_values() strips '<>' on boundaries for address values
        #logger.debug(originators)
        if len(originators) > 1:
            sender_flag += self.score

        return sender_flag

    def get_list_precedence(self):
        precedence_flag = INIT_SCORE
        if self.msg.get('Precedence') and self.msg.get('Precedence').strip() == 'bulk':
            precedence_flag += self.score

        return precedence_flag

    def get_list_reply_to(self):
        reply_to_flag = INIT_SCORE
        x = [self.decoded_values[name] for name in ['From','Sender']]
        if not x:
            return sender_flag
        x = reduce(add,x)
        originators = set(map(itemgetter(1), x))
        domains = set([ address.partition('@')[2] for address in originators ])
        if len(set(domains)) == 1:
            reply_to_flag += self.score

        return reply_to_flag

    def get_list_delivered_to(self):
        # in general nets are very personal, so check Delivered-To may be a feature
        delivered_to_flag = INIT_SCORE
        for name in ['Delivered-To','To']:
            value = self.msg.get_all(name)
            if not value:
                return delivered_to_flag

            pairs = self.pattern.get_addr_values(value)

        if len(set(pairs)) == 1 :
            delivered_to_flag += self.score

        return delivered_to_flag

@Wrapper
class OriginatorChecker(BaseChecker):
    '''
    keeps trigger-methods for describing
    originators values by following features:

    ORIG_CHECKSUM       --> crc32-checksum from mailbox element, 'From' header value ;
    ORIG_SCORE          --> gained by mailbox element and address by applied to them
                            regexes from patterns + compare sender domain with
                            smtp-originator domain ;
    FORGET_SENDER_FLAG  --> check whether 'Sender' header is redundant or not ;
    '''
    def __init__(self, pattern_obj):

        BaseChecker.__init__(self, pattern_obj)

        self.obj = pattern_obj
        self.name_addr_tuples = self.pattern.get_addr_values(self.msg.get_all('From'))

        name_addr = namedtuple('addr_value', 'realname address')
        self.name_addr_list = (name_addr(*pair) for pair in self.name_addr_tuples)

        self.localnames = [pair.address.partition('@')[0] for pair in self.name_addr_list]
        self.domains = [pair.address.partition('@')[2] for pair in self.name_addr_list]
        self.mailboxes = [pair.realname.lower() for pair in self.name_addr_list]

        #logger.debug('localnames : '+str(self.localnames))
        #logger.debug('domains : '+str(self.domains))
        #logger.debug('mailboxes : '+str(self.mailboxes))
        #logger.debug('name_addr_list : '+str(self.name_addr_list))

    def get_originator_checksum(self):
        '''
        :return: crc32 from mailbox element
                    of field value (From: <mail-box> <address>)

        this trigger is inverse to get_list_sender_flag(), and they are slightly different
        '''

        from_checksum = INIT_SCORE
        # todo: rfc6854 support of new format lists for From: values

        if self.name_addr_tuples:
            from_value, from_addr = reduce(add, self.name_addr_tuples[:1])
            from_checksum = binascii.crc32(from_value.encode(self.def_encoding, self.err_handling))

        #logger.debug(from_checksum)
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
        check with pattern regexps u'box_name'
        and localname from address

        :return ADDR_SCORE
        '''
        addr_score = INIT_SCORE

        reg_compiled_list = get_regexp(self.pattern.ORIGINATOR_LOCALNAMES_RULES)
        for localname in self.localnames:
            addr_score += len([regexp for regexp in reg_compiled_list if regexp.search(localname, re.I)])*self.score

        #logger.debug('reg_compiled_list :'+str(addr_score))

        box_names_regs = get_regexp(self.pattern.ORIGINATOR_MAILBOX_RULES)
        for box_name in self.mailboxes:
            addr_score += len([regexp for regexp in box_names_regs if regexp.search(box_name)])*self.score

        #logger.debug('box_list :'+str(addr_score))


    def get_originator_punicode(self):
        '''
        check domain from address with punicode regexp

        :return P_FLAG
        '''
        p_flag = INIT_SCORE

        punicode = [domain for domain in self.domains if re.search(self.puni_regex, domain, re.I)]
        if punicode:
            p_flag = self.score


        return p_flag

    def get_originator_domain_score(self):
        '''
        check that domain from address is equal to originator domain from SMTP MAIL FROM:
        return DOM_SCORE
        '''
        dom_score = INIT_SCORE
        valid_domains = [domain for domain in self.domains if re.search(domain, self.pattern.get_smtp_originator_domain())]

        if valid_domains and self.obj.__str__() == 'HAM':
            dom_score += self.score

        return dom_score

@Wrapper
class MimeChecker(BaseChecker):
    '''
    keeps trigger-methods for describing
    bodies MIME-sctructures with following
    features :

    MIME_NEST_LEVEL --> 42 ;
    MIME_CHECKSUM   --> crc32-checksum from sequence of Content-Type values
                            for each MIME-part in multipart-body, obtain some
                            kind of skeleton of email and keep it in checksum ;
    '''
    def __init__(self, pattern_obj):

        BaseChecker.__init__(self, pattern_obj)

    def get_mime_nest_level(self):

        mime_parts = self.pattern.get_mime_struct()
        mime_nest_level = len(filter(lambda n: re.search(r'(multipart|message)\/', n, re.I), mime_parts.keys()))

        return mime_nest_level

    def get_mime_checksum(self):

        # EX_MIME_ATTRS_LIST: values of uninteresting mime-attrs
        mime_checksum = self.INIT_SCORE
        #logger.debug('excluded mime-header\'s attributes list from : '+str(self.__class__))
        #logger.debug(self.EX_MIME_ATTRS_LIST)

        for prefix in self.EX_MIME_ATTRS_LIST:
            items = [[k, list(ifilterfalse(lambda x: x.startswith(prefix),v))] for k,v in self.pattern.get_mime_struct().items()]
            if items:
                items = reduce(add, items)

            mime_checksum = binascii.crc32(''.join([''.join(i) for i in items]))

        return mime_checksum

@Wrapper
class ContentChecker(BaseChecker):
    '''
    keeps trigger-methods for describing
    text/<mime>-parts content by following features:

        -HTML_SCORE             - score, gained by checking html-tags structures ;
        -TXT_SCORE              - score, gained by checking tokens sequences from text/<mime> parts ;
        -HTML_CHECKSUM          - crc32-checksum from enclosing html-table
                                    (because html-emails mostly contain old-style make-up,
                                    where all elements are stored in one enclosing table) ;
        -TXT_AVG_ENTROPY        - avg entropy of mime-parts or text-part, if email isn't multipart ;
        -TXT_COMPRESSION_RATIO  - compression ratio, if we zip all mime-parts from one email or just text
                                    string, if email isn't multipart ;

    '''
    def __init__(self, pattern_obj):

        BaseChecker.__init__(self, pattern_obj)

    def get_content_txt_score(self):
        '''
        maps regexp list from suitable Pattern Class
        to each sentence one by one

        :return: penalising score, gained by all
        sentenses from body
        '''

        regs_list = get_regexp(self.pattern.TEXT_REGEXP_LIST)
        #logger.debug(tuple(self.pattern.get_sentences()))

        sents_generator = self.pattern.get_sentences()
        txt_score = INIT_SCORE

        # parses in very accurate way, try to get the maximum from each line
        while(True):
            try:
                sentences = next(sents_generator)

                for sentence in sentences:
                    lines = sentence.split('\n')
                    lines = [ line for line in lines if len(line.strip())>0 ]

                    for reg_obj in regs_list:
                        if [ el for el in lines if reg_obj.search(el.strip()) ]:
                            txt_score += self.score*self.pattern.AXIS_STRETCH
                            #logger.debug("text_score: "+str(txt_score))

            except StopIteration as err:
                break

        return txt_score

    def get_content_html_checksum(self):
        '''
        from the last text/html part creates HTML-body skeleton from end-tags,
        returns crc32-checksum from it, cause spammer's and info's/net's HTML patterns
        are very similar ;

        :return: 42
        '''
        html_checksum = INIT_SCORE
        html_skeleton = list()
        soups_list = tuple(self.pattern.get_html_parts())

        for s in soups_list:
            body_line = s.body
            # get table checksum
            comments = body_line.findAll( text=lambda text: isinstance(text, Comment) )
            [comment.extract() for comment in comments]

            # leave only closing tags struct
            reg = re.compile(ur'<[a-z]*/[a-z]*>')
            body_line = (body_line.prettify()).lower()
            t = tuple(reg.findall(body_line, re.M))

            html_skeleton.append(tuple(x.encode(self.def_encoding, errors=self.err_handling) for x in t))
            #logger.debug(html_skeleton)

        if html_skeleton:
            html_checksum = reduce(add, html_skeleton)
            html_checksum = binascii.crc32(''.join(html_checksum))

        return html_checksum

    def get_content_avg_entropy(self):
        '''
        :return: avg entropy of text/<mime> parts for multipart bodies
        '''
        n = 0
        txt_avg_ent = INIT_SCORE
        # todo: make n-grams
        tokens_list = tuple(self.pattern.get_stemmed_tokens())
        #logger.debug(tokens_list)

        for tokens in tokens_list:
            #logger.debug(tokens)
            n +=1
            freqdist = FreqDist(tokens)
            probs = [freqdist.freq(l) for l in FreqDist(tokens)]
            txt_avg_ent += -sum([p * math.log(p,2) for p in probs])
            #logger.debug(n)

        # :))
        if n !=0:
            txt_avg_ent = txt_avg_ent/n

        return txt_avg_ent

    def get_content_compress_ratio(self):
        '''
        :return: compress ratio of stemmed text-strings from all text/mime-parts
        '''

        txt_compressed_ratio = INIT_SCORE
        all_text_parts = list(self.pattern.get_stemmed_tokens())

        if all_text_parts:
            x = reduce(add, all_text_parts)
            #logger.debug(str(x))
            all_text = ''.join(x)
            txt_compressed_ratio = float(len(zlib.compress(all_text.encode(self.def_encoding, self.err_handling))))/len(all_text)

        return txt_compressed_ratio

