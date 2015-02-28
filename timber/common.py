# -*- coding: utf-8 -*-
"""
shared module with common-used functions,
maybe, will became a separate class in future
"""

import os, sys, re, logging, binascii, unicodedata, urlparse

from email.header import decode_header
from operator import add, itemgetter
from collections import Counter, OrderedDict, namedtuple
from itertools import ifilterfalse

try:
    from bs4 import BeautifulSoup
except ImportError:
    print('Can\'t find bs4 module, probably, it isn\'t installed.')
    print('try: "easy_install beautifulsoup4" or install package "python-beautifulsoup4"')

from pattern_wrapper import BasePattern

INIT_SCORE = BasePattern.INIT_SCORE
MIN_TOKEN_LEN = BasePattern.MIN_TOKEN_LEN

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

def basic_headers_cheker(head_pattern, known_mailers, header_value_list, score):

    typical_heads_score = INIT_SCORE
    known_mailer_flag = INIT_SCORE
    header = namedtuple('header','name value')

    header_value_list = [header(*pair) for pair in header_value_list]
    headers_list = [i.name for i in header_value_list]

    emarket_heads = set(filter(lambda header: re.match(head_pattern, header, re.I), headers_list))
    typical_heads_score += len(emarket_heads)*score

    mailer_header = ''.join(filter(lambda h: re.match(r'^x-mailer$', h, re.I), headers_list))


    if dict(header_value_list).get(mailer_header):
        x_mailer =  dict(header_value_list).get(mailer_header)
        if filter(lambda reg: re.search(reg, x_mailer, re.I), known_mailers):
            known_mailer_flag = score

    return(typical_heads_score, known_mailer_flag)

def basic_attach_checker(mime_parts_list, reg_list, score):

    # mime_parts_list - list with mime-parts dictionaries
    attach_score = INIT_SCORE

    mime_values_list = reduce(add, mime_parts_list)
    attach_attrs = filter(lambda name: re.search(r'(file)?name([\*[:word:]]{1,2})?=.*',name), mime_values_list)
    attach_attrs = [(x.partition(';')[2]).strip('\r\n\x20') for x in attach_attrs]
    attach_count = len(attach_attrs)

    attach_score += score*len(filter(lambda name: re.search(r'(file)?name(\*[0-9]{1,2}\*)=.*',name), attach_attrs))


    for exp in [re.compile(r,re.I) for r in reg_list]:
        x = filter(lambda value: exp.search(value,re.M), attach_attrs)
        score += score*len(x)

    inline_score = score*len(filter(lambda value: re.search(r'inline\s*;', value, re.I), mime_values_list))

    return(attach_count, score, inline_score)

# returns score
def basic_subjects_checker(line_in_unicode, subj_regs, score):

    # check by regexp rules
    total_score = INIT_SCORE
    logger.debug('line: '+line_in_unicode)
    line = re.sub(ur'[\\\|\/\*]', '', line_in_unicode)
    logger.debug('line after: '+line_in_unicode)


    regs = BasePattern._get_regexp_(subj_regs, re.U)
    matched = filter(lambda r: r.search(line, re.I), regs)
    logger.debug(str(matched))
    total_score += score*len(matched)

    words = [w for w in line.split()]

    upper_words_count = len(filter(lambda w: w.isupper(),words))
    title_words_count = len(filter(lambda w: w.istitle(),words))

    return (total_score, upper_words_count, title_words_count)

def basic_lists_checker(header_value_list, rcvds, score):
    # very weak for spam cause all url from 'List-Unsubscribe','Errors-To','Reply-To'
    # have to be checked with antiphishing service
    unsubscribe_score = INIT_SCORE
    body_from = re.compile(r'@.*[a-z0-9]{1,63}\.[a-z]{2,4}')

    #logger.debug('\t=====>'+str(header_value_list))
    heads_dict = dict(header_value_list)

    # try to get sender domain from RCVD headers,
    # use header_value_list to obtain
    # exactly the first rcvd header,
    # order makes sense here

    sender_domain = get_smtp_domain(rcvds)
    if not sender_domain:
        body_from.search(heads_dict.get('From'))
        # try to get it from From: header value
        sender_domain = (for_body_from.search(heads_dict.get('From'))).group(0)
        sender_domain = sender_domain.strip('@')

    patterns = [
                    r'https?:\/\/.*'+sender_domain+'\/.*(listinfo|unsub|email=).*', \
                    r'mailto:.*@.*\.'+sender_domain+'.*'
    ]

    # check Reply-To only with infos, very controversial, here are only pure RFC 2369 checks
    # leave Errors-To cause all russian authorized email market players
    # rather put exactly Errors-To in their infos instead of List-Unsubscribe
    rfc_heads = ['List-Unsubscribe', 'Errors-To', 'Sender']

    presented = filter(lambda h: (heads_dict.keys()).count(h), rfc_heads)
    # doesn't support RFC 2369 in a proper way
    unsubscribe_score += (len(rfc_heads)-len(presented))*score

    if not presented:
        return (unsubscribe_score)

    for uri in [heads_dict.get(head) for head in presented]:
        if not filter(lambda reg: re.search(reg, uri, re.M), patterns):
            unsubscribe_score += score

    return (unsubscribe_score)

def basic_dmarc_checker(header_value_list, score, required_heads_list=[]):

    if not required_heads_list:

        required_heads = ['Received-SPF','(DKIM|DomainKey)-Signature']

    dmarc_dict = dict(map(lambda x,y: (x,y),required_heads,[INIT_SCORE]*len(required_heads)))
    logger.debug(str(dmarc_dict))
    dkim_domain = ''
    heads_dict = dict(header_value_list)

    # according to RFC 7001, this header has to be included
    if not (heads_dict.keys()).count('Authentication-Results'):
        return(dmarc_dict, dkim_domain)

    total = []
    for h in dmarc_dict.iterkeys():
        dkims = filter(lambda z: re.search(h, z), heads_dict.keys())
        total.extend(dkims)

    logger.debug('TOTAL:'+str(total))

    # (len(required_heads_list)+1, cause we can find DKIM-Signature and DomainKey-Signature in one doc
    logger.debug('req_head:'+str(len(required_heads_list)+1))
    #logger.debug('req_head:'+str(len(required_heads_list)+1))
    logger.debug('found:'+str(len(set(total))*score))

    basic_score = (len(required_heads_list)+1) - (len(set(total))*score)

    # simple checks for Received-SPF and DKIM/DomainKey-Signature
    if heads_dict.keys().count('Received-SPF') and re.match(r'^\s*pass\s+', heads_dict.get('Received-SPF'), re.I):
        dmarc_dict['Received-SPF'] += score

    # check domain names in From and DKIM-headers (but now it's probably redundant)
    from_domain = (heads_dict.get('From')).partition('@')[2]
    from_domain = from_domain.strip('>').strip()

    dkim_domain=''
    logger.debug('dkims'+str(dkims))
    valid_lines = filter(lambda f: re.search(from_domain,f), [heads_dict.get(h) for h in dkims])
    if len(valid_lines) == len(dkims):
        dmarc_dict['(DKIM|DomainKey)-Signature'] += score
        dkim_domain = from_domain
        logger.debug('dkim_domain '+str(dkim_domain))

    return(dmarc_dict, dkim_domain)

# TODO: add support the comparation of addrs vectors,
# so now in general in commercial infos only one rcpt in To field
# but in software email-discussions there are always many rcpts in To !
def basic_rcpts_checker(score, traces_values_list, to_values_list):

    rcpt_score = INIT_SCORE

    to_values, to_addrs = get_addr_values(to_values_list)
    logger.debug(">>to_addrs: "+str(to_addrs))
    parsed_rcvds = [rcvd.partition(';')[0] for rcvd in traces_values_list]
    # todo: check - maybe not need list
    smtp_to_list = filter(lambda x: x, tuple([(r.partition('for')[2]).strip() for r in parsed_rcvds]))
    if not smtp_to_list:
        return(rcpt_score)

    logger.debug(">>smtp_to_list: "+str(smtp_to_list))
    smtp_to = re.search(r'<(.*@.*)?>', smtp_to_list[0])

    if to_addrs and smtp_to and smtp_to.group(0) == to_addrs[0]:
        rcpt_score+= score


    return(rcpt_score)

def basic_url_checker(parsed_links_list, rcvds, score, domain_regs, text_regs):
    # domain_regs, regs - lists of compiled RE objects
    logger.debug('our list: '+str(parsed_links_list))

    basics = ['url_count', 'url_score', 'distinct_count', 'sender_count']
    basic_features = Counter(map(lambda x,y: (x,y), basics, [INIT_SCORE]*len(basics)))
    # URL_COUNT: url count for infos and nets maybe lies in certain boundaries, \
    # cause they are generated by certain patterns  ));
    # URL_SCORE: score, which will be earned during regexp-checks for different parts of parsed URLs;
    # DISTINCT_COUNT: count of different domains from netlocation parts of URLs;
    # SENDER_COUNT: count of domains/subdomains from netlocation parts of URLs,
    # which are the same with sender domain from RCVD-headers.

    # url_count
    basic_features['url_count'] = len(parsed_links_list)

    netloc_list = []
    for url in parsed_links_list:
        if url.netloc:
            netloc_list.append(url.netloc)
            continue
        elif url.path:
            netloc_list.append(url.path.strip('www.'))
            continue

    netloc_list = filter(lambda d: d, netloc_list)
    only_str_obj = filter(lambda i: type(i) is str, netloc_list)

    if only_str_obj:
        only_str_obj  = [i.decode('utf8') for i in only_str_obj]
        netloc_list = only_str_obj + filter(lambda i: type(i) is unicode, netloc_list)

    #print("NETLOC: >>>>>"+str(netloc_list))

    sender_domain = get_smtp_domain(rcvds)
    pattern = ur'\.?'+sender_domain.decode('utf-8')+u'(\.\w{2,10}){0,2}'

    # url_score, distinct_count, sender_count
    reg = namedtuple('reg', 'for_dom_pt for_txt_pt')
    compiled = reg(*(BasePattern._get_regexp_(l, re.I) for l in (domain_regs, text_regs)))

    if netloc_list:

        for reg in compiled.for_dom_pt:
            basic_features['url_score'] += len(filter(lambda netloc: reg.search(netloc), netloc_list))*score

        basic_features['distinct_count'] += len(set([d.strip() for d in netloc_list]))
        basic_features['sender_count'] += len(filter(lambda d: re.search(pattern, d, re.I), netloc_list))

    # url_score
    metainfo_list = []
    for attr in ['path', 'query', 'fragment']:
        metainfo_list.extend([i.__getattribute__(attr) for i in parsed_links_list])

    if metainfo_list:
        for reg in compiled.for_txt_pt:
            basic_features['url_score'] += len(filter(lambda metainfo: reg.search(metainfo), metainfo_list))*score

    return(dict(basic_features), netloc_list)

































