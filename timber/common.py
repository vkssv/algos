# -*- coding: utf-8 -*-
'''
shared module with common-used functions, will be class in future
'''

import email, os, sys, re, logging, binascii, unicodedata, urlparse

from email.errors import MessageParseError
from email.header import decode_header
from operator import add, itemgetter
from collections import Counter, OrderedDict
from itertools import ifilterfalse

from pattern_wrapper import BasePattern
INIT_SCORE = BasePattern.INIT_SCORE
MIN_TOKEN_LEN = BasePattern.MIN_TOKEN_LEN

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

# just for debugging new regexp on fly
def get_regexp(regexp_list, compilation_flag=0):
    compiled_list = []

    for exp in regexp_list:
        logger.debug(exp)
        if compilation_flag:
            exp = re.compile(exp, compilation_flag)
        else:
            exp = re.compile(exp)

        compiled_list.append(exp)

    return(compiled_list)

# excluded_list=['Received', 'From', 'Date', 'X-.*']
# header_value_list = [(header1,value1),...(headerN, valueN)] = msg.items() - save the order of heads
def get_all_heads_crc(header_value_list, excluded_list = None):

    vect = dict.fromkeys(['heads_crc','values_crc'])
    logger.debug("header_value_list >>"+str(header_value_list))
    heads_vector = tuple(map(itemgetter(0), header_value_list))
    heads_dict = dict(header_value_list)

    if excluded_list:
        for ex_head in excluded_list:
            # can use match - no new lines in r_name
            heads_vector = tuple(filter(lambda h_name: not re.match(ex_head, h_name, re.I), heads_vector[:]))

    values_vector = tuple([heads_dict.get(k) for k in heads_vector])
    #logger.debug('values_vector'+str(values_vector))
    # save the last word
    values_vector = tuple([value.split()[-1:] for value in values_vector[:]])
    #logger.debug('values_vector --->'+str(values_vector))

    vect['heads_crc'] = binascii.crc32(''.join(heads_vector))
    vect['values_crc'] = binascii.crc32(''.join(reduce(add,values_vector)))

    return (vect)

def get_mime_crc(mime_skeleton_dict, excluded_args_list=['boundary=','charset=']):

    checksum = 0
    logger.debug('EXL:'+str(excluded_args_list))

    items = mime_skeleton_dict.items()

    for prefix in excluded_args_list:
        items = [[k, list(ifilterfalse(lambda x: x.startswith(prefix),v))] for k,v in items]

    if items:
        items = reduce(add,items)
        checksum = binascii.crc32(''.join([''.join(i) for i in items]))

    return(checksum)

def get_trace_crc(rcvds_vect):

    #logger.debug('rcvds_vect:'+str(rcvds_vect))
    traces_dict = {}

    for rcvd_line, n in zip(rcvds_vect, range(len(rcvds_vect))):
        #logger.debug(rcvd_line)
        trace = map(lambda x: rcvd_line.replace(x,''),['from','by',' '])[2]
        trace = trace.strip().lower()
        trace = binascii.crc32(trace)

        traces_dict['rcvd_'+str(n)] = trace

    return (traces_dict)

def get_addr_values(head_value=''):
    logger.debug('+++++>'+str(head_value))
    for_crunch = re.compile(r'[\w\.-_]{1,64}@[a-z0-9-]{1,63}(?:\.[\w]{2,4})+',re.I)

    h_value = tuple(decode_header(head_value))
    # don't use encoding info for translations, so don't keep it
    h_value = tuple([pair[0] for pair in h_value])
    logger.debug('+++++'+str(h_value))
    # crunch addreses and names
    addrs=[]
    names = []
    for part in h_value:
        logger.debug('part  '+str(part))
        part = re.sub(r'<|>','',part)
        logger.debug(str(part))
        addrs += for_crunch.findall(part)
        logger.debug(str(addrs))
        names.append(for_crunch.sub('',part))

    #logger.debug('names: '+str(names))

    # keep order => use tuples, + cause function should works
    # either for To/CC/Bcc headers with many senders,
    # or for From/Sender
    # names are raw encoded strings
    return(tuple(names),tuple(addrs))

def get_smtp_domain(rcvds):
# get sender domain from the first (by trace) RCVD-field, e.g. SMTP MAIL FROM: value


    regexp = re.compile(r'(@|(?<=helo)\s?=\s?|(?<=from)\s+)?([a-z0-9-]{1,60}\.){1,3}[a-z]{2,10}', re.M)
    orig_domain = ''

    l = filter(lambda value: regexp.search(value), rcvds)
    if l:
        orig_domain = reduce(add,l)
        print('+++++++++++++++++++++++++++++++++++++++')
        print((orig_domain,))
        orig_domain = (regexp.search(orig_domain)).group(0)
        orig_domain = orig_domain.strip('.').strip('@').strip('=').strip()
        print('ORIG_DOMAINS: '+str(orig_domain))

    return(orig_domain)

def get_subject(subj_line,token_len = MIN_TOKEN_LEN):

    logger.debug('SUBJ_LINE: >'+str(subj_line)+'<')
    subj_parts = decode_header(subj_line)
    logger.debug('parts >>>>>'+str(subj_parts))
    subj = u''
    encodings_list = []
    for p in subj_parts:
        logger.debug(p)
        line, encoding = p
        logger.debug('enc:'+str(encoding))
        logger.debug(line)
        if encoding:
            line = line.decode(encoding,'replace')
            encodings_list.append(encoding)
        else:
            try:
                line = line.decode('utf-8')
                encodings_list.append('utf-8')
            except UnicodeDecodeError as err:
                logger.warning('Can\'t decode Subject\'s part: "'+line+'", it will be skipped.')
                continue

        subj+=line
    # force decode to utf

    words_list = tuple(subj.split())
    # remove short tockens
    words_list = filter(lambda s: len(s)>token_len, words_list[:])
    if not encodings_list:
        encodings_list = ['ascii']

    return(unicodedata.normalize('NFC',subj), words_list, encodings_list)

def basic_headers_cheker(head_pattern, known_mailers, header_value_list, score):

    typical_heads_score = INIT_SCORE
    known_mailer_flag = INIT_SCORE
    headers_list = [i[0] for i in header_value_list]

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
def basic_subjects_checker(line_in_unicode, regexes, score):

    # check by regexp rules
    total_score = INIT_SCORE
    logger.debug('line: '+line_in_unicode)
    line = re.sub(ur'[\\\|\/\*]', '', line_in_unicode)
    logger.debug('line after: '+line_in_unicode)

    # for debug purposes:
    regs = get_regexp(regexes)

    #regexes = [re.compile(exp) for exp in regexes]
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
    smtp_to_list = filter(lambda x: x, tuple([(r.partition('for')[2]).strip() for r in parsed_rcvds]))
    if not smtp_to_list:
        return(rcpt_score)

    logger.debug(">>smtp_to_list: "+str(smtp_to_list))
    smtp_to = re.search(r'<(.*@.*)?>', smtp_to_list[0])

    if to_addrs and smtp_to and smtp_to.group(0) == to_addrs[0]:
        rcpt_score+= score


    return(rcpt_score)

def basic_url_checker(parsed_links_list, rcvds, score, domain_regs, regs):
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

    print("NETLOC: >>>>>"+str(netloc_list))


    sender_domain = get_smtp_domain(rcvds)
    pattern = ur'\.?'+sender_domain.decode('utf-8')+u'(\.\w{2,10}){0,2}'

    # url_score, distinct_count, sender_count
    if netloc_list:
        domain_regs = get_regexp(domain_regs, re.I)

        for reg in domain_regs:
            basic_features['url_score'] += len(filter(lambda netloc: reg.search(netloc), netloc_list))*score

        basic_features['distinct_count'] += len(set([d.strip() for d in netloc_list]))
        basic_features['sender_count'] += len(filter(lambda d: re.search(pattern, d, re.I), netloc_list))

    # url_score
    metainfo_list = []
    for attr in ['path', 'query', 'fragment']:
        metainfo_list.extend([i.__getattribute__(attr) for i in parsed_links_list])

    if metainfo_list:
        regs = get_regexp(regs, re.I)
        for reg in regs:
            basic_features['url_score'] += len(filter(lambda metainfo: reg.search(metainfo), metainfo_list))*score

    return(dict(basic_features), netloc_list)

#def basic_html_checker():


def basic_body_checker():
    # THE LAST!!!!!!!!!!!
    pass



























