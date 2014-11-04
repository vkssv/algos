# -*- coding: utf-8 -*-
'''
shared module with common-used functions, will be class in future
'''

import email, os, sys, re, logging, binascii, unicodedata

from email.errors import MessageParseError
from email.header import decode_header
from operator import add

from pattern_wrapper import BasePattern
INIT_SCORE = BasePattern.INIT_SCORE
MIN_TOKEN_LEN = BasePattern.MIN_TOKEN_LEN

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

# excluded_list=['Received', 'From', 'Date', 'X-.*']
# header_value_list = [(header1,value1),...(headerN, valueN)] = msg.items() - save the order of heads
def get_all_heads_crc(header_value_list, excluded_list = None):

    vect = dict.fromkeys(['heads_crc','values_crc'])
    heads_vector = tuple([item[0] for item in header_value_list])
    heads_dict = {key: value for (key, value) in header_value_list}

    if excluded_list:
        for ex_head in excluded_list:
            # can use match - no new lines in r_name
            heads_vector = tuple(filter(lambda h_name: not re.match(ex_head, h_name, re.I), heads_vector[:]))

    values_vector = tuple([heads_dict.get(k) for k in heads_vector])
    #print('values_vector'+str(values_vector))
    # save the last word
    values_vector = tuple([value.split()[-1:] for value in values_vector[:]])
    #print('values_vector --->'+str(values_vector))

    vect['heads_crc'] = binascii.crc32(''.join(heads_vector))
    vect['values_crc'] = binascii.crc32(''.join(reduce(add,values_vector)))

    return (vect)

def get_trace_crc(rcvds_vect):

    #print('rcvds_vect:'+str(rcvds_vect))
    traces_dict = {}

    for rcvd_line, n in zip(rcvds_vect, range(len(rcvds_vect))):
        #print(rcvd_line)
        trace = map(lambda x: rcvd_line.replace(x,''),['from','by',' '])[2]
        trace = trace.strip().lower()
        trace = binascii.crc32(trace)

        traces_dict['rcvd_'+str(n)] = trace

    return (traces_dict)

def get_addr_values(head_value=''):
    print('+++++>'+str(head_value))
    for_crunch = re.compile(r'[\w\.-_]{1,64}@[a-z0-9-]{1,63}(?:\.[\w]{2,4})+',re.I)

    h_value = tuple(decode_header(head_value))
    print(h_value)
    # don't use encoding info for translations, so don't keep it
    h_value = tuple([pair[0] for pair in h_value])
    print('+++++'+str(h_value))
    # crunch addreses and names
    addrs=[]
    names = []
    for part in h_value:
        print('part  '+str(part))
        part = re.sub(r'<|>','',part)
        print(part)
        addrs += for_crunch.findall(part)
        print(addrs)
        names.append(for_crunch.sub('',part))

    #print('names: '+str(names))

    # keep order => use tuples, + cause function should works
    # either for To/CC/Bcc headers with many senders,
    # or for From/Sender
    # names are raw encoded strings
    return(tuple(names),tuple(addrs))


def get_mime_info(msg):

    mime_heads = ['content-type','content-transfer-encoding','content-id','content-disposition']

    mime_parts=[]
    for part in msg.walk():

        all_heads = [name.lower() for name in part.keys()]
        #print(all_heads)

        part_dict = {}
        for head in filter(lambda n: all_heads.count(n), mime_heads):
            part_dict[head] = part.get_all(head)
        if len(part_dict) == 0:
            continue

        mime_parts.append(part_dict)

    return(tuple(mime_parts))


def get_mime_structure_crc(mime_info):
    all_content_types = tuple(reduce(add,[dict.get('content-type') for dict in mime_info]))
    line = ''.join([l.partition(';')[0] for l in all_content_types])

    return(binascii.crc32(line))

def get_nest_level(mime_info):
    all_content_types = reduce(add,[dict.get('content-type') for dict in mime_info])
    all_content_types = [x.partition(';')[0] for x in all_content_types]
    level = len(filter(lambda n: re.search(r'(multipart|message)\/',n,re.I),all_content_types))

    return(level)


def get_subject(subj_line,token_len = MIN_TOKEN_LEN):

    subj_parts = decode_header(subj_line)
    subj = u''
    encodings_list = []
    for p in subj_parts:
        print(p)
        line, encoding = p
        print('enc:'+str(encoding))
        if encoding:
            line = line.decode(encoding)
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

def basic_attach_checker(mime_heads,reg_list,score):

    attach_score = INIT_SCORE

    mime_heads = reduce(add, reduce(add,[dict.values() for dict in mime_heads[:]]))
    attach_attrs = filter(lambda name: re.search(r'(file)?name(\*[0-9]{1,2}\*)?=.*;',name),mime_heads)
    attach_attrs = [(x.partition(';')[2]).strip('\r\n\x20') for x in attach_attrs]
    attach_count = len(attach_attrs)

    attach_score += score*len(filter(lambda name: re.search(r'(file)?name(\*[0-9]{1,2}\*)=.*;',name),attach_attrs))


    for exp in [re.compile(r,re.I) for r in reg_list]:
        x = filter(lambda value: exp.search(value,re.M), attach_attrs)
        score += score*len(x)

    inline_pattern = r'inline\s*;'
    inline_score = score*len(filter(lambda value: re.search(inline_pattern,value,re.I), mime_heads))

    return(attach_count, score, inline_score)

# returns score
def basic_subjects_checker(line_in_unicode, regexes, score):

    # check by regexp rules
    total_score = INIT_SCORE
    print('line: '+line_in_unicode)
    line = re.sub(ur'[\\\|\/\*]', '', line_in_unicode)
    print('line after: '+line_in_unicode)
    # for debug purposes:
    regs = []
    for exp in regexes:
        logger.debug(exp)
        exp = re.compile(exp)
        regs.append(exp)

    #regexes = [re.compile(exp) for exp in regexes]
    matched = filter(lambda r: r.search(line, re.I), regs)
    print(matched)
    total_score += score*len(matched)

    words = [w for w in line.split()]

    upper_flag = len(filter(lambda w: w.isupper(),words))
    title_flag = len(filter(lambda w: w.isupper(),words))

    return (total_score, upper_flag, title_flag)

def basic_lists_checker(header_value_list, score):
    # very weak for spam cause all url from 'List-Unsubscribe','Errors-To','Reply-To'
    # have to be checked with antiphishing service
    unsubscribe_score = INIT_SCORE

    for_trace = re.compile(r'\.[a-z0-9]{1,63}\.[a-z]{2,4}\s+',re.M)
    for_body_from = re.compile(r'@.*[a-z0-9]{1,63}\.[a-z]{2,4}')

    #print('\t=====>'+str(header_value_list))
    heads_dict = dict(header_value_list)

    # try to get sender domain from RCVD headers,
    # use header_value_list to obtain
    # exactly the first rcvd header, order makes sense here
    h_name, value = (filter(lambda rcvd: re.match('Received', rcvd[0]), header_value_list))[-1:][0]
    #print('h_name'+h_name)
    #print('value'+value)

    sender_domain = ''
    if for_trace.search(value.partition(';')[0]):
        sender_domain = (for_trace.search(value.partition(';')[0])).group(0)
        sender_domain = sender_domain.strip('.').strip()

    elif for_body_from.search(heads_dict.get('From')):
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
    rfc_heads = ['List-Unsubscribe','Errors-To', 'Sender']

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
    print(dmarc_dict)
    dkim_domain = ''
    heads_dict = dict(header_value_list)

    # according to RFC 7001, this header has to be included
    if not (heads_dict.keys()).count('Authentication-Results'):
        return(dmarc_dict, dkim_domain)

    total = []
    for h in dmarc_dict.iterkeys():
        dkims = filter(lambda z: re.search(h, z), heads_dict.keys())
        total.extend(dkims)

    print('TOTAL:'+str(total))

    # (len(required_heads_list)+1, cause we can find DKIM-Signature and DomainKey-Signature in one doc
    print('req_head:'+str(len(required_heads_list)+1))
    #print('req_head:'+str(len(required_heads_list)+1))
    print('found:'+str(len(set(total))*score))

    basic_score = (len(required_heads_list)+1) - (len(set(total))*score)

    # simple checks for Received-SPF and DKIM/DomainKey-Signature
    if heads_dict.keys().count('Received-SPF') and re.match(r'^\s*pass\s+', heads_dict.get('Received-SPF'), re.I):
        dmarc_dict['Received-SPF'] += score

    # check domain names in From and DKIM-headers (but now it's probably redundant)
    from_domain = (heads_dict.get('From')).partition('@')[2]
    from_domain = from_domain.strip('>').strip()

    dkim_domain=''
    print('dkims'+str(dkims))
    valid_lines = filter(lambda f: re.search(from_domain,f), [heads_dict.get(h) for h in dkims])
    if len(valid_lines) == len(dkims):
        dmarc_dict['(DKIM|DomainKey)-Signature'] += score
        dkim_domain = from_domain
        print('dkim_domain '+str(dkim_domain))

    return(dmarc_dict, dkim_domain)

# TODO: add support the comparation of addrs vectors,
# so now in general in commercial infos only one rcpt in To field
# but in software email-discussions there are always many rcpts in To !
def basic_rcpts_checker(score, traces_values_list, to_values_list):

    rcpt_score = INIT_SCORE

    to_values, to_addrs = get_addr_values(to_values_list)
    print(">>to_addrs: "+str(to_addrs))
    parsed_rcvds = [rcvd.partition(';')[0] for rcvd in traces_values_list]
    smtp_to_list = filter(lambda x: x, tuple([(r.partition('for')[2]).strip() for r in parsed_rcvds]))
    if not smtp_to_list:
        return(rcpt_score)

    print(">>smtp_to_list: "+str(smtp_to_list))
    smtp_to = re.search(r'<(.*@.*)?>', smtp_to_list[0])

    if to_addrs and smtp_to and smtp_to.group(0) == to_addrs[0]:
        rcpt_score+= score


    return(rcpt_score)



















