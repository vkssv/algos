'''
shared module with common-used functions, will be class in future
'''

import email, os, sys, re, logging, binascii

from email.errors import MessageParseError
from email.header import decode_header
from operator import add


logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

# excluded_list=['Received', 'From', 'Date', 'X-.*']
# header_value_list = [(header1,value1),...(headerN, valueN)] = msg.items() - save the order of heads
def get_heads_crc(header_value_list, excluded_list = None):

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

def get_addr_fields(head_value=''):

    for_crunch = re.compile(r'[\w\.-_]{1,64}@[a-z0-9]{1,63}(?:\.[\w]{2,4})+')

    h_value = tuple(decode_header(head_value))
    # don't use encoding info for translations, so don't keep it
    h_value = tuple([pair[0] for pair in h_value[:]])
    # crunch addreses and names
    addrs=[]
    names = []
    for part in h_value:
        part = re.sub(r'<|>','',part)
        addrs += for_crunch.findall(part)
        names += for_crunch.sub('',part)

    # keep order
    return(tuple(names),tuple(addrs))

def get_mime_info(msg):

    mime_heads = ['content-type','content-transfer-encoding','content-id','content-disposition']

    mime_parts=[]
    for part in msg.walk():
        all_heads = [name.lower() for name in part.keys()]

        part_dict = {}
        for head in filter(lambda n: all_heads.count(n), mime_heads):
            part_dict[head] = part.get_all(head)

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

def basic_attach_checker(mime_heads,reg_list,score):

    score = 0

    mime_heads = reduce( add,reduce(add,[dict.values() for dict in mime_heads[:]] ))
    attach_attrs = filter(lambda name: re.search(r'(file)?name(\*[0-9]{1,2}\*)?=.*;',name),mime_heads)
    attach_attrs = [(x.partition(';')[2]).strip('\r\n\x20') for x in attach_attrs]
    attach_count = len(attach_attrs)

    attach_score += score*len(filter(lambda name: re.search(r'(file)?name(\*[0-9]{1,2}\*)=.*;',name),attach_attrs))


    for exp in [re.compile(r,re.I) for r in reg_list]:
        x = filter(lambda value: exp.search(value,re.M), attach_attrs)
        score += score*len(x)

    inline_pattern = r'inline\s*;'
    inline_score = score*len(filter(lambda value: re.search(inline_pattern,value,re.I), mime_heads))

    return(attach_count,score,inline_score)



# returns score + crc32 trace
def basic_subjects_checker(heads_dict, regex_list, len_threshold, score):
    #print(regex_list)
    total_score = 0

    # unconditional spams without Subject header at all or with empty Subj value are still in traffic
    if not heads_dict.get('Subject'):
        return (score, 0)

    subj_parts = tuple(map(lambda part: part[0].strip(), decode_header(heads_dict.get('Subject'))))

    # check total len
    if sum(map(lambda w: len(w), subj_parts)) >= len_threshold:
        total_score += score

    # for RFC 5322 checks
    prefix_heads_map = {
                            'RE' : ['In-Reply-To', 'Thread(-.*)?', 'References'],
                            'FW' : ['(X-)?Forward']
    }

    subj_trace = ''

    for p in subj_parts:
        #print('part:'+'--'+p+'--')
        # check if is empty
        if not len(p) and len(subj_parts) == 1:
            total_score += score
            break

        elif not len(p):
            continue

        # only for latin, check if subj has uppercase words
        if len(filter(lambda word: word.isupper(), p.split())) > 0:
            total_score += score

        # RFC 5322 checks, usually user's modern MUAs try to follow standards
        matched_list = map(lambda prefix: re.search(prefix, p, re.I), [r'^\s*Re\s*(?=:)', r'^\s*Fwd?\s*(?=:)'])
        #print ('matched_list:'+str(matched_list))
        matched_list = filter(lambda obj: obj, matched_list)
        #print ('matched_list:'+str(matched_list))
        if matched_list:
            keys = [obj.group(0) for obj in matched_list]
            keys = [k.strip('d').upper() for k in keys]
            #print(keys)

            values = [prefix_heads_map.get(k) for k in keys]
            #print(values)
            correlated = reduce(add,values)

            for regexp_name in correlated:
                if not filter(lambda name: re.search(regexp_name, name, re.I), heads_dict.keys()):
                    total_score += score

        # check the presence of strong tokens for unconditional in filtered
        # and unfiltered lines (works only for US-ASCII and UTF8)
        filtered_line = re.sub(re.sub('[\\\/\s]','',p)
        for s in [p,filtered_line]:
            matched = filter(lambda r: re.search(r, s, re.I), regex_list)
            total_score += score*len(matched)

        # keep the last two word for making crc32 trace (??)
        words = tuple(p.split())
        subj_trace += words[-1:][0]

    subj_trace = binascii.crc32(subj_trace)

    return (total_score, subj_trace)

def basic_lists_checker(header_value_list, score):
    # very weak for spam cause all url from 'List-Unsubscribe','Errors-To','Reply-To'
    # have to be checking with antiphishing service
    unsubscribe_score = 0

    for_trace = re.compile(r'\.[a-z0-9]{1,63}\.[a-z]{2,4}\s+',re.M)
    for_body_from = re.compile(r'@.*[a-z0-9]{1,63}\.[a-z]{2,4}')

    #print('\t=====>'+str(header_value_list))
    heads_dict = { key: value for (key, value) in header_value_list }

    # try to get sender domain from RCVD headers, use header_value_list to obtain
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

def basic_bodies_checks():
















