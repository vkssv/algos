'''
shared module with common-used functions
'''

import email, os, sys, re, logging

from email.errors import MessageParseError
from email.header import decode_header
from operator import add

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

def get_body_skeleton(msg):

    body_skeleton={}
    for part in msg.walk():
        body_skeleton[part.get_content_type()]=part.get_filename()

    if not len(body_skeleton.keys()):
        raise MessageParseError

    else:
        logger.debug("SKELETON: "+str(body_skeleton))

    return(body_skeleton)


def get_heads_crc(excluded_list=[],heads_vector,without_X=False):

	# exclude common headers like Received, From, Date or X-*, etc, if needed
	if excluded_list:
		heads_vector = tuple(filter(lambda h: not excluded_heads.count(h),heads_vector[:]))

	elif without_X:
		heads_vector = tuple(filter(lambda h: not h.startswith('X'),heads_vector[:]))

	elif excluded_list and without_X:
		heads_vector = tuple(filter(lambda h: not ( h.startswith('X') or excluded_heads.count(h)), heads_vector[:]))

	crc32 = binascii.crc32(''.join(heads_vector))

	return(crc32)

def remove_noise_str(str):

	return(re.sub('[\[\]\\\/\^\.&$#~`"\=@',:;\|\?\*\+\(\)\{\}\s]','',str))

def check_suspect_heads(heads_dict, sus_tokens_dict, score):
	'''''
		sus_tokens_dict = {'head_name': ([regexp_list],score)}
		heads_dict = {'head_name':'value'}
	'''''

	scores_dict = {}
	for key in sus_tokens_dict.iterkeys():

		value = heads_dict.get(key)
		if not with_noise:
			value = remove_noise_str(value)
		logger.debug(value)

		scores_dict[head] = 0.0
		if filter(lambda reg: re.search(reg,value,re.I), regs_list):
			scores_dict[head] = score_dict.get(head)+score

        logger.debug (score_dict[head])

    return (scores.dict)

# take first n RCVD headers from bottom, extracts gateways names and IP's, normilize
# and get CRC32, use tuples for keeping order
def parse_trace_fields(msg,n=0):

	rcvd_values = tuple(msg.get_all('Received'))[-1*n:]
	rcvds_vect = tuple([rcvd.partition(';')[0] for rcvd in rcvd_values[:]])

	return(rcvds_vect)

def smtp_trace_crc(rcvds_vect,regs_list):

	traces_dict={}

	for rcvd, n in zip(rcvds_vect, range(len(rcvds_vect))):

		trace = ''

		temp = tuple(map(lambda x: re.search(x,rcvd,re.I),regs_list))
		trace = ''.join([item.group(0).strip() for item in temp])
		trace = binascii.crc32(trace)

		traces_dict['rcvd_'+n] = trace

	return(traces_dict)

def check_subject(headers_list,regex_list):

	total_score = 0

	l = filter(lambda pair: pair[0]=='Subject',headers_list, subject_len_trashold, score)
	if len(l) > 2:
		total_score += score*len(l)
		# never go here, but in case for funny msg with 2 Subjects add them extra penalty?
		# well, I'd use this trick if I'd send spam, MUA shows the first Subj (usually maden to keep users attention) and the second
		# with good strong tockens to reduce the total score, poisoning the desicion matrix for instance

	header_name, value = l[0]
	subj_parts = tuple(map(lambda part: part[0].strip(),decode_header(value)))

	# check total len
	if sum(map(lambda w: len(w),subj_parts)) > subject_len_trashold:
		total_score += score

	# for RFC 5322 checks
	correlated_heads = {
							'Re'    : ['In-Reply-To', '(X-)?Thread(-.*)?', '(X-)?References'],
							'Fwd'   : ['(X-)?Forward'],
	                        'Fw'    : ['(X-)?Forward']
						}

	subj_trace = ''

	for p in subj_parts:
		# check if is empty
		if not len(p) and len(subj_parts)==1:
			total_score += score
			break

		elif not len(p):
			continue

		# check if subj has uppercase words
		if len(filter(lambda word: word.isupper(),p.split())) > 0:
			total_score += score

		# RFC 5322 checks, usually user's MUA try to follow standards
		matched_list = map(lambda prefix: re.search(prefix,p,re.I),['^\s+Re\s+:','^\s+Fw(d)+\s+:'])
		matched_list = filter(lambda obj: obj,matched_list)
		keys = [obj.group(0) for obj in matched_list]

		correlated = reduce(add, [correlated_heads.get(k) for k in keys])
		h_names = [item[0] for item in msg.items()]

		for regexp_name in correlated:
			if not filter(lambda head_name: re.search(regexp_name,name,re.I), h_names):
				total_score += score

		# check the presence of strong tokens for unconditional
		matched = filter(lambda r: re.search(r,p,re.I),regex_list)
		if matched:
			total_score += score*len(matched)

		# keep the last two word for making crc32 trace (??)
		words = tuple(p.split())
		subj_trace += words[-1:][0]

	subj_trace = binascii.crc32(subj_trace)

	return(total_score,subj_trace)

def get_senders(msg):

    senders = dict.fromkeys(('From','Sender','Reply-To'))
	fr_field = msg.get('From:')
		if not fr_field:
			return(None,None)

	parts_list = fr_field.split()

	sender_addr_list = filter(lambda sender_inits: re.search('<(.*@.*)?>',sender_inits,re.I),parts_list)

	sender_name_list = filter(lambda sender_inits: not re.search('<(.*@.*)?>',sender_inits,re.I),parts_list)
	if sender_name_list:
		sender_name =[decode_header(part) for part in sender_name_list]

	# return structure ([(part, encoding)],<address>)
	return(sender_name,sender_addr[0])

def get_rcpts(msg):

	to_field = msg.get('To:')
		if not to_field:
			return(None,None)

	parts_list = [obj.strip() for obj in msg.get('To').split(',')]
	parts_list = sum([p.split() for p in parts_list],[])

	rcpt_addr_list = filter(lambda rcpt: re.search('<(.*@.*)?>',rcpt,re.I),parts_list)

	rcpt_name_list = filter(lambda sender_inits: not re.search('<(.*@.*)?>',sender_inits,re.I),parts_list)
	rcpt_name_list = [rcpt.strip('"') for rcpt in rcpt_name_list]
	if rcpt_name_list:
		rcpt_names =[decode_header(part) for part in rcpt_name_list]

	return(rcpt_names,rcpt_addr_list)

def check_lists(msg,score):

	unsubscribe_score = 0

	for required in [ 'List-Unsubscribe','Sender','Reply-To']:
		if not (msg.keys()).count(required):
			unsubscribe_score += score

	if heads_list.count('List-Unsubscribe'):

		uri_list = re.findall('<.*?>',msg.get('List-Unsubscribe'),re.I)
		if not uri_list:
			return(unsubscribe_score += score) # never go here

		from_value = get_from_value(msg)
		if not from_value:
			return(unsubscribe_score += score)

		name, addr = from_value
		sender_domain = re.match('@((?!-)[a-z0-9-\.]{1,63}(?<!-))+(\.[a-z]{2,6}){0,}',addr)
		if not sender_domain:
			return(unsubscribe_score += score)

		sender_domain = sender_domain.group(0).strip('@')

		# some primitive patterns
		patterns = [
						'http(s)+:\/\/.*sender_domain\/.*(listinfo|unsub|email=).*',\
		                'mailto:.*@.*\.sender_domain.*'
					]

		for uri in uri_list:
			if not filter(lambda reg: re.search(reg,uri,re.I),patterns):
				unsubscribe_score += score

	return(unsubscribe_score)
















