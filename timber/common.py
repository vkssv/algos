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

def check_lists(heads_list,score):

	unsubscribe_score = 0
	for pattern in [ '(.*-)?Unsubscribe(-.*)?', '(.*-)?UnList(-.*)?']:
		if not filter(lambda head_name: re.search(pattern, head_name, re.I), heads_list):
			unsubscribe_score += score

    if not heads_list.count('Sender')
            unsubscribe_score += score

	return(unsubscribe_score)
















