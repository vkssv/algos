'''
shared module with common-used functions
'''

import email, os, sys, re, logging

from email.errors import MessageParseError
from email.header import decode_header
from operator import add
#from vectorizer_exceptions import VectError

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

# excluded_list=['Received', 'From', 'Date', 'X-.*']
def get_heads_crc(excluded_list=[], heads_tuple):

	if excluded_list:
		for ex_head in excluded_list:
			heads_vector = tuple(filter(lambda h_name: not re.match(ex_head,h_name,re.I),heads_tuple[:]))

	checksum = binascii.crc32(''.join(heads_tuple))

	return(checksum)

#def remove_noise_str(str):

#	return(re.sub('[\[\]\\\/\^\.&$#~`"\=@\',:;\|\?\*\+\(\)\{\}\s]','',str))

# very basic here: takes given RCVD headers from bottom, cut timestamp fields
def basic_traces_parser(rcvds_tuple):



	return(rcvds_vect)

def get_trace_crc(rcvds_vect,regs_list):

	traces_dict={}

	for rcvd, n in zip(rcvds_vect, range(len(rcvds_vect))):

		trace = ''

		temp = tuple(map(lambda x: re.search(x,rcvd,re.I),regs_list))
		trace = ''.join([item.group(0).strip() for item in temp])
		trace = binascii.crc32(trace)

		traces_dict['rcvd_'+n] = trace

	return(traces_dict)

def get_decoded_headers(header_value_list, need_header_list):

	decoded_heads={}

	for r_name in need_header_list:
		header = filter(lambda item: re.match(r_name,item[0],re.I),msg.items())
		if header:
			h_name, value = header[0]
			decoded_heads[h_name] = decode_header(value)

	if not decoded_heads:
		logger.warn("get_decoded_headers: can't find any header from "+str(need_headers))

	return(decoded_heads)

# returns score + crc32 trace
def basic_subjects_checker(msg.items(), regex_list, len_threshold, score):

	total_score = 0

	l = filter(lambda pair: pair[0]=='Subject',headers_list)
	if len(l) > 2:
		total_score += score*len(l)
		# never go here, but in case for funny msg with 2 Subjects add them extra penalty?

	header_name, value = l[0]
	subj_parts = tuple(map(lambda part: part[0].strip(),decode_header(value)))

	# check total len
	if sum(map(lambda w: len(w),subj_parts)) > len_threshold:
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
		matched_list = map(lambda prefix: re.search(prefix, p, re.I), ['^\s+Re\s+:','^\s+Fw(d)+\s+:'])
		matched_list = filter(lambda obj: obj, matched_list)
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

def basic_lists_checker(msg,score):

	unsubscribe_score = 0

	for required in [('List-Unsubscribe','Errors-To'),('Sender','Reply-To')]:
		# according to RFC #2369 every bulk
		if not (msg.keys()).count(required[0] or msg.keys()).count(required[1]):
			unsubscribe_score += score

	if heads_list.count('List-Unsubscribe') || heads_list.count('Errors-To'):

		uri_list = re.findall('<.*?>',msg.get('List-Unsubscribe'),re.I)

		if not uri_list or not(get_from_value(msg))
			unsubscribe_score += score
			return(unsubscribe_score)



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




def get_body_skeleton(msg):

    body_skeleton={}
    for part in msg.walk():
        body_skeleton[part.get_content_type()]=part.get_filename()

    if not len(body_skeleton.keys()):
        raise MessageParseError

    else:
        logger.debug("SKELETON: "+str(body_skeleton))

    return(body_skeleton)













