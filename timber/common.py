'''
shared module with common-used functions
'''

import email, os, sys, re, logging

from email.errors import MessageParseError

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

def check_suspect_heads(decoded_heads_dict,sus_tokens_dict,with_noise=True):
	'''''
		regexp_dict = {'head_name': ([regexp_list],score)}
		decoded_heads_dict = {'head_name':'value'}
	'''''

	scores_dict = {}
	for head in regexp_dict.keys():
		regs_list, score = regexp_dict.get(head)
		logger.debug (regs_list, score)

		value = heads_dict.get(head)
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
def parse_trace_fields(msg,n=0)

	rcvd_values = tuple(msg.get_all('Received'))[-1*n:]
	rcvds_vect = tuple([rcvd.partition(';')[0] for rcvd in rcvd_values[:]])
    rcvds_vect = tuple([rcvd.partition('for') for rcvd in rcvds_vect[:]])

	return(rcvds_vect)

