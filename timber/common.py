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

def check_suspect_heads(heads_dict,regexp_dict,with_noise=True):
	'''''
		regexp_dict = {'head_name': ([regexp_list],score)}
		heads_dict = {'head_name':'value'}
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

def make_rcvd_shingles(self.msg,d):

	rcvd_values = tuple(m1.get_all('Received'))[-1*d:]
	l = h.split(';')[0]
	l.lower().split('with')[0]
	# vect = normilize + take crc32
	#return({rcvdn:crc32})


# for what heads meats we also need shingles ? for spam
#def url_checker()