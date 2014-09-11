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


def get_heads_crc(excluded_list,heads_vector):

	unique_list = []

	# exclude common headers like Received, From, Date, etc, if needed
	if excluded_list:
		for head in [ filter(lambda h: not excluded_list.count(h),heads_vector) ]
			unique_list.append(head)
			logger.debug(unique_list)

		# try to save order of rested headers, as they appeared in msg
		unique_list = tuple(unique_list)

	else
		unique_list = heads_vect

	heads_line = ''.join(msg_heads)
	crc32 = binascii.crc32(heads_line)

	return(crc32)

def check_string()