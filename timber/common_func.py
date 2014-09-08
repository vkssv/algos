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


