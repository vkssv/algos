#! /usr/bin/env python

import os, sys, logging, re, common
from email.header import decode_header

#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

class SpamPattern():
	"Keeps and applies vectorising rules for spams."

	def __init__(self,msg):
		self.msg = msg

	def run(self):

		vector_dict = {}

		# 1. get crc32 of just unique headers vector
		heads_vect = tuple(self.msg.keys())

		excluded_heads = ['Received', 'Subject', 'Date', 'MIME-Version', 'To', 'Message-ID', 'Return-Path']
		without_X_heads = True
		vector_dict['heads_crc'] = common.get_heads_crc(excluded_heads, heads_vect, without_X_heads)

		# 2. strong features for unconditional spams
        # Subject checks are valuable only for pure US-ASCII messages (RFC 5322)
        # or for Subjects: which contain Latin symbols
        sus_tokens_dict = {
                        'Subject'  : (['(viagra|ciali(s|\$)|pfizer|discount|pill|med|free|click|Best\s+Deal\s+Ever|babe)+'],1.0),
                        'Received' : (['(adsl|dsl|dynamic|static)+'],1.0)
                    }

        decoded_heads_dict ={}
        for h in regs_dict.keys():
            head_value, encoding = (decode_header(msg.get('Subject'))[0])
            decoded_heads_dict[h] = head_value

        headers_scores = common.check_suspect_heads(decoded_heads_dict,sus_tokens_dict,with_noise=False)
        # rules for FWD/RE in subj
        #regs_list = ['Fwd:','Re','FN','FP','Report']
        #if re.match("[]",decoded_heads_dict.get('Subject'),re.I)

		headers_scores['Subject'] = headers_scores.get('Subject')+score

		vector_dict.update(headers_scores)


		# 3. make CRC32 vect for chosen RCVD heads + shingles-like checksums for some other
        n_rcvds = 3
        keys = tuple(['rcvd'+str(i) for i in range(n_rcvds)])
        values = common.crc_from_rcvd(msg,n_rcvds)
        logger.debug(str(dict(zip(keys,values))))
        vector_dict.update(dict(zip(keys,values)))

		# 4. check urls


		# 5. simple checks by regexp for unconditional spams
		vect_dict.update(common.get_body_skeleton(self.msg))
		logger.debug(vect)
		return(vect_dict)


if __name__ == "__main__":

	formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
	ch = logging.StreamHandler(sys.stdout)
	ch.setLevel(logging.DEBUG)
	ch.setFormatter(formatter)
	logger.addHandler(ch)

	try:
		pattern=SpamPattern(msg)
		vector = test.run()
		logger.debug(vector)


	except Exception, details:
		raise

			


		


	
			



