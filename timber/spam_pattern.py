#! /usr/bin/env python

import os, sys, logging,  re,  common_func

#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class SpamPattern():
	"Set vectorising rules for shams."

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
        regs_dict = {
                        'Subject'  : (['(viagra|ciali(s|\$)|pfizer|discount|pill|med|free|click|Best\s+Deal\s+Ever|babe)+'],1.0),
                        'Received' : (['(adsl|dsl|dynamic|static)+'],1.0)
                    }

		vector_dict.update(common.check_suspect_heads(msg.keys(),regexp_dict,with_noise=True))
		# 3. check Fwd

		# 4. make shingles for RCVD
		# 5. check urls
		# 2. simple checks by regexp for unconditional spams
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

			


		


	
			



