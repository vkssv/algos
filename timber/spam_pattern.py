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

		excluded_heads = ['Received', 'From', 'Subject', 'Date', 'MIME-Version', 'To', 'Message-ID', 'Return-Path']
		vector_dict['heads_crc'] = common.get_heads_crc(excluded_heads,heads_vect)

		# 2. simple checks by regexp for unconditional spams
	def __check_features_headers(head_value, head_name):

        res = 0.0
        if head_name in ['To','Cc','Bcc']:

	        res = len(re.findall('<.*>',head_value))

        elif head_name in ['Subject','Received']:

		if head_name == 'Subject':
			# remove noise in cases of "my tasty V I A G R A \S\I\A\L\I\S /D/R/U/G"
			head_value = re.sub('[\\\/\s]','',head_value)

                headers_dict = {
                                        'Subject'       : '(viagra|cialis|discount|pill|med|free|click|Best\s+Deal\s+Ever|babe)+',
                                        'Received'      : '(adsl|dsl|dynamic|static)+'
                                }

                m = re.search(headers_dict.get(head_name),head_value,re.I)
		if m:
		        res = 1.0
			logger.debug ('SUSPECT_'+head_name.upper()+': '+(m.group(0)).strip())

        logger.debug (head_name.upper()+' = '+str(res))

	return(res)


		vect.update(common.get_body_skeleton(self.msg))
		logger.debug(vect)
		return(vect)


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

			


		


	
			



