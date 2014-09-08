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
		vect = {}
		vect.update(common_func.get_body_skeleton(self.msg))
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

			


		


	
			



