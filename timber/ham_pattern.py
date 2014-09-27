#! /usr/bin/env python

import os, sys, logging, subprocess, ConfigParser, re, shutil, time, env, common
from signal import SIGHUP, SIGTERM, SIGKILL

#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class SpamPattern():
	"Set vectorising rules for hams."

	def run(self,msg):
        vect = {}
        vect.update(common.get_body_skeleton())
        logger.debug(vect)




		return(vect)


if __name__ == "__main__":

	formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
	ch = logging.StreamHandler(sys.stdout)
	ch.setLevel(logging.DEBUG)
	ch.setFormatter(formatter)
	logger.addHandler(ch)

	try:
		test=HamPattern(env)
		vector = test.run()
		logger.debug(vector)


	except Exception, details:
		raise

			


		


	
			



