#! /usr/bin/env python

import os, sys, logging, subprocess, ConfigParser, re, shutil, time, env, common
from signal import SIGHUP, SIGTERM, SIGKILL

#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class InfoPattern():
	"Set vectorising rules for ads."

	def run(self,msg):
        vect = {}
        vect.update(common.get_body_skeleton())
        logger.debug(vect)

		# cat /tmp/headers.log | grep Keywords
	


		return(vect)


if __name__ == "__main__":

	formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
	ch = logging.StreamHandler(sys.stdout)
	ch.setLevel(logging.DEBUG)
	ch.setFormatter(formatter)
	logger.addHandler(ch)

	try:
		test=SpamPattern(env)
		vector = test.run()
		logger.debug(vector)


	except Exception, details:
		raise

			


		


	
			



