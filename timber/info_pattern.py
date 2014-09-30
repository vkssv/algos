#! /usr/bin/env python

import os, sys, logging, subprocess, ConfigParser, re, shutil, time, env, common
from signal import SIGHUP, SIGTERM, SIGKILL

# formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class InfoPattern():
    "Set vectorising rules for ads."

    def run(self, msg):

        vect = { }
    vect.update(common.get_body_skeleton())
    logger.debug(vect)

    # cat /tmp/headers.log | grep Keywords


    if filter(lambda list_field: re.search('^List(-.*)?', list_field), self.msg.items()):
        #deep check
        temp_dict ['List'] = common.check_lists(self.msg.items())

        # some primitive patterns
        patterns = [
            'http(s)+:\/\/.*sender_domain\/.*(listinfo|unsub|email=).*', \
            'mailto:.*@.*\.sender_domain.*'
        ]


    else:
    # search unsubscribe link in body

    #Sender != From
    # Reply-to always
    return (vect)

       # regs = [r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', r'\s((?!-)[a-z0-9-\.]{1,63}(?<!-))+(\.[a-z]{2,6}){0,}']


if __name__ == "__main__":

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    try:
        test = SpamPattern(env)
        vector = test.run()
        logger.debug(vector)


    except Exception, details:
        raise

			


		


	
			



