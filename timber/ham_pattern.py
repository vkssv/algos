#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
"Set vectorising rules for hams."

import os, sys, logging, common
from pattern_wrapper import BasePattern

#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class HamPattern(BasePattern):


	def run(self,msg):
        vect = {}
        vect.update(common.get_body_skeleton())
        logger.debug(vect)


        # Subject checks
        features = ['len','style','score']
        features_dict = dict(map(lambda x,y: ('subj_'+x,y), features, [BasePattern.INIT_SCORE]*len(features)))

        if self.msg.get('Subject'):

            total_score = BasePattern.INIT_SCORE
            unicode_subj, norm_words_list = common.get_subject(self.msg("Subject"))

            if 5 < len(unicode_subj) < 60:
                features_dict['subj_len'] = 1

            hams_patterns = [
                                ur'(Re\s*:|Fw(d)?\s*:|fly|ticket|account|payment|verify\s+your\s+(email|account)|bill)',
                                ur'(support|help|participate|registration|electronic|answer|from|update|undelivered)',
                                ur'(от\s+([\w-\.]{3,10})\s+|счет|отчет|выписка|электронный\s+(билет)?)'
                            ]



            subj_score, upper_flag, title_flag = common.basic_subjects_checker(unicode_subj, subject_rule, score)
            # almoust all words in subj string are Titled
            if len(title_flag) < 3:
                features_dict['subj_style'] = 1

            features_dict['subj_score'] = total_score + subj_score

        vector_dict.update(features_dict)
        logger.debug('\t----->'+str(vector_dict))


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


	except Exception as details:
		raise

			


		


	
			



