#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
"Set vectorising rules for hams."

import os, sys, logging, common, math
from pattern_wrapper import BasePattern
from collections import OrderedDict, Counter

INIT_SCORE = BasePattern.INIT_SCORE
MIN_TOKEN_LEN = BasePattern.MIN_TOKEN_LEN


#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class HamPattern(BasePattern):

    MAX_SUBJ_LEN = 5
    MIN_SUBJ_LEN = 60

	def run(self, score):
        vector_dict = OrderedDict()

        # 1. "Subject:" Header
        logger.debug('>>> 1. SUBJECT CHECKS:')

        features = ['len','style','score']
        features_dict = dict(map(lambda x,y: ('subj_'+x,y), features, [INIT_SCORE]*len(features)))

        if self.msg.get('Subject'):

            total_score = INIT_SCORE
            unicode_subj, norm_words_list = common.get_subject(self.msg("Subject"))

            if self.MIN_SUBJ_LEN < len(unicode_subj) < self.MAX_SUBJ_LEN:
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

        # 8. check urls
        logger.debug('>>> 2. URL_CHECKS:')

        urls_list = BasePattern.get_url_list(self)

        if urls_list:
            logger.debug('URLS_LIST >>>>>'+str(urls_list))

            domain_regs = [
                                ur'(www\.)?(registration|account|payment|confirmation|password|intranet|emarket)',
                                ur'(www\.)?(tickets+|anywayanyday|profile|job|my\.|email|blog|support)',
                                ur'(www\.)?(meetup\.com|odnoklassniki\.ru|vk\.com|my\.mail\.ru|facebook\.com)',
                                ur'(www\.)?(linkedin\.com|facebook\.com|linternaute\.com|blablacar\.com)',
                                ur'(www\.)?(youtube\.com|plus\.google\.com|twitter\.com|pinterest\.com|tumblr\.com)',
                                ur'(www\.)?(instagram\.com|flickr\.com|vine\.com|tagged\.com|ask\.fm|meetme\.com)',
                                ur'(www\.)?classmates'
            ]

            regs = [
                                ur'(users?\/|id|sign[_\s]{0,1}(in|up)|e?ticket|kassa|account|payment|confirm(ation)?|password',
                                ur'(support|settings|orders?|product|disclosures?|privacy|\?user_id|validate_e?mail\?)'
                    ]

            d, netloc_list = common.basic_url_checker(urls_list, rcvds, score, domain_regs, regs)
            basic_features_dict['url_score'] = d.get('url_score')

            urls_features = ['avg_length', 'query_absence']
            urls_dict = OrderedDict(map(lambda x,y: (x,y), urls_features, [INIT_SCORE]*len(urls_features)))

            queries_count = float(len(filter(lambda line: line, [ u.query for u in urls_list ])))
            if math.floor(queries_count/float(len(urls_list))) == 0.0:
                urls_features['query_absence'] = score

            urls_dict['avg_length'] = math.ceil((float(sum([ len(url) for url in [ obj.geturl() for obj in urls_list ]])))/float(len(urls_list)))

        else:

            basic_features_dict = dict({'url_score': INIT_SCORE})

        vector_dict.update(basic_features_dict)
        vector_dict.update(urls_dict)

		return(vector_dict)


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

			


		


	
			



