#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Keeps and applies vectorising rules for hams. """

import os, sys, logging, common, math
from collections import OrderedDict, Counter

from pattern_wrapper import BasePattern

INIT_SCORE = BasePattern.INIT_SCORE
MIN_TOKEN_LEN = BasePattern.MIN_TOKEN_LEN


#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class HamPattern(BasePattern):
    """
    Pattern class for build vectors, based on features,
    which are more suitable for transactional emails,
    i.e. correspondance from banks, e-shops, bills, etc:

        -- if the email looks like ham, it's vector will contain
            values, which are mostly don't equal to zero ;
        -- vector will contain mostly zeros, if the email doesn't
            have these sets of features ;
    """

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
            unicode_subj, norm_words_list, encodings = common.get_subject(self.msg.get("Subject"), MIN_TOKEN_LEN)

            if self.MIN_SUBJ_LEN < len(unicode_subj) < self.MAX_SUBJ_LEN:
                features_dict['subj_len'] = 1

            subject_rule = [
                                ur'(Re\s*:|Fw(d)?\s*:|fly|ticket|account|payment|verify\s+your\s+(email|account)|bill)',
                                ur'(support|help|participate|registration|electronic|answer|from|update|undelivered)',
                                ur'от\s+[\w\.-]{3,10}\s+(счет|отчет|выписка|электронный\s+(билет)?)'
                            ]


            subj_score, upper_flag, title_flag = common.basic_subjects_checker(unicode_subj, subject_rule, score)
            # almoust all words in subj string are Titled
            if title_flag < 3:
                features_dict['subj_style'] = 1

            features_dict['subj_score'] = total_score + subj_score

            vector_dict.update(features_dict)
            logger.debug('\t----->'+str(vector_dict))

            # 8. check urls
            logger.debug('>>> 2. URL_CHECKS:')

            urls_list = BasePattern.get_url_list(self)
            urls_features = ['avg_length', 'query_absence', 'url_score']
            urls_dict = OrderedDict(map(lambda x,y: (x,y), urls_features, [INIT_SCORE]*len(urls_features)))

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
                                ur'(users?\/|id|sign[_\s]{0,1}(in|up)|e?ticket|kassa|account|payment|confirm(ation)?|password)',
                                ur'(support|settings|orders?|product|disclosures?|privacy|\?user_id|validate_e?mail\?)'
                        ]

                n_rcvds = 3
                rcvds = BasePattern.get_rcvds(self,n_rcvds)
                rcvd_vect = tuple([r.partition('by')[0] for r in rcvds])

                d, netloc_list = common.basic_url_checker(urls_list, rcvd_vect, score, domain_regs, regs)
                urls_dict['url_score'] = d.get('url_score')

                queries_count = float(len(filter(lambda line: line, [ u.query for u in urls_list ])))
                if math.floor(queries_count/float(len(urls_list))) == 0.0:
                    urls_dict['query_absence'] = score

                length_list = [ len(url) for url in [ obj.geturl() for obj in urls_list ]]
                urls_dict['avg_length'] = math.ceil(float(sum(length_list))/float(len(urls_list)))

            vector_dict.update(urls_dict)

        logger.debug('>>> 9. BODY\'S TEXT PARTS CHECKS:')

        tags_map = {
                        'img' :{
                                    'src'             : '(cid:(_.*|part.*|profile|photo|logo|google|ima?ge?\d{1,3}.*@[\w.])|assets|track(ing)?|api|ticket|logo|fb|vk|tw)',
                                    'moz-do-not-send' : 'true'
                        },
                        'li'  :{
                                    'dir'             : 'ltr',
                                    'class'           : '\[\'.*\'\]'
                        }
        }

        regexp_list= [
                        ur'(track(ing)?\s+No|proc(é|e)+d(er)?|interview|invit[eation]|welcom(ing)?|introduc(tion)?|your\s+.*(ticket|order)s?*\s+(\#|№)|day|quarter|inquir[yies])',
                        ur'(feature|questions?|support|request|contrac?ts?|drafts?|teams?|priorit[yies]|details?|attach(ed)?|communic.*|train(ing)?)',
                        ur'(propos[eal]|found\s+this|concern(ing|ant)?|remind[ers]|contrac?t|act|s(e|é)curit[yieés]|during\s+.*(the)?\s+period)',
                        ur'(reports?|logs?|journals?|(re)?scheduled?|(specif[yied]|conference|call)\s+.*time|transfer|cancel(ed)?|payment|work|labour|mis\s+(à|a)\s+jour)',
                        ur'(profile\s+activation|invit(aion)?|registration|forgot.*password|pre-.*|post-.*|document(ation)?|compte)',
                        ur'((d\')?expiration|exchange|service|requisition|albeit|compl(é|e)mentaire(es)?|addition(al)?|terms?\s+and\s+conditions?)',
                        ur'(en\s+invitant|ci-(jointe|dessous)|trans(mette|mis)|souscription|sp(é|e)siale?|procéd[eré]|(e|é)change|us(age|ing|er)',
                        ur'(valider\s+les?|donnéés|дата|недел|тариф|уведомлен|связ|по\s+причин|магазин|поступил|отмен).*',
                        ur'(заказ|сч(е|ё)т|предложен|контракт|отмена?|платеж|чек|данн|подтвер(ждение|ит[еть]|билет|номер|трэк|(тех)?поддерж).*',
                        ur'(аккаунт|парол|доступ|истек[лоает]|договор|справка|интервью|встреча?|приглашен|собеседован|офис|врем|график|адрес).*',
                        ur'(баланс|детали|выписк|прикреплен|(набор\s)?.*услуг).*'
                    ]


        features = ('html_score', 'text_score', 'table_checksum')
        features_dict = Counter(zip(features, self.get_html_parts_metrics(self, regexp_list, score, tags_map)))
        features_dict['text_score'] += self.get_text_parts_metrics(self, regexp_list, score)
        vector_dict.update(features_dict)
        #vector_dict['entropy'] = BasePattern.get_body_parts_entropy(self)

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

			


		


	
			



