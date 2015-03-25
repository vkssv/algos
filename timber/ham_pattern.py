#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""Keeps and applies vectorising rules for hams. """

import os, sys, logging, math
from collections import OrderedDict, Counter

from pattern_wrapper import BasePattern

#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class HamPattern(BasePattern):
    """
    Pattern class for build vectors, based on features
    suitable for transactional emails : msgs from banks,
    e-shops, bills, etc:
    -- if email looks like ham, it's vector will contain
        values, mostly don't equal to zeros ;
    """

    RCVDS_NUM = 3

    # try greedy regexes, maybe will precise them in future
    SUBJ_RULES = [
                             ur'(Re\s*:|Fw(d)?\s*:|fly|ticket|account|payment|verify\s+your\s+(email|account)|bill)',
                             ur'(support|help|participate|registration|electronic|answer|from|update|undelivered)',
                             ur'от\s+[\w\.-]{3,10}\s+(счет|отчет|выписка|электронный\s+(билет)?)'

    ]

    TEXT_REGEXP_LIST = [

                        ur'(track(ing)?\s+No|proc(é|e)+d(er)?|interview|invit[eation]|welcom(ing)?|introduc(tion)?|your\s.*(ticket|order)\s.*(\#|№)|day|quarter|inquir[yies])',
                        ur'(feature|questions?|support|request|contrac?ts?|drafts?|teams?|priorit[yies]|details?|attach(ed)?|communic.*|train(ing)?)',
                        ur'(propos[eal]|found\s+this|concern(ing|ant)?|remind[ers]|contrac?t|act|s(e|é)curit[yieés]|during\s+.*(the)?\s+period)',
                        ur'(reports?|logs?|journals?|(re)?scheduled?|(specif[yied]|conference|call)\s+.*time|transfer|cancel(ed)?|payment|work|labour|mis\s+(à|a)\s+jour)',
                        ur'(profile\s+activation|invit(aion)?|registration|forgot.*password|pre-.*|post-.*|document(ation)?|compte)',
                        ur'((d\')?expiration|exchange|service|requisition|albeit|compl(é|e)mentaire(es)?|addition(al)?|terms?\s+and\s+conditions?)',
                        ur'(en\s+invitant|ci-(jointe|dessous)|trans(mette|mis)|souscription|sp(é|e)siale?|procéd[eré]|(e|é)change|us(age|ing|er))',
                        ur'(valider\s+les?|donnéés|дата|недел|тариф|уведомлен|связ|по\s+причин|магазин|поступил|отмен).*',
                        ur'(заказ|сч(е|ё)т|предложен|контракт|отмена?|платеж|чек|данн|подтвер(ждение|ит[еть])|билет|номер|трэк|(тех)?поддерж).*',
                        ur'(аккаунт|парол|доступ|истек[лоает]|договор|справка|интервью|встреча?|приглашен|собеседован|офис|врем|график|адрес).*',
                        ur'(баланс|детали|выписк|прикреплен|(набор\s)?.*услуг).*'

    ]

    HTML_TAGS_MAP = {

                                'img' :{
                                            'src'             : '(cid:(_.*|part.*|profile|photo|logo|google|ima?ge?\d{1,3}.*@[\w.])|assets|track(ing)?|api|ticket|logo|fb|vk|tw)',
                                            'moz-do-not-send' : 'true'
                                },
                                'li'  :{
                                            'dir'             : 'ltr',
                                            'class'           : '\[\'.*\'\]'
                                }
                    }


    URL_FQDN_REGEXP = [
                            ur'(www\.)?(registration|account|payment|confirmation|password|intranet|emarket)',
                            ur'(www\.)?(tickets+|anywayanyday|profile|job|my\.|email|blog|support)',
                            ur'(www\.)?(meetup\.com|odnoklassniki\.ru|vk\.com|my\.mail\.ru|facebook\.com)',
                            ur'(www\.)?(linkedin\.com|facebook\.com|linternaute\.com|blablacar\.com)',
                            ur'(www\.)?(youtube\.com|plus\.google\.com|twitter\.com|pinterest\.com|tumblr\.com)',
                            ur'(www\.)?(instagram\.com|flickr\.com|vine\.com|tagged\.com|ask\.fm|meetme\.com)',
                            ur'(www\.)?classmates'

    ]

    URL_TXT_REGEXP = [
                            ur'(users?\/|id|sign[_\s]{0,1}(in|up)|e?ticket|kassa|account|payment|confirm(ation)?|password)',
                            ur'(support|settings|orders?|product|disclosures?|privacy|\?user_id|validate_e?mail\?)'
    ]

    def __init__(self, **kwds):
        '''
        :param kwds:
        # todo: initialize each <type>-pattern with it's own penalizing self.score,
        will be useful in vector-distance calculations, for axes stretching

        :return: expand msg_vector, derived from BasePattern class with
        less-correlated metrics, which are very typical for spams,
        '''

        super(HamPattern, self).__init__(**kwds)



        # 0. initialize vector of features explicitly,
        # for avoiding additional headaches and investigations with Python GC
        base_features = [
                            'rcvd_score',
                            'forged_sender',
                            'disp_notification',
                            'mime_score'
        ]

        features_dict = {
                            'subj':   ['style','checksum','encoding'],
                            'url' :   ['upper', 'repetitions', 'punicode', 'domain_name_level',\
                                         'avg_len', 'onMouseOver', 'hex', 'at_sign'],
        }

        total = list()

        [ total.extend([k+'_'+name for name in features_dict.get(k)]) for k in features_dict.keys() ]
        # use SpamPattern._INIT_SCORE --> in case we want to assing for SpamPattern some particular _INIT_SCORE
        [ self.__setattr__(f, self.INIT_SCORE) for f in (base_features + total) ]

        # 2. Subject
        self.get_subj_features(['subj_'+name for name in features_dict.get('subj')])

        # 7. URL-checks
        self.get_url_features(['url_'+name for name in features_dict.get('url')])

        logger.debug('SpamPattern was created'.upper()+' :'+str(id(self)))
        #logger.debug(self.__dict__)
        for (k,v) in self.__dict__.iteritems():
            logger.debug(str(k).upper()+' ==> '+str(v).upper())
        logger.debug("++++++++++++++++++++++++++++++++++++++++++++++++++")
        #logger.debug(SpamPattern.__dict__)
        for (k,v) in self.__dict__.iteritems():
            logger.debug(str(k).upper()+' ==> '+str(v).upper())
        logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))


        # 1. "Subject:" Header
        logger.debug('>>> 1. SUBJECT CHECKS:')

        features = ('len','style','score')
        features_dict = OrderedDict(map(lambda x,y: ('subj_'+x,y), features, [self.INIT_SCORE]*len(features)))

        if self._msg.get('Subject'):

            total_score = self.INIT_SCORE
            unicode_subj, tokens, encodings = self.get_decoded_subj(self._msg.get("Subject"))

            features_dict['subj_len'] = len(unicode_subj)
            #if self.MIN_SUBJ_LEN < len(unicode_subj) < self.MAX_SUBJ_LEN:
            #    features_dict['subj_len'] = 1

            subject_rule = [

            ]

            subj_score, upper_words_num, title_words_num = self.get_subjects_metrics(unicode_subj, subject_rule, self.score)

            #features_dict['subj_style'] = title_words_num

            features_dict['subj_score'] += subj_score

        vector_dict.update(features_dict)
        logger.debug('\t----->'+str(vector_dict))

        # 2. check urls
        logger.debug('>>> 2. URL_CHECKS:')

        urls_list = self.get_url_list()
        urls_features = ('avg_length', 'query_absence', 'url_score')
        urls_dict = OrderedDict(map(lambda x,y: (x,y), urls_features, [self.INIT_SCORE]*len(urls_features)))

        if urls_list:
            logger.debug('URLS_LIST >>>>>'+str(urls_list))

            rcvds = self.get_rcvds(self.__RCVDS_NUM)
            rcvd_vect = tuple([r.partition('by')[0] for r in rcvds])

            d, netloc_list = self.get_url_metrics(urls_list, rcvd_vect, score, domain_regs, regs)
            urls_dict['url_score'] = d.get('url_score')

            queries_count = float(len(filter(lambda line: line, [ u.query for u in urls_list ])))
            if math.floor(queries_count/float(len(urls_list))) == 0.0:
                urls_dict['query_absence'] = score

            length_list = [ len(url) for url in [ obj.geturl() for obj in urls_list ]]
            urls_dict['avg_length'] = math.ceil(float(sum(length_list))/float(len(urls_list)))

        vector_dict.update(urls_dict)

        logger.debug('>>> 3. BODY\'S TEXT PARTS CHECKS:')




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

			


		


	
			



