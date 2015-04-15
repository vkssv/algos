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

        def __init__(self, **kwds):
        '''
        :param kwds:
        # todo: initialize each <type>-pattern with it's own penalizing self.score,
        will be useful in vector-distance calculations, for axes stretching

        :return: expand msg_vector, derived from BasePattern class with
        less-correlated metrics, which are very typical for spams,
        '''
        super(InfoPattern, self).__init__(**kwds)


        features_map = {
                         'subject'      : ['score','len','style'],
                         'url'          : ['score','avg_len','absence'],
                         'content'      : ['txt_score','html_score']
        }

        logger.debug('Start vectorize msg with rules from InfoPattern...')

        for n, key in enumerate(features_map.keys(),start=1):
            logger.debug(str(n)+'. Add '+key.upper()+' features attributes to msg-vector class: '+str(self.__class__))


            features = ['get_'+key+'_'+name for name in features_map[key]]
            checker_obj = checkers.__getattribute__(key.title()+'Checker')
            checker_obj = checker_obj(self)

            logger.debug('Instance of '+str(checker_obj.__class__)+' was initialized:')
            logger.debug('>> '+str(checker_obj.__dict__))
            logger.debug("================")

            functions_map = [(name.lstrip('get_'), getattr(checker_obj, name)) for name in features]

            for name, f in functions_map:
                feature_value = self.INIT_SCORE
                print(name)
                print(f)
                try:
                    feature_value = f()
                except Exception as err:
                    logger.error(str(f)+' : '+str(err))
                    pass

                self.__setattr__(name, feature_value)



        logger.debug('\n>> info-features vector : \n'.upper())
        for (k,v) in self.__dict__.iteritems():
            logger.debug('>>> '+str(k).upper()+' ==> '+str(v).upper())

        logger.debug("++++++++++++++++++++++++++++++++++++++++++++++++++")
        logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))

'''''




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

			
'''''

		


	
			



