#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""Keeps and applies vectorising rules for hams. """

import os, sys, logging, math
from collections import OrderedDict, Counter

from msg_wrapper import BeautifulBody
from pattern_wrapper import BasePattern
import checkers

logger = logging.getLogger('')
#logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(filename)s %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#logger.addHandler(ch)

'''''
from email import parser
parser = parser.Parser()
with open('/home/calypso/train_dir/abusix/0000006192_1422258877_ff43700.eml','rb') as f:
#with open('/tmp/201501251750_abusix/0000006194_1422258936_10744700.eml','rb') as f:
    M = parser.parse(f)
'''''

INIT_SCORE = BasePattern.INIT_SCORE

class HamPattern(BeautifulBody):
    """
    Pattern class for build vectors, based on features
    suitable for transactional emails : msgs from banks,
    e-shops, bills, etc:
    -- if email looks like ham, it's vector will contain
        values, mostly don't equal to zeros ;
    """

     # search them in DKIM maybe later SPF headers
    KNOWN_DOMAINS = [
                        r'.*\.paypal\.com',\
                        r'.*\.smartfares\.com',\
                        r'.*\.anywayanyday.*\.com',\
                        r'.*\.airbnb\.com',\
                        r'.*\.booking\.com'
    ]

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



    def __init__(self, score, **kwds):
        '''
        :param kwds:
        # todo: initialize each <type>-pattern with it's own penalizing self.score,
        will be useful in vector-distance calculations, for axes stretching

        :return: expand msg_vector, derived from BasePattern class with
        less-correlated metrics, which are very typical for spams,
        '''
        self.PENALTY_SCORE = score

        super(HamPattern, self).__init__(**kwds)

        features_map = {
                         'subject'      : ['score','len','style'],
                         'dmarc'        : ['spf'],
                         'emarket'      : ['domains_score'],
                         'url'          : ['score','avg_len','absence'],
                         'content'      : ['txt_score','html_score']
        }

        logger.debug('Start vectorize msg with rules from HamPattern ')

        for n, key in enumerate(features_map.keys(),start=1):
            logger.debug(str(n)+'. Add '+key.upper()+' features attributes to msg-vector class: ')

            features = ['get_'+key+'_'+name for name in features_map[key]]
            checker_obj = checkers.__getattribute__(key.title()+'Checker')
            checker_obj = checker_obj(self)

            functions_map = [(name.lstrip('get_'), getattr(checker_obj, name, lambda : INIT_SCORE)) for name in features]

            for name, f in functions_map:
                feature_value = INIT_SCORE
                logger.debug(name)
                logger.debug(f)
                try:
                    feature_value = f()
                except Exception as err:
                    logger.error(str(f)+' : '+str(err))
                    pass

                self.__setattr__(name, feature_value)


        logger.debug("++++++++++++++++++++++++++++++++++++++++++++++++++")
        logger.debug("total vect len : "+str(len(self.__dict__.items())-1))
        non_zero = [v for k,v in self.__dict__.items() if float(v) !=0.0 ]
        logger.debug("non_zero features count : "+str(len(non_zero)))


		


	
			



