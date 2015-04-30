#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-

import sys, logging

from msg_wrapper import BeautifulBody
from pattern_wrapper import BasePattern
import checkers

logger = logging.getLogger('')
#logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(levelname)s %(funcName)s: %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#logger.addHandler(ch)

INIT_SCORE = BasePattern.INIT_SCORE


class HamPattern(BeautifulBody):
    """
    Pattern class for build vectors, based on features
    suitable for transactional emails : msgs from banks,
    e-shops, bills, etc:
    -- if email looks like ham, it's vector will contain
        values, mostly don't equal to zeros ;
    """

    # search them in DKIM headers
    KNOWN_DOMAINS = [
                        r'.*\.paypal\.com',\
                        r'.*\.smartfares\.com',\
                        r'.*\.anywayanyday.*\.com',\
                        r'.*\.airbnb\.com',\
                        r'.*\.booking\.com'
    ]

    # try greedy regexes, maybe will precise them in future
    SUBJ_RULES = [
                             ur'(Re\s*:|Fw(d)?\s*:|fly|ticket|account|payment|verify.*your.*(email|account)|bill)',\
                             ur'(support|help|participate|registration|electronic|answer|from|update|undelivered)',
                             ur'от.*[\w\.-]{3,10}.*(счет|отчет|выписка|электронный.*(билет)?)'

    ]


    TEXT_REGEXP_LIST = [

                            ur'(track(ing)?.*No|proc(é|e)d(er)?|interview|invit[eation]?|welcom(ing)?|introduc(tion)?|your\s.*(ticket|order)\s.*(\#|№)|day|quarter|inquir[yies])',
                            ur'(feature|questions?|support|request|contrac?ts?|drafts?|teams?|priorit[yies]|details?|attach(ed)?|communic.*|train(ing)?)',
                            ur'(propos[eal]|found.*this|concern(ing|ant)?|remind[ers]|contrac?t|act|s(e|é)curit[yieés]|during.*(the)?.*period)',
                            ur'(reports?|logs?|journals?|(re)?scheduled?|(specif[yied]|conference|call).*time|transfer|cancel(ed)?|payment|work|labour|mis.*(à|a).*jour)',
                            ur'(profile.*activation|invit(aion)?|registration|forgot.*password|pre-.*|post-.*|document(ation)?|compte)',
                            ur'((d\')?expiration|exchange|service|requisition|albeit|compl(é|e)mentaire(es)?|addition(al)?|terms?.*and.*conditions?)',
                            ur'(en.*invitant|ci-(jointe|dessous)|trans(mette|mis)|souscription|sp(é|e)siale?|procéd[eré]|(e|é)change|us(age|ing|er))',
                            ur'(valider.*les?.*donnéés)',
                            ur'(veuillez.*agrées|salutations.*(distinguées)|à.*la.*suite.*de.*vo[stre]|souhaiter[ezitonsr])',
                            ur'((tous)?.*renseignements|de.*bien.*vouloir|(indiqu|expliqu)[erzensto]|tarif|faire.*parvenir)',
                            ur'((nous.*vous)?.*remerci[ezonsti]|concern[enant]facture|délais.*de.*livraison|conditions?de.*règlement)',
                            ur'(tenons.*(à.*votre.*disposition)|réservation.*(effectuée)?|pré-approuvé|période|terme)'

    ]

    URL_FQDN_REGEXP = [
                            ur'(www\.)?(registration|account|payment|confirmation|password|intranet|emarket)',
                            ur'(www\.)?(tickets?|anywayanyday|profile|job|my\.|email|blog|support)',
                            ur'(www\.)?(meetup\.com|odnoklassniki\.ru|vk\.com|my\.mail\.ru|facebook\.com)',
                            ur'(www\.)?(linkedin\.com|facebook\.com|linternaute\.com|blablacar\.com)',
                            ur'(www\.)?(youtube\.com|plus\.google\.com|twitter\.com|pinterest\.com|tumblr\.com)',
                            ur'(www\.)?(instagram\.com|flickr\.com|vine\.com|tagged\.com|ask\.fm|meetme\.com)',
                            ur'(www\.)?classmates?'

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
                         'content'      : ['txt_score']
        }

        for n, key in enumerate(features_map.keys(),start=1):

            features = ['get_'+key+'_'+name for name in features_map[key]]
            checker_obj = checkers.__getattribute__(key.title()+'Checker')
            checker_obj = checker_obj(self)

            functions_map = [(name.lstrip('get_'), getattr(checker_obj, name, lambda : INIT_SCORE)) for name in features]

            for name, f in functions_map:
                feature_value = INIT_SCORE
                #logger.debug(name)

                try:
                    feature_value = f()
                except Exception as err:
                    logger.error(str(f)+' : '+str(err))
                    pass

                self.__setattr__(name, feature_value)

    def __str__(self):
        return('HAM')


		


	
			



