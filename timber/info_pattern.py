#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
""" Keeps and applies vectorising rules for infos. """

import os, sys, logging, re, binascii, math, string

from operator import add
from collections import OrderedDict, Counter

import checkers
from pattern_wrapper import BasePattern


formatter = logging.Formatter('%(levelname)s %(funcName)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
#ch = logging.StreamHandler(sys.stdout)
#logger.addHandler(ch)

'''''
from email import parser
parser = parser.Parser()
with open('/home/calypso/train_dir/abusix/0000006192_1422258877_ff43700.eml','rb') as f:
#with open('/tmp/201501251750_abusix/0000006194_1422258936_10744700.eml','rb') as f:
    M = parser.parse(f)
'''''

class InfoPattern(BasePattern):
    """
    Pattern class for build vectors, based on typical newsletters
    and ads-mails features :

        -- if email looks like news-letter, it's vector will contain
            values, which are mostly don't equal to zeros ;
    """

    RCVDS_NUM = 0

    EXCLUDED_HEADS = [
                            'Received', 'Subject', 'From', 'Date', 'Received-SPF', 'To', 'Content-Type',\
                            'Authentication-Results', 'MIME-Version', 'DKIM-Signature', 'Message-ID', 'Reply-To'
    ]

    EMARKET_HEADS = r'((X-)?EMID|MAIL|EDATIS|SG-E?ID|(rp)?campaign(id)?|Feedback(-ID)?)'

    KNOWN_MAILERS   = [ r'MailChimp', r'PHPMailer', r'GetResponse\s+360', 'GreenArrow', 'habrahabr', 'nlserver',\
                        r'EMS', r'eC-Messenger\s+Build', r'NMS.*Mail.*', 'Cabestan\s+DMS'
    ]

    KNOWN_DOMAINS = [   r'.*\.?smartfares\.com',\
                        r'.*\.?anywayanyday.*\.com',\
                        r'.*\.?airbnb\.com',\
                        r'.*\.?booking\.com',\
                        r'.*\.?twitter\.com',\
                        r'.*\.?look-at-media\.com',\
                        r'.*\.?voyages-sncf\.com',\
                        r'.*\.?redoute\.com',\
                        r'.*\.?france-air\.com',\
                        r'.*\.?fnac\.com',\
                        r'.*\.?le-passage\.fr'


    ]

    # take crc32 from the second half (first can vary cause of personalisation, etc)

    SUBJ_TITLES_THRESHOLD = 3

    # try greedy regexes, maybe will precise them in future
    SUBJ_RULES = [

                            ur'([\u25a0-\u27ff]|[\u2900-\u299f])', \
                            ur'([\u0370-\u03ff]|[\u2010-\u337b]|[\u0460-\u0482]|[\u0488-\u056f])', \
                            ur'(whats?.*(are|is)|(why|how).*(do)?|when|since|could|may|is|in)', \
                            ur'(SALE|FREE|news(letter)?|do.*not.*|don\'t.*miss|they.*back|is.*here|now.*with)', \
                            ur'(interesting|announcing|hurry|big(gest)?|great|only|deal|groupon|tour|travel|hot|inside)', \
                            ur'(all.*for|price|vip|special|trends|brands|shopping|hysteria|save|kick|super(b)?)', \
                            ur'(now.*or.*never|call|share|stock|exclusive|free.*shipping|car|shopper|bonus)', \
                            ur'(lpg|spa|trend|brand|opportunity|be.*the.*first|get.*it.*now|see|look|watch)', \
                            ur'(devis.*de|de.*votre.*iphone|prix.*promotionnels.*jusqu.*|elections?|découv[tsirez])',\
                            ur'(remise.*vo[tres].*commandes?|d[eé]rniere?s?|salon.*(du.*au)?|les.*journées?)',\
                            ur'(sont.*arrivées?|hebdo|sp[eé]ciale?|itespresso|arcticles?.*prefere.*)',\
                            ur'(qui|à.*quoi|pourquoi|actualité\.*monde|(vous.*)?recherch[ontiezrs]|enquete|comment)',\
                            ur'([\w\s-]{2,10}){1,2}\s*:([\w\s+,\.\$!]{2,15})', \
                            ur'[\d]{1,2}\s+[\d]{1,2}[0]{1,3}\s+.*', \
                            ur'-?[\d]{1,2}\s+%\s+.*', \
                            ur'[\d](-|\s+)?\S{1,4}(-|\s+)?[\d]\s+.*', \
                            ur'[\*-=\+~]{1,}\S+[\*-=\+~]{1,}'
    ]

    TEXT_REGEXP_LIST = [
                                ur'(styl(ish)?|perfect|beauti|winter|summer|fall|spring|look|blog|spot)', \
                                ur'(news|letter|discount|sale|info|unsubscribe?|bonus|ads|market)', \
                                ur'((social)?media|partage|share|actu|publicité|télécharger|download)',\
                                ur'(recommend[ations]?|toutes?.*marques?|si.*vous.*avez|promotion|présentation)',\
                                ur'(elections?|(pour)?.*bénéfici[er].*|(vo[tres])?.*remise|(cette)?.*offre.*est.*valable)',\
                                ur'(automatiqu[ement].*déduite?|pass[es].*vo[stre].*commandes?|derniere?s? )',\
                                ur'(nous.*avons.*le.*plaisir|(à.*)?decouv[zonsriert]|les.nouveaut[ée]s?)',\
                                ur'(rencontr[ezntons]|grandes?.*marques?|(particip|choisi)[ezstonsi]|sondage|décideurs?)',\
                                ur'(choix|plus.*d\'information|autres?.*(actus|nouvelles?)|analyses?|infographies?)'
    ]

    URL_FQDN_REGEXP =   [
                                    ur'(news(letter)?|trip|sales?|offer|journal|event|post|asseccories|rasprodaga)', \
                                    ur'(global|response|click|shop|sale|flight|hotel|cit(y|ies)|campaign|bouquet)', \
                                    ur'(celebration|friday|binus|magazin|cheap|subscibe|manage|feed|list|blog)', \
                                    ur'(programm|online|create|amazon|meetup|book|flowers|app|connect|emea|habrahabr|media)', \
                                    ur'(citilink|ulmart|lamoda|nero-|vip|ideel|quora|yves-rocher|fagms.de|wix.com|papers)', \
                                    ur'(opportunity|whites+|chance|email|practice|yr-ru|us\d-|stanford|brands+|labels+)', \
                                    ur'(look-at-media|digest|the-village|ozon.ru|enter.ru)'

    ]

    URL_TXT_REGEXP = [
                                    ur'(cheap[est]|prices?|clothes?|action|shoes?|women|label|brand|zhensk|odezhd)', \
                                    ur'(campaign|rasprodaga|requirements|choice|personal|track|click|customer|product)', \
                                    ur'(meetup|facebook|twitter|pinterest|vk|odnoklassinki|google)_footer', \
                                    ur'(training|mailing|modify|unsub|newsletter|catalog|mdeia|graphics|announcement)', \
                                    ur'(utm_medium=|utm_source=|utm_term=|utm_campaign=|applications+|upn=|aspx\?)', \
                                    ur'(shop|magazin|collections+|lam|(mail_link_)?track(er)?|EMID=|EMV=|genders)'

    ]

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
                         'pattern_score': ['mime'],
                         'subject'      : ['score','len','encoding','upper','titled','checksum'],
                         'dmarc'        : ['spf','score','x_score'],
                         'emarket'      : ['score','flag','domains_score'],
                         'url'          : ['score','count','avg_len','distinct_count','sender_count', 'avg_query_len','sim'],
                         'list'         : ['score', 'ext_headers_set', 'sender_flag', 'precedence', 'reply_to'], #delivered-to
                         'attaches'     : ['count'],
                         'originator'   : ['checksum'],  # ['checksum','eq_to_dkim']
                         'content'      : ['compress_ratio','avg_entropy','txt_score','html_checksum']
        }

        for n, key in enumerate(features_map.keys(),start=1):

            if key == 'pattern_score':
                features = ['get_'+name+'_'+key for name in features_map[key]]
                checker_obj = self
            else:
                features = ['get_'+key+'_'+name for name in features_map[key]]
                checker_obj = checkers.__getattribute__(key.title()+'Checker')
                checker_obj = checker_obj(self)

            functions_map = [(name.lstrip('get_'), getattr(checker_obj, name, lambda : self.INIT_SCORE)) for name in features]

            for name, f in functions_map:
                feature_value = self.INIT_SCORE
                logger.debug(name)
                logger.debug(f)
                try:
                    feature_value = f()
                except Exception as err:
                    logger.error(str(f)+' : '+str(err))
                    pass

                self.__setattr__(name, feature_value)

        logger.debug("total vect len : ".upper()+str(len(self.__dict__.items())-1))
        non_zero = [v for k,v in self.__dict__.items() if float(v) !=0.0 ]
        logger.debug("non_zero features count : ".upper()+str(len(non_zero)))

    def __str__(self):
        return('INFO')


    def get_mime_pattern_score(self):

        mime_score = self.INIT_SCORE
        if not self.msg.is_multipart():
            return mime_score

        # all infos are attractive nice multiparts...
        mime_score += self.PENALTY_SCORE

        first_content_type = self.msg.get('Content-Type')
        if 'text/html' in first_content_type and re.search('utf-8', first_content_type, re.I):
            mime_score += self.PENALTY_SCORE

        mime_skeleton = self.get_mime_struct()
        logger.debug('MIME STRUCT: '+str(mime_skeleton))
        if (mime_skeleton.keys()).count('text/html') and 'inline' in mime_skeleton.get('text/html'):
            mime_score += self.PENALTY_SCORE



        return mime_score


'''''
if __name__ == "__main__":

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    try:
        test = InfoPattern(env)
        vector = test.run()
        logger.debug(str(vector))


    except Exception as details:
        raise
'''''


	
			



