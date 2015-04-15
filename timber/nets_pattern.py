#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
""" Keeps and applies vectorising rules for nets. """

import os, sys, logging, re, binascii, string, math

from operator import add
from pattern_wrapper import BasePattern
from collections import OrderedDict, Counter

#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

class NetsPattern(BasePattern):
    """
    Pattern class for build vectors, based on typical
    SN-notifications features ( call them "nets" ):

        -- if email looks like notification from SN, it's vector will contain
            values, which are mostly don't equal to zeros ;
    """
    EXCLUDED_HEADS = [
                        'Received', 'X-Received', 'From', 'Subject', 'Date', 'MIME-Version', 'To', 'Message-ID',\
                        'Delivered-To', 'Authentication-Results', 'DKIM-Signature','Content-Type'
    ]

    RCVDS_NUM = 3

    EMARKET_HEADS = r'^X-(LinkedIn(-.*)?|FACEBOOK(-.*)?|MEETUP(-.*)*|CRITSEND-ID|Auto-Response-Suppress)$'

    KNOWN_MAILERS = [ r'ZuckMail', r'PHPMailer', r'ONE\s+mailer', r'GreenArrow' ]

    KNOWN_DOMAINS = [
                            r'.*\.vk\.com',\
                            r'.*\.twitter\.com',\
                            r'.*\.facebook.*\.com',\
                            r'.*\.odnoklassniki\.ru',\
                            r'.*\.plus\.google\.com',\
                            r'.*\.linkedin\.com', \
                            r'.*\.meetup\.com', \
                            r'.*\.viadeo\.com'
    ]

    SUBJ_RULES = [
                                # dingbats
                                ur'(Meetup|Do\+you\+know|Congrat(s|uleta)\s+([\w-]{2,10}\s+){1,3}|you\s+g[eo]t)',
                                ur'(See\s+([\w-]{2,10}\s+){1,3}\s+new|Welcome.*to|stay\s+in\s+touch\s+with|meet\s+the\s+new)',
                                ur'^([\w\s-]{2,10}){1,2}\s*[,:]\s*.*(please\s+add|try\s+free|join\s+these|are\s+looking\s+for)',
                                ur'(Google+|LinkedIn|Twitter|Facebook|Viadeo|vk.com|vkontakte|odnoklassniki|create\s+community)',
                                ur'(top\s+post|this\s+week|viewed\s+your|added\s+you|you\s+miss(ed)?|discussion\s+on|connection)',
                                ur'(invitation|reminder|(a)?wait(ing)?\s+(for\s+)?(you|your)?\s+(response)?|suggested\s+for)',
                                ur'(comment\s+on|check\s+out|tomorrow|(mon|thurs|wednes|tues|sun|satur|fri)day|new\s+.*\s+group)',
                                ur'^(Invitation|Reminder)\s*:\s.*$',
                                ur'(you\s+g[eo]t|job\s+on|endorsed|try\s+a\s+free|top\s+pages|blog|profil(e)?)',
                                ur'(Вы\s+знаете|Вернуться\s+на|предложение|недел.*)',
                                ur'(У\s+вас\s+.*\s+больше\s+друзей)',
                                ur'(Say\s+happy\s+birthday|people\s+are\s+look(ing)?|top\s+suggested|you\s+missed\s+from)',
                                ur'(Ajoutez\s+|visité\s+votre|profile\s+views\s+|last\s+week|votre\s+semaine)'
    ]

    SUBJ_FUNCTION = lambda z,y: y[len(y)/2:]
    SUBJ_TITLES_THRESHOLD = 5

    ATTACHES_RULES = [r'(method\s?=|format\s?=\s?flowed\s?;\s?delsp\s?=\s/yes)']

    TEXT_REGEXP_LIST = [
                        ur'(say\s+(happy\s+birthday|congratulat[eions]|condolences?)|new\s+job|anniversary|meet)',
                        ur'(are\s+looking|tomorrow|introduc[eing]|l?earn\s+more|work\s+fast|die\s+young|(leave|be)\s+positive.*(in\s+your\s+coffin)?)',
                        ur'(fellow|new\s+friends|(build|create|new).*(community|group)|passion|(do\s+)?you\s+know.*(that\s+he\s+is ...)?)',
                        ur'(add\s+me\s+to|eat\s+me|drink\s+me|kill\s+me|connections?|more\s+people)'

    HTML_TAGS_MAP = {

                            'table' :{
                                    'border'      : '0',
                                    'cellpadding' : '0',
                                    'cellspacing' : '0',
                                    'width'       : '\d{1,2}[^%](px)?'
                        },
                        'img'   :{
                                    'src'         : '(logo|notification?|photo|bu?tt?o?n|icon|person|contacts|email|profile|account|member|group|api)',
                                    'alt'         : '(accounts?|Google\s+Plus|Blog|Facebook|LinkedIn|Twitter|YouTube|Logo.*|Meetup|L\'Internaute|''|(\w{1-10}\s*){1,3})',
                                    'style'       : 'display:block'

                        }

    }

    URL_FQDN_REGEXP =   [
                                ur'(www\.)?(meetup\.com|odnoklassniki\.ru|vk\.com|my\.mail\.ru|facebook\.com)',
                                ur'(www\.)?(linkedin\.com|facebook\.com|linternaute\.com|blablacar\.com)',
                                ur'(www\.)?(youtube\.com|plus\.google\.com|twitter\.com|pinterest\.com|tumblr\.com)',
                                ur'(www\.)?(instagram\.com|flickr\.com|vine\.com|tagged\.com|ask\.fm|meetme\.com)',
                                ur'(www\.)?classmates'

    ]

    URL_TXT_REGEXP = [
                                ur'\?(find-friends|learn-more|home\.php|submit|simpleredirect)',
                                ur'loc=(facepile|profile_pic|cta|reminder|tracking|email|validate_e?mail\?)',
                                ur'(formlink|jobs|events|btn|teaser|profile|logo_|userpic)',
                                ur'(eml-skills_endorsements-btn-0-new_teaser_add|grp_email_subscribe_new_posts)'
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
                         'score'        : ['mime'],
                         'subject'      : ['score','encoding','style','checksum'],
                         'emarket'      : ['score','flag','domains_score'],
                         'url'          : ['score','count','avg_len','distinct_count','sender_count','sim', 'avg_query_len'],
                         'list'         : ['score','delivered-to']
                         'attaches'     : ['score','count'],
                         'originator'   : ['checksum'],  # ['checksum','eq_to_dkim']
                         'content'      : ['compress_ratio','avg_entropy','txt_score','html_score','html_checksum']
        }

        logger.debug('Start vectorize msg with rules from InfoPattern...')

        for n, key in enumerate(features_map.keys(),start=1):
            logger.debug(str(n)+'. Add '+key.upper()+' features attributes to msg-vector class: '+str(self.__class__))

            if key == 'score':
                features = ['get_'+name+'_'+key for name in features_map[key]]
                checker_obj = self
            else:
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


    def get_mime_score(self):

        self.mime_score = self.INIT_SCORE
        # 8. Check MIME headers
        logger.debug('>>> 8. MIME CHECKS:')
        # presence of typical mime-parts for infos
        frequent_struct = set(['multipart/alternative', 'text/plain', 'text/html'])
        current_struct = set(mime_skeleton.keys())
        if frequent_struct == current_struct:
            self.mime_score += self._penalty_score
            for mime_type in filter(lambda k: k.startswith('text'), frequent_struct):
                if filter(lambda item: re.match(r'(text|html)-body', item, re.I), mime_skeleton.get(mime_type)):
                    self.mime_score += self._penalty_score

            # weak metric probably
            if filter(lambda marker_head: list(current_struct).count(marker_head), ['text/calendar', 'application/isc']):
                self.mime_score += self._penalty_score


'''''

if __name__ == "__main__":

	formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
	ch = logging.StreamHandler(sys.stdout)
	ch.setLevel(logging.DEBUG)
	ch.setFormatter(formatter)
	logger.addHandler(ch)

	try:
		test=NetsPattern(env)
		vector = test.run()
		logger.debug(str(vector))


	except Exception as details:
		raise

			
'''''

		


	
			



