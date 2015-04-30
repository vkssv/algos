#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-

import sys, logging, re

import checkers
from pattern_wrapper import BasePattern


logger = logging.getLogger('')
#logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(levelname)s %(funcName)s: %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#logger.addHandler(ch)

#from email import parser
#parser = parser.Parser()
#with open('','rb') as f:
#    M = parser.parse(f)


class NetsPattern(BasePattern):
    """
    Pattern class for build vectors, based on typical
    SN-notifications features ( call them "nets" ):

    -- if email looks like notification from SN, it's vector will contain
        values, which are mostly don't equal to zeros ;
    """

    AXIS_STRETCHING = 1.0

    EXCLUDED_HEADS = [
                        'Received', 'X-Received', 'From', 'Subject', 'Date', 'MIME-Version', 'To', 'Message-ID',\
                        'Delivered-To', 'Authentication-Results', 'DKIM-Signature','Content-Type'
    ]

    RCVDS_NUM = 3

    EMARKET_HEADS = r'((X-)?LinkedIn(-.*)?|FACEBOOK(-.*)?|MEETUP(-.*)?|CRITSEND-ID|MSFBL|(Acx)?SID|Auto-Response-Suppress)'

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
                        ur'(meetup|do.*you.*know|congrat[suleta].*([\w-]{2,10}.*){1,3}|you.*g[eo]t)', \
                        ur'(see.*([\w-]{2,10}.*){1,3}.*new|welcome.*to|stay.*in.*touch.*with|meet.*the.*new)', \
                        ur'((please)?.*add|try.*free|join.*these|are.*looking|bienvenue.*sur|confirm[ez])', \
                        ur'(here\'s.*what.*you.*missed|added.*you.*(on)?|vo[stre].*compte|twitter)',\
                        ur'(ajout[ez].*(une?).*(photo|adresse).*de.*profil|add.*(photo|email).*profile)',\
                        ur'(google\+|linkedin|twitter|facebook|viadeo|vk.com|vkontakte|odnoklassniki|create.*community)', \
                        ur'(top.*post|this.*week|viewed.*your|added.*you|you.*miss(ed)?|discussion.*on|connection)', \
                        ur'(invitation|reminder|(a)?wait(ing)?.*(for)?.*your?.*(response)?|suggested.*for)', \
                        ur'(comment.*on|check.*out|tomorrow|monday|thursday|wednesday|tuesday|sunday|saturday|friday|new.*group)', \
                        ur'(invitation|reminder|connaissez-vous|lier.*(un)?.*e-mail|au.*profil|suiv[ezr])', \
                        ur'(you.*g[eo]t|job.*on|endorsed|top.*pages|blog|profile?s?|répond[ezionsr])', \
                        ur'(say.*happy.*birthday|people.*are.*look(ing)?|top.*suggest[edions]|you.*missed.*from)', \
                        ur'(ajoutez|visité.*votre|profile.*views|last.*week|votre.*semaine|amie?s?|(re)?trouve[rztionse])'

    ]

    SUBJ_TITLES_THRESHOLD = 5

    ATTACHES_RULES = [  r'(method\s?=|format\s?=\s?flowed\s?;\s?delsp\s?=\s/yes)' ]

    TEXT_REGEXP_LIST = [
                            ur'(say.*happy.*birthday|congratulat[eions]|new.*job|anniversary|meet)', \
                            ur'(are.*looking|tomorrow|introduc[eing]?|your?.*connections?|network)', \
                            ur'(fellow|new.*friends|(build|create|new).*(community|group)|passion|do.*you.*know)', \
                            ur'(add.*me.*to.*connections|more.*people|collegs|add.*email|address|certificates?)',\
                            ur'(connaissez.*vous|vo[stre].*adresses?|camarades?|amie?s?|classe|anciens?.*collègues?)',\
                            ur'(ajout[ezionsr].*à|mes.*contacts|vo[stre].*réseau|abonnements?|personnalisées?)',\
                            ur'(invit[ed].*you|to.*connect|respond|(accept|ignor)[ed]?|d\'autres.*suggestions?)',\
                            ur'(forget.*to.*redeem|see.*the.*full.*list|connect.*on|respond|confirm[ez]|vo[ster]]compte)',\
                            ur'(afin.*de.*compléter|bouton.*ci-dessous|étape|notre.*suggestion|suiv[re]|vo[stre].*intérêts?)',\
                            ur'(post.*you.*might.*have.*miss[ed]|shar[ed].*public|photos?.*in.*album)'
    ]

    URL_FQDN_REGEXP =   [
                            ur'(www\.)?(meetup\.com|odnoklassniki\.ru|vk\.com|my\.mail\.ru|facebook\.com)', \
                            ur'(www\.)?(linkedin\.com|facebook\.com|linternaute\.com|blablacar\.com)', \
                            ur'(www\.)?(youtube\.com|plus\.google\.com|twitter\.com|pinterest\.com|tumblr\.com)', \
                            ur'(www\.)?(instagram\.com|flickr\.com|vine\.com|tagged\.com|ask\.fm|meetme\.com)', \
                            ur'(www\.)?classmates'

    ]

    URL_TXT_REGEXP = [
                        ur'\?(find-friends|learn-more|home\.php|submit|simpleredirect)', \
                        ur'loc=(facepile|profile_pic|cta|reminder|tracking|email|validate_e?mail\?)', \
                        ur'(formlink|jobs|events|btn|teaser|profile|logo_|userpic)', \
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

        super(NetsPattern, self).__init__(**kwds)

        features_map = {
                         'pattern_score': ['mime'],
                         'subject'      : ['score','encoding','upper','titled','checksum'],
                         'dmarc'        : ['spf','score'],
                         'emarket'      : ['score','flag','domains_score'],
                         'url'          : ['score','count','avg_len','distinct_count','sender_count','sim', 'avg_query_len'],
                         'list'         : ['score','delivered_to'],
                         'attaches'     : ['score','count'],
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
                try:
                    feature_value = f()
                except Exception as err:
                    logger.error(f.func_name+' : '+str(err))
                    pass

                self.__setattr__(name, feature_value)


    def __str__(self):
        return('NETS')

    def get_mime_pattern_score(self):

        mime_score = self.INIT_SCORE
        if not self.msg.is_multipart():
            return mime_score

        # check a presence of typical mime-parts for nets
        frequent_struct = set(['multipart/alternative', 'text/plain', 'text/html'])
        mime_skeleton = self.get_mime_struct()
        mime_keys = mime_skeleton.keys()

        current_struct = set(mime_keys)
        if frequent_struct == current_struct:
            mime_score += self.PENALTY_SCORE
            for mime_type in filter(lambda k: k.startswith('text'), frequent_struct):
                if filter(lambda item: re.match(r'(text|html)-body', item, re.I), mime_skeleton.get(mime_type)):
                    mime_score += self.PENALTY_SCORE

        # weak metric probably will work only for letters from Meetup
        if filter(lambda marker_head: list(current_struct).count(marker_head), ['text/calendar', 'application/isc']):
            mime_score += self.PENALTY_SCORE

        return mime_score


		


	
			



