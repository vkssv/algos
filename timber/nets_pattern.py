#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""Keeps and applies vectorising rules for nets."""

import os, sys, logging, common, re, binascii
from operator import add
from pattern_wrapper import BasePattern

INIT_SCORE = BasePattern.INIT_SCORE
MIN_TOKEN_LEN = BasePattern.MIN_TOKEN_LEN

#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class NetsPattern(BasePattern):

    def run(self, score):

        vector_dict = {}

        # 1. Received headers

        # get crc32 of only unique headers and their values
        excluded_heads = [
                            'Received', 'X-Received', 'From', 'Subject', 'Date', 'MIME-Version', 'To', 'Message-ID',\
                            'Delivered-To', 'Authentication-Results', 'DKIM-Signature','Content-Type'
                            ]

        vector_dict.update(common.get_all_heads_crc(self.msg.items(), excluded_heads))
        logger.debug('\t----->'+str(vector_dict))

        # keep the count of traces fields
        vector_dict ["traces_num"] = self.msg.keys().count('Received')
        logger.debug('\t----->'+str(vector_dict))

        # basic parsing and dummy checks with regexps (takes only first n_rcvds headers)
        n_rcvds = 3
        rcvd_values = tuple(self.msg.get_all('Received'))[-1*n_rcvds:]
        #print('rcvd_values: '+str(rcvd_values))
        parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in rcvd_values[:]])
        #logger.debug('parsed_rcvds -->'+str(parsed_rcvds))

        vector_dict['to'] = common.basic_rcpts_checker(score ,self.msg.get_all('Received'), self.msg.get_all('To'))

        # get crc32 from first N trace fields
        rcvd_vect = tuple([rcvd.partition('by')[0] for r in parsed_rcvds])
        logger.debug(rcvd_vect)
        vector_dict.update(common.get_trace_crc(rcvd_vect))
        logger.debug('\t----->'+str(vector_dict))

        # DMARC checks
        dmarc_dict_checks, dkim_domain = common.basic_dmarc_checker(self.msg.items(), score)
        vector_dict.update(dmarc_dict_checks)

        # special headers checks
        typical = ['LinkedIn(-.*)?','FACEBOOK(-.*)?','MEETUP(-.*)*','CRITSEND-ID','Auto-Response-Suppress']
        matched_list=[]
        for r in typical:
            matched_list = filter(lambda h: re.match(r'(X-)?'+r,h,re.I), self.msg.keys())

        vector_dict['social'] = len(matched_list)


        # in general sender's clients names are the same
        vector_dict['mailer'] = INIT_SCORE
        if self.msg.keys().count('X-Mailer'):
            vector_dict['mailer'] = binascii.crc32((self.msg.get('X-Mailer')).strip())

        # take the name from DKIM heads, it's very expensive for spammers to sign their bulk
        known_domains = [
                            r'.*\.vk\.com',\
                            r'.*\.facebook.*\.com',\
                            r'odnoklassniki\.ru',\
                            r'plus\.google\.com',\
                            r'.*\.linkedin\.com', \
                            r'.*\.meetup\.com', \
                            r'.*\.viadeo\.com'
                        ]


        vector_dict['known_domain'] = len(filter(lambda regexp: re.search(regexp, dkim_domain, re.I), known_domains))

        # 2. Subject checks

        features = ['style','score','encoding','checksum']
        features_dict = dict(map(lambda x,y: ('subj_'+x,y), features, [INIT_SCORE]*len(features)))

        if self.msg.get('Subject'):

            total_score = BasePattern.INIT_SCORE
            unicode_subj, norm_words_list, encodings = common.get_subject(self.msg.get("Subject"))

            subject_rule = [
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


            subj_score, upper_flag, title_flag = common.basic_subjects_checker(unicode_subj,subject_rule,score)
            # almoust all words in subj string are Titled
            if (len(norm_words_list) - title_flag ) < 5:
                features_dict['subj_style'] = 1

            features_dict['subj_score'] = total_score + subj_score

            # nets statistically have subj lines in utf-8 or pure ascii
            if len(set(encodings)) == 1 and set(encodings).issubset(['utf-8','ascii']):
                features_dict['encoding'] = 1

            # take crc32 only from words in lower case, cause Names and etc. are titled here
            norm_words_list = tuple(filter(lambda word: not word.istitle(), norm_words_list))
            subj_trace = ''.join(tuple([w.encode('utf-8') for w in norm_words_list]))
            print('subj_trace--->'+subj_trace)
            if subj_trace:
                features_dict['subj_checksum'] = binascii.crc32(subj_trace)

        vector_dict.update(features_dict)
        logger.debug('\t----->'+str(vector_dict))

        # 4. crc for From values
        vector_dict['from']=0
        logger.debug('\t----->'+str(vector_dict))

        if self.msg.get('From'):
            from_values = common.get_addr_values(self.msg.get('From'))[0]

            if from_values:
                vector_dict['from'] = binascii.crc32(reduce(add,from_values))
                logger.debug('\t----->'+str(vector_dict))

        # 5. simple List fields checks

        list_features = ['basic_checks', 'delivered']
        list_features_dict = dict(map(lambda x,y: ('list_'+x,y), list_features, [INIT_SCORE]*len(list_features)))

        logger.debug('\t----->'+str(list_features_dict))

        if filter(lambda list_field: re.match('(List|Errors)(-.*)?', list_field,re.I), self.msg.keys()):
            # well, this unique spam author respects RFC 2369, his creation deservs more attentive check
            list_features_dict['basic_checks'] = common.basic_lists_checker(self.msg.items(), score)
            logger.debug('\t----->'+str(list_features_dict))


        # in general nets are very personal, so check Delivered-To may be a feature
        keys = tuple(filter(lambda k: self.msg.get(k), ['Delivered-To','To']))
        addr_dict = dict([(k, (common.get_addr_values(self.msg.get(k))[1])[0]) for k in keys])
        print('>>>>>'+str(addr_dict))
        if addr_dict.get('Delivered-To') and addr_dict.get('Delivered-To') != addr_dict.get('To'):
            list_features_dict['delivered'] = 1

        vector_dict.update(list_features_dict)
        logger.debug('\t----->'+str(vector_dict))

        '''
        # 5. Check MIME headers

        mime_checks = [(x,0) for x in ['mime_spammness', 'att_count','att_score','in_score','nest_level']]
        mime_dict = dict(mime_checks)

        if self.msg.get('MIME-Version') and not self.msg.is_multipart():
            mime_dict['mime_spammness'] = score

        elif self.msg.is_multipart():

            attach_regs = [
                            r'(application\/(octet-stream|pdf|vnd.*|ms.*|x-.*)|image\/(png|gif|message\/))',
                            r'.*\.(exe|xlsx?|pptx?|txt|maild.*|docx?|html|js|bat|eml|zip|png|gif|cgi)',
                            ]

            mime_heads_vect = common.get_mime_info(self.msg)
            logger.debug(str(mime_heads_vect))
            count, att_score, in_score = common.basic_attach_checker(mime_heads_vect,attach_regs,score)
            mime_dict['att_count'] = count
            mime_dict['att_score'] = att_score
            mime_dict['in_score'] = in_score
            if common.get_nest_level(mime_heads_vect) > 2:
                mime_dict['nest_level'] = 1


        vector_dict.update(mime_dict)
        logger.debug('\t----->'+str(vector_dict))




        # analyse attachements extensions

        #vect_dict.update(common.get_body_skeleton(self.msg))
        '''

        return (vector_dict)


if __name__ == "__main__":

	formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
	ch = logging.StreamHandler(sys.stdout)
	ch.setLevel(logging.DEBUG)
	ch.setFormatter(formatter)
	logger.addHandler(ch)

	try:
		test=NetsPattern(env)
		vector = test.run()
		logger.debug(vector)


	except Exception as details:
		raise

			


		


	
			



