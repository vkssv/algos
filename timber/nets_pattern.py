#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
""" Keeps and applies vectorising rules for nets. """

import os, sys, logging, re, binascii, string, math

from operator import add
from pattern_wrapper import BasePattern
from collections import OrderedDict, Counter

INIT_SCORE = self.INIT_SCORE

#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

class NetsPattern(BasePattern):
    """
    Pattern class for build vectors, based on typical features of the
    notifications from SNs ( call them "nets" ):

        -- if email looks like notification from SN, it's vector will contain
            values, which are mostly don't equal to zero ;
        -- vector will contain almoust only zeros, if email doesn't
            have these sets of features ;
    """
    RCVDS_NUM = 3

    def run(self, score):

        vector_dict = OrderedDict()

        # 1. "Received:" Headers
        logger.debug('>>> 1. RCVD_CHECKS:')

        # get crc32 of only unique headers and their values
        excluded_heads = [
                            'Received', 'X-Received', 'From', 'Subject', 'Date', 'MIME-Version', 'To', 'Message-ID',\
                            'Delivered-To', 'Authentication-Results', 'DKIM-Signature','Content-Type'
                            ]

        vector_dict.update(self._get_all_heads_crc_(self._msg.items(), excluded_heads))
        logger.debug('\t----->'+str(vector_dict))

        # keep the count of traces fields
        vector_dict ["traces_num"] = self._msg.keys().count('Received')
        logger.debug('\t----->'+str(vector_dict))


        # 2. "To:", "SMTP RCPT TO:" Headers
        logger.debug('>>> 2. DESTINATOR CHECKS:')
        vector_dict['to'] = self.get_rcpts_metrics(score ,self._msg.get_all('Received'), self._msg.get_all('To'))

        # get crc32 from first N trace fields
        rcvd_vect = tuple([r.partition('by')[0] for r in self._get_rcvds_(self, RCVDS_NUM)])
        logger.debug(rcvd_vect)
        vector_dict.update(self._get_trace_crc_(rcvd_vect))
        logger.debug('\t----->'+str(vector_dict))


        # 3. DMARC checks
        logger.debug('>>> 3. SPF/DKIM_CHECKS:')

        dmarc_dict_checks, dkim_domain = self.get_dmarc_metrics(self._msg.items(), score)
        vector_dict.update(dmarc_dict_checks)

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


        # 4. special headers checks
        logger.debug('>>> 4. Specific SN-headers checks:')

        heads_pattern = r'^X-(LinkedIn(-.*)?|FACEBOOK(-.*)?|MEETUP(-.*)*|CRITSEND-ID|Auto-Response-Suppress)$'
        known_senders = [r'ZuckMail', r'PHPMailer', r'ONE\s+mailer', r'GreenArrow']

        heads_score, known_mailer_flag = self.basic_headers_cheker(heads_pattern, known_senders, self._msg.items(), score)

        vector_dict['emarket_heads_score'] = heads_score
        vector_dict['known_sender'] = known_mailer_flag


        # 5. Subject checks
        logger.debug('>>> 5. SUBJECT CHECKS:')
        features = ('style', 'score', 'encoding', 'checksum')
        features_dict = dict(map(lambda x,y: ('subj_'+x,y), features, [INIT_SCORE]*len(features)))

        if self._msg.get('Subject'):

            total_score = self.INIT_SCORE
            unicode_subj, norm_words_list, encodings = self._get_decoded_subj_(self._msg.get("Subject"))

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


            subj_score, upper_flag, title_flag = self.get_subject_metrics(unicode_subj, subject_rule, score)
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
            logger.debug('subj_trace--->'+subj_trace)
            if subj_trace:
                features_dict['subj_checksum'] = binascii.crc32(subj_trace)

        vector_dict.update(features_dict)
        logger.debug('\t----->'+str(vector_dict))


        # 6. crc for From values
        logger.debug('>>> 6. ORIGINATOR CHECKS:')
        vector_dict['from']=0
        logger.debug('\t----->'+str(vector_dict))

        if self._msg.get('From'):
            from_values = self._get_addr_values_(self._msg.get('From'))[0]

            if from_values:
                vector_dict['from'] = binascii.crc32(reduce(add,from_values))
                logger.debug('\t----->'+str(vector_dict))


        # 7. simple List fields checks
        logger.debug('>>> 7. LIST CHECKS:')
        list_features = ('basic_checks', 'delivered')
        list_features_dict = dict(map(lambda x,y: ('list_'+x,y), list_features, [INIT_SCORE]*len(list_features)))

        logger.debug('\t----->'+str(list_features_dict))

        if filter(lambda list_field: re.match('(List|Errors)(-.*)?', list_field,re.I), self._msg.keys()):

            list_features_dict['basic_checks'] = self.get_list_metrics(self._msg.items(), rcvd_vect, score)
            logger.debug('\t----->'+str(list_features_dict))

        # in general nets are very personal, so check Delivered-To may be a feature
        keys = tuple(filter(lambda k: self._msg.get(k), ['Delivered-To','To']))
        addr_dict = dict([(k, (self._get_addr_values_(self._msg.get(k))[1])[0]) for k in keys])
        logger.debug('>>>>>'+str(addr_dict))
        if addr_dict.get('Delivered-To') and addr_dict.get('Delivered-To') != addr_dict.get('To'):
            list_features_dict['delivered'] = 1

        vector_dict.update(list_features_dict)
        logger.debug('\t----->'+str(vector_dict))


        # 8. Check MIME headers
        logger.debug('>>> 8. MIME CHECKS:')

        mime_features = ('mime_score', 'checksum', 'att_score', 'att_count', 'nest_level')
        mime_dict = OrderedDict(map(lambda x,y: (x,y), mime_features, [INIT_SCORE]*len(mime_features)))

        if self._msg.is_multipart():
            mime_dict['mime_score'] = score

            mime_skeleton = self._get_mime_struct_(self)

            # some particular rules for SN emails
            # presence of typical mime-parts for infos
            frequent_struct = set(['multipart/alternative', 'text/plain', 'text/html'])
            current_struct = set(mime_skeleton.keys())
            if frequent_struct == current_struct:
                mime_dict['mime_score'] += score
                for mime_type in filter(lambda k: k.startswith('text'), frequent_struct):
                    if filter(lambda item: re.match(r'(text|html)-body', item, re.I), mime_skeleton.get(mime_type)):
                        mime_dict['mime_score'] += score

            # weak metric probably
            if filter(lambda marker_head: list(current_struct).count(marker_head), ['text/calendar', 'application/isc']):
                mime_dict['mime_score'] += score

            attach_regs = [
                                r'(method\s?=|format\s?=\s?flowed\s?;\s?delsp\s?=\s/yes)'
            ]

            logger.debug(str(mime_skeleton))
            count, att_score, in_score = self.get_attach_metrics(mime_skeleton.values(), attach_regs, score)
            mime_dict['att_count'] = count
            mime_dict['att_score'] = att_score
            mime_dict['checksum'] = self._get_mime_crc_(mime_skeleton)

            # helps to outline difference between spams, which were made very similar to nets
            mime_dict['nest_level'] = self._get_nest_level_()
            #if BasePattern.get_nest_level(self) <= NEST_LEVEL_THRESHOLD:
            #    mime_dict['nest_level'] = score


        vector_dict.update(mime_dict)
        logger.debug('\t----->'+str(vector_dict))


        # 9. URL CHECKS
        logger.debug('>>> 9. URL_CHECKS:')

        urls_list = self._get_url_list_(self)
        logger.debug('URLS_LIST >>>>>'+str(urls_list))
        if urls_list:

            domain_regs = [
                                ur'(www\.)?(meetup\.com|odnoklassniki\.ru|vk\.com|my\.mail\.ru|facebook\.com)',
                                ur'(www\.)?(linkedin\.com|facebook\.com|linternaute\.com|blablacar\.com)',
                                ur'(www\.)?(youtube\.com|plus\.google\.com|twitter\.com|pinterest\.com|tumblr\.com)',
                                ur'(www\.)?(instagram\.com|flickr\.com|vine\.com|tagged\.com|ask\.fm|meetme\.com)',
                                ur'(www\.)?classmates'
                            ]

            regs =  [
                                ur'\?(find-friends|learn-more|home\.php|submit|simpleredirect)',
                                ur'loc=(facepile|profile_pic|cta|reminder|tracking|email|validate_e?mail\?)',
                                ur'(formlink|jobs|events|btn|teaser|profile|logo_|userpic)',
                                ur'(eml-skills_endorsements-btn-0-new_teaser_add|grp_email_subscribe_new_posts)'

                    ]

            basic_features_dict, netloc_list = self.get_url_metrics(urls_list, rcvd_vect, score, domain_regs, regs)

            urls_features = ('path_sim', 'ascii', 'avg_length')
            urls_dict = OrderedDict(map(lambda x,y: (x,y), urls_features, [INIT_SCORE]*len(urls_features)))

            url_lines = [ ''.join(u._asdict().values()) for u in urls_list ]
            if filter(lambda x: x in string.printable, [line for line in url_lines]):
                urls_dict['ascii'] = score

            length_list = [ len(url) for url in [ obj.geturl() for obj in urls_list ]]
            urls_dict['avg_length'] = math.ceil((float(sum(length_list)))/float(len(urls_list)))

            obj_list = [url.__getattribute__('path') for url in urls_list]
            if math.ceil(float(len(set(obj_list)))/float(len(urls_list))) < 1.0:
                urls_dict['path_sim'] = score


        else:
            basics = ('url_count', 'url_score', 'distinct_count', 'sender_count')
            basic_features_dict = dict(map(lambda x,y: (x,y), basics, [INIT_SCORE]*len(basics)))

        vector_dict.update(basic_features_dict)
        vector_dict.update(urls_dict)


        # 10. check body
        regexp_list = [
                        ur'(say\s+(happy\s+birthday|congratulat[eions]|condolences?)|new\s+job|anniversary|meet)',
                        ur'(are\s+looking|tomorrow|introduc[eing]|l?earn\s+more|work\s+fast|die\s+young|(leave|be)\s+positive.*(in\s+your\s+coffin)?)',
                        ur'(fellow|new\s+friends|(build|create|new).*(community|group)|passion|(do\s+)?you\s+know.*(that\s+he\s+is ...)?)',
                        ur'(add\s+me\s+to|eat\s+me|drink\s+me|kill\s+me|connections?|more\s+people)'
        ]

        tags_map = {
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

        vector_dict.update(dict(zip(('html_score','html_checksum'), self.get_html_parts_metrics(score, tags_map))))
        vector_dict['text_score'] = self.get_text_parts_metrics(score, regexp_list)
        vector_dict['avg_ent'] = self.get_text_parts_avg_entropy()
        vector_dict['mime_compres_ratio'] = self.get_text_compress_ratio()

        return vector_dict


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

			


		


	
			



