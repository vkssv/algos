#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""Keeps and applies vectorising rules for nets."""

import os, sys, logging, common
from pattern_wrapper import BasePattern

#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class NetsPattern(BasePattern):

    def run(self, score):

        vector_dict = {}

        # 1. Received headers

        # get crc32 of only unique headers and their values
        excluded_heads = [
                            'Received', 'From', 'Subject', 'Date', 'MIME-Version', 'To', 'Message-ID', 'Cc','Bcc','Return-Path',\
                            'X-Drweb-.*', 'X-Spam-.*', 'X-Maild-.*','Resent-.*'
                            ]

        vector_dict.update(common.get_heads_crc(self.msg.items(), excluded_heads))
        logger.debug('\t----->'+str(vector_dict))

        # keep the count of traces fields
        vector_dict ["traces_num"] = self.msg.keys().count('Received')
        logger.debug('\t----->'+str(vector_dict))

        # basic parsing and dummy checks with regexps (takes only first n_rcvds headers)
        n_rcvds = 2
        rcvd_values = tuple(self.msg.get_all('Received'))[-1*n_rcvds:]
        #print('rcvd_values: '+str(rcvd_values))
        parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in rcvd_values[:]])
        #logger.debug('parsed_rcvds -->'+str(parsed_rcvds))

        vector_dict ["trace_rule"] = 0
        logger.debug('\t----->'+str(vector_dict))
        rcvd_rules = [
                        r'(public|airnet|wi-?fi|a?dsl|dynamic|pppoe|static|account)+',
                        r'(\(|\s+)(([a-z]+?)-){0,2}(\d{1,3}-){1,3}\d{1,3}([\.a-z]{1,63})+\.(ru|in|id|ua|ch)'
        ]

        for rule in rcvd_rules:
            if filter(lambda l: re.search(rule, l), parsed_rcvds):
                vector_dict ["trace_rule"] = 1


        # deep parsing and checks for some wellknown spammers tricks with To: header
        vector_dict ['smtp_to'] = 0
        vector_dict ['to'] = 0
        logger.debug('\t----->'+str(vector_dict))

        to_values, to_addrs = common.get_addr_fields(self.msg.get('To'))
        if to_values and filter(lambda x: re.search(r'undisclosed-recipients',x,re.I), to_values):
            vector_dict['to'] += score
            logger.debug('\t----->'+str(vector_dict))

        if not to_addrs:
            vector_dict['to'] += score
            logger.debug('\t----->'+str(vector_dict))

        smtp_to_list = filter(lambda x: x, tuple([(r.partition('for')[2]).strip() for r in parsed_rcvds]))

        if smtp_to_list:
            trace_str_with_to = smtp_to_list[0]
            smtp_to = re.search(r'<(.*@.*)?>', trace_str_with_to)
            if smtp_to:
                smtp_to = smtp_to.group(0)
                #logger.debug(smtp_to)

                if len(to_addrs) == 1 and smtp_to != to_addrs[0]:
                    vector_dict['to'] += score
                    logger.debug('\t----->'+str(vector_dict))

                elif len(to_addrs) > 2 and smtp_to != '<multiple recipients>':
                    vector_dict['to'] += score
                    logger.debug('\t----->'+str(vector_dict))

        else:
            vector_dict ['smtp_to'] += 1
            logger.debug('\t----->'+str(vector_dict))

        # get crc32 from first N trace fields
        rcvd_vect = tuple([rcvd.partition('by')[0] for r in parsed_rcvds])
        logger.debug(rcvd_vect)
        vector_dict.update(common.get_trace_crc(rcvd_vect))
        logger.debug('\t----->'+str(vector_dict))

        # 2. Subject checks

        features = ['style','score','checksum']
        features_dict = dict(map(lambda x,y: ('subj_'+x,y), features, [BasePattern.INIT_SCORE]*len(features)))

        if self.msg.get('Subject'):

            total_score = BasePattern.INIT_SCORE
            unicode_subj, norm_words_list = common.get_subject(self.msg("Subject"))

            nets_patterns = [
                                # dingbats
                                ur'(Meetup|Do\+you\+know|Congrat(s|uleta)\s+([\w-]{2,10}\s+){1,3}|you\s+g[eo]t)',
                                ur'(See\s+([\w-]{2,10}\s+){1,3}\s+new|Welcome.*to|stay\s+in\s+touch\s+with|meet\s+the\s+new)',
                                ur'^([\w-\s]{2,10}){1,2}\s*[,:]\s*.*(please\s+add|try\s+free|join\s+these|are\s+looking\s+for)',
                                ur'(Google+|LinkedIn|Twitter|Facebook|Viadeo|vk.com|vkontakte|odnoklassniki|create\s+community)',
                                ur'(top\s+post|this\s+week|viewed\s+your|added\s+you|you\s+miss(ed)?|discussion\s+on|connection)',
                                ur'(invitation|reminder|(a)?wait(ing)?\s+(for\s+)?(you|your)?\s+(response)?|suggested\s+for)',
                                ur'(comment\s+on|check\s+out|tomorrow|(mon|thurs|wednes|tues|sun|satur|fri)day|new\s+.*\s+group)',
                                ur'^(Invitation|Reminder)\s*:\s.*$',
                                ur'(you\s+g[eo]t|job\s+on|endorsed|try\s+a\s+free|top\s+pages|blog|profile)',
                                ur'(Вы\s+знаете|Вернуться\s+на|предложение)',
                                ur'(Ajoutez\s+)'
                            ]


            subj_score, upper_flag, title_flag = common.basic_subjects_checker(unicode_subj,subject_rule,score)
            # almoust all words in subj string are Titled
            if (len(norm_words_list) - title_flag ) < 5:
                features_dict['subj_style'] = 1

            features_dict['subj_score'] = total_score + subj_score

            # take crc32 only from words in lower case, cause Names and etc. are titled here

            subj_trace = ''.join(tuple(filter(lambda word: not word.istitle(), norm_words_list))
            if subj_trace:
                features_dict['subj_checksum'] = binascii.crc32(subj_trace)

        vector_dict.update(features_dict)
        logger.debug('\t----->'+str(vector_dict))

        # 3. List checks and some other RFC 5322 compliences checks for headers

        temp_dict = dict([('list',score), ('sender',0), ('preamble',0), ('disp-notification',0)])
        logger.debug('\t----->'+str(temp_dict))

        if filter(lambda list_field: re.search('(List|Errors)(-.*)?', list_field), self.msg.keys()):
            # well, this unique spam author respects RFC 2369, his creation deservs more attentive check
            temp_dict['list'] = common.basic_lists_checker(self.msg.items(), score)
            logger.debug('\t----->'+str(temp_dict))

        elif (self.msg.keys().count('Sender') and self.msg.keys().count('From')):
            # if we don't have List header From = Sender (RFC 5322),
            # MUA didn't generate Sender field cause of redundancy
            temp_dict ['sender'] = 1
            logger.debug('\t----->'+str(temp_dict))

        if self.msg.preamble and not re.search('This\s+is\s+a\s+(crypto.*|multi-part).*\sMIME\s.*', self.msg.preamble,re.I):

            temp_dict ['preamble'] = 1
            logger.debug('\t----->'+str(temp_dict))

        vector_dict.update(temp_dict)
        logger.debug('\t----->'+str(vector_dict))

        if (self.msg.keys()).count('Disposition-Notification-To'):
            vector_dict ['disp-notification'] = 1
            logger.debug('\t----->'+str(vector_dict))

        # 4. crc for From values
        vector_dict['from']=0
        logger.debug('\t----->'+str(vector_dict))

        if self.msg.get('From'):
            from_values = common.get_addr_fields(self.msg.get('From'))[0]

            if from_values:
                vector_dict['from'] = binascii.crc32(reduce(add,from_values[:1]))
                logger.debug('\t----->'+str(vector_dict))

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

			


		


	
			



