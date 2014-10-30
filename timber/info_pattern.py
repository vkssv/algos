#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Keeps and applies vectorising rules for infos.
If doc(email) is very similar to this pattern
its vector will be filled by "1" or score value > 0
or crc32 value for each feature, otherwise - "0" """

import os, sys, logging, common
from pattern_wrapper import BasePattern

# formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class InfoPattern(BasePattern):

    def run(self, score):

        vector_dict = {}

        # 1. Received headers

        # get crc32 of only unique headers and their values
        excluded_heads = [
                            'Received', 'Subject', 'From', 'Date', 'Received-SPF', 'To', 'Content-Type',\
                            'Authentication-Results', 'MIME-Version', 'DKIM-Signature', 'Message-ID', 'Reply-To'
                          ]
        vector_dict.update(common.get_heads_crc(self.msg.items(), excluded_heads))
        logger.debug('\t----->'+str(vector_dict))

        # keep the count of traces fields
        vector_dict ["traces_num"] = self.msg.keys().count('Received')
        logger.debug('\t----->'+str(vector_dict))

        # basic parsing and dummy checks with regexps (takes only first n_rcvds headers)
        n_rcvds = 0
        rcvd_values = tuple(self.msg.get_all('Received'))[-1*n_rcvds:]
        #print('rcvd_values: '+str(rcvd_values))
        parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in rcvd_values[:]])
        #logger.debug('parsed_rcvds -->'+str(parsed_rcvds))


        # get crc32 from first N trace fields
        rcvd_vect = tuple([rcvd.partition('by')[0] for r in parsed_rcvds])
        logger.debug(rcvd_vect)
        vector_dict.update(common.get_trace_crc(rcvd_vect))
        logger.debug('\t----->'+str(vector_dict))

        # DMARC checks
        vector_dict.update(common.basic_dmarc_checker(self.msg.items(), score)

        # Presense of X-EMID && X-EMMAIL
        em_names = ['X-EMID','X-EMMAIL']
        sc = 0
        pat = '^X-EM(ID|MAIL)$'

        if len(set(filter(lambda xx: re.match(pat,xx,re.I),self.msg.keys()))) == len(em_names):
            if self.msg.get('X-EMMAIL') == self.msg.get('To'):
                sc = 1

        em_dict = dict(map(lambda x,y: (x,y),em_names,[sc]*len(em_names)))
        vector_dict.update(em_dict)

        # 2. Subject checks

        if self.msg.get('Subject'):

            subject_rule = [
                                r'^(\xe2\x9c\x88|)!$',
                                r'[\d]{1,2}\s+[\d]{1,2}[0]{1,3}\s+.*',
                                r'-?[\d]{1,2}\s+%\s+.*',
                                r'[\d](-|\s+)?\S{1,4}(-|\s+)?[\d]\s+.*',
                                r'[\*-=\+~]{1,}\S+[\*-=\+~]{1,}',
                                r'(free.*(every?)*.*(order)*|online.*&.*(save)*(split?ed?)*.*has?le)',
	                            r'(cheap([est])?.*(satisf[ied]?)*.**customer|',
	                            r'(100%\s+GUARANTE?D|free.{0,12}(?:(?:instant|express|online|)',
	                            r'(dear.*(?:IT\W|Internet|candidate|sirs?|madam||travell?er|car\sshopper|web))',
                                r'.*(eml|spam).*',
                                # news
                            ]

            len_threshold = 70

            heads_dict = {key: value for (key, value) in self.msg.items()}
            subj_score, subj_trace = common.basic_subjects_checker(heads_dict, subject_rule, len_threshold, score)

            vector_dict ['subj_score'] = subj_score
            vector_dict ['subj_trace'] = subj_trace

        else:

            vector_dict ['subj_score'] = 1
            vector_dict ['subj_trace'] = 0

        logger.debug('\t----->'+str(vector_dict))
        # 3. List checks and some other RFC 5322 compliences checks for headers

        temp_dict = dict([('list',score), ('sender',0), ('disp-notification',0)])
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
        attach_score =0
        attach_regs = [
                        r'image\/(png|gif)',
                        r'.*\.(html|js|jpeg|png|gif|cgi)',
        ]

        mime_heads_vect = common.get_mime_info(msg)
        count, att_score, in_score = common.basic_attach_checker(mime_heads_vect,attach_regs,score)
        vector_dict['att_count'] = count
        vector_dict['att_score'] = att_score
        vector_dict['in_score'] = in_score
        vector_dict['nest_level'] = common.get_nest_level(mime_heads_vect)


if __name__ == "__main__":

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    try:
        test = InfoPattern(env)
        vector = test.run()
        logger.debug(vector)


    except Exception as details:
        raise

			


		


	
			



