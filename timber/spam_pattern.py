#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""Keeps and applies vectorising rules for spams."""

import os, sys, logging, re, common, binascii, urllib
from operator import add
from pattern_wrapper import BasePattern
from collections import OrderedDict
INIT_SCORE = BasePattern.INIT_SCORE
MIN_TOKEN_LEN = BasePattern.MIN_TOKEN_LEN
MAX_SUBJ_LEN = 5
MIN_SUBJ_LEN = 70

# formatter_debug = logging.Formatter('%(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class SpamPattern(BasePattern):

    def run(self, score):

        vector_dict = OrderedDict()

        # 1. Received headers

        # get crc32 of only unique headers and their values
        logger.debug('>>>RCVD_CHECKS:')
        excluded_heads = [
                            'Received', 'From', 'Subject', 'Date', 'MIME-Version', 'To', 'Message-ID', 'Cc','Bcc','Return-Path',\
                            'X-Drweb-.*', 'X-Spam-.*', 'X-Maild-.*','Resent-.*'
                            ]
        logger.debug(str(self.msg.items()))
        vector_dict.update(common.get_all_heads_crc(self.msg.items(), excluded_heads))
        logger.debug('\t----->'+str(vector_dict))

        # keep the count of traces fields
        vector_dict ["traces_num"] = self.msg.keys().count('Received')
        logger.debug('\t----->'+str(vector_dict))

        # basic parsing and dummy checks with regexps (takes only first n_rcvds headers)


        vector_dict ["trace_rule"] = BasePattern.INIT_SCORE
        logger.debug('\t----->'+str(vector_dict))
        rcvd_rules = [
                        r'(public|airnet|wi-?fi|a?dsl|dynamic|pppoe|static|account)+',
                        r'(\(|\s+)(([a-z]+?)-){0,2}(\d{1,3}-){1,3}\d{1,3}([\.a-z]{1,63})+\.(ru|in|id|ua|ch)'
        ]

        n_rcvds = 2
        for rule in rcvd_rules:
            if filter(lambda l: re.search(rule, l), BasePattern.get_rcvds(self,n_rcvds)):
                vector_dict ["trace_rule"] = 1

        # get crc32 from first N trace fields
        rcvd_vect = tuple([r.partition('by')[0] for r in BasePattern.get_rcvds(self,n_rcvds)])

        logger.debug(rcvd_vect)
        vector_dict.update(common.get_trace_crc(rcvd_vect))
        logger.debug('\t----->'+str(vector_dict))

        logger.debug('>>>DESTINATOR_CHECKS:')
        # deep parsing and checks for some wellknown spammers tricks with To: header
        vector_dict ['smtp_to'] = BasePattern.INIT_SCORE
        vector_dict ['to'] = BasePattern.INIT_SCORE
        logger.debug('\t----->'+str(vector_dict))

        to_values, to_addrs = common.get_addr_values(self.msg.get('To'))
        if to_values and filter(lambda x: re.search(r'undisclosed-recipients', x, re.I), to_values):
            vector_dict['to'] += score
            logger.debug('\t----->'+str(vector_dict))

        if not to_addrs:
            vector_dict['to'] += score
            logger.debug('\t----->'+str(vector_dict))

        smtp_to_list = filter(lambda x: x, tuple([(r.partition('for')[2]).strip() for r in BasePattern.get_rcvds(self,n_rcvds)]))

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

        # 2. Subject checks
        logger.debug('>>>SUBJ_CHECKS:')
        features = ['len','style','score','checksum','encoding']
        features_dict = dict(map(lambda x,y: ('subj_'+x,y), features, [INIT_SCORE]*len(features)))

        if self.msg.get("Subject"):

            total_score = INIT_SCORE
            unicode_subj, norm_words_list, encodings = common.get_subject(self.msg.get("Subject"), MIN_TOKEN_LEN)
            # check the length of subj in chars, unicode str was normilised by Unicode NFC rule, i.e.
            # use a single code point if possible, spams still use very short subjects like ">>:\r\n", or
            # very long
            if len(unicode_subj)< MAX_SUBJ_LEN or len(unicode_subj)> MIN_SUBJ_LEN:
                features_dict['subj_len'] = 1

            # for RFC 5322 checks
            prefix_heads_map = {
                                    'RE' : ['In-Reply-To', 'Thread(-.*)?', 'References'],
                                    'FW' : ['(X-)?Forward']
                                }

            for k in prefix_heads_map.iterkeys():
                if re.match(ur''+k+'\s*:', unicode_subj, re.I):
                    heads_list  = prefix_heads_map.get(k)

                    for h_name in self.msg.keys():
                        found_heads = filter(lambda reg: re.match(reg,h_name,re.I),h_name)
                        total_score += (len(prefix_heads_map.get(k)) - len(found_heads))*score

            # some common greedy regexes
            subject_rule = [
                                ur'((S)?SN|v+i+a+g+r+a+|c+i+a+(l|1)+i+(s|\$|z)+|pfizer|discount|med|click|Best\s+Deal\s+Ever|,|\!|\?!|>>\:|sale|-)+',
                                ur'[\d]{1,2}\s+[\d]{1,2}[0]{1,3}\s+.*',
                                ur'-?[\d]{1,2}\s+%\s+.*',
                                ur'[\d](-|\s+)?\S{1,4}(-|\s+)?[\d]\s+.*',
                                ur'[\*-=\+~]{1,}\S+[\*-=\+~]{1,}',
                                ur'(free.*(pills?).*(every?)*.*(order)*|online.*&.*(save)*|tablet.*(split?ed?)*.*has?le)',
	                            ur'(cheap([est])?.*(satisf[ied]?)*.*(U[SK])*.*(CANADIAN)*.*customer|To.*Be.*Remov([ed])?.*(Please?)*)',
	                            ur'(100%\s+GUARANTE?D|free.{0,12}(?:(?:instant|express|online|no.?obligation).{0,4})+.{0,32})',
	                            ur'(dear.*(?:IT\W|Internet|candidate|sirs?|madam|investor|travell?er|car\sshopper|ship))+',
                                ur'.*(eml|spam).*',
                                ur'.*(payment|receipt|attach(ed)?|extra\s+inches)',
                                ur'(ТАКСИ|Услуги\s+.*\s+учреждениям|Реклама|Рассылк.*\s+недорого|арбитражн.*\s+суд|Только\s+для\s+(владельц.*|директор.*))',
                                ur'(Таможен.*(союз|пошлин.*|налог.*|сбор.*|правил.*)|деклараци.*|налог.*|больше\s+.*\s+заказ|ликвид|помоги)'
                            ]

            subj_score, upper_flag, title_flag = common.basic_subjects_checker(unicode_subj, subject_rule, score)
            # some words in upper case or almoust all words in subj string are Titled
            if upper_flag or (len(norm_words_list) - title_flag) < 3:
                features_dict['subj_style'] = 1

            features_dict['subj_score'] = total_score + subj_score

            if len(set(encodings)) > 1:
                features_dict['encoding'] = score



            # take crc32, make line only from words on even positions
            norm_words_list = tuple([norm_words_list[i] for i in filter(lambda i: i%2, range(len(norm_words_list)))])
            subj_trace = ''.join(tuple([w.encode('utf-8') for w in norm_words_list]))
            features_dict['subj_checksum'] = binascii.crc32(subj_trace)

        vector_dict.update(features_dict)
        logger.debug('\t----->'+str(vector_dict))

        # 3. assert the absence of List headers + some other RFC 5322 compliences checks for headers
        logger.debug('>>>LIST_CHECKS:')
        list_features = ['list', 'sender','preamble', 'disp-notification']
        list_features_dict = dict(map(lambda x,y: (x,y), list_features, [BasePattern.INIT_SCORE]*len(list_features)))
        logger.debug('\t----->'+str(list_features_dict))

        if filter(lambda list_field: re.search('(List|Errors)(-.*)?', list_field), self.msg.keys()):
            # well, this unique spam author respects RFC 2369, his creation deservs more attentive check
            list_features_dict['list'] = common.basic_lists_checker(self.msg.items(), score)
            logger.debug('\t----->'+str(list_features_dict))

        elif (self.msg.keys().count('Sender') and self.msg.keys().count('From')):
            # if we don't have List header From = Sender (RFC 5322),
            # MUA didn't generate Sender field cause of redundancy
            list_features_dict ['sender'] = 1
            logger.debug('\t----->'+str(list_features_dict))

        if self.msg.preamble and not re.search('This\s+is\s+a\s+(crypto.*|multi-part).*\sMIME\s.*', self.msg.preamble,re.I):

            list_features_dict ['preamble'] = 1
            logger.debug('\t----->'+str(list_features_dict))

        vector_dict.update(list_features_dict)
        logger.debug('\t----->'+str(list_features_dict))

        if (self.msg.keys()).count('Disposition-Notification-To'):
            vector_dict ['disp-notification'] = 1
            logger.debug('\t----->'+str(vector_dict))

        # 5. assert the absence of SPF, Auth and DKIM headers, what is very typically exactly for spam
        dmarc_dict, dkim_domain = common.basic_dmarc_checker(self.msg.items(), score)
        vector_dict.update(dmarc_dict)

        # 4. crc for From values
        vector_dict['from_checksum']=0
        logger.debug('\t----->'+str(vector_dict))

        if self.msg.get('From'):
            from_values = common.get_addr_values(self.msg.get('From'))[0]

            if from_values:
                vector_dict['from_checksum'] = binascii.crc32(reduce(add,from_values[:1]))
                logger.debug('\t----->'+str(vector_dict))

        # 5. Check MIME headers
        logger.debug('/n>>>MIME_CHECKS:')
        mime_features = ['mime_spammness', 'att_count','att_score','in_score','nest_level','checksum']
        mime_dict = dict(map(lambda x,y: (x,y), mime_features, [INIT_SCORE]*len(mime_features)))

        if self.msg.get('MIME-Version') and not self.msg.is_multipart():
            mime_dict['mime_spammness'] = score

        elif self.msg.is_multipart():

            attach_regs = [
                            r'(application\/(octet-stream|pdf|vnd.*|ms.*|x-.*)|image\/(png|gif|message\/))',
                            r'.*\.(exe|xlsx?|pptx?|txt|maild.*|docx?|html|js|bat|eml|zip|png|gif|cgi)',
                            ]

            mime_skeleton = BasePattern.get_mime_struct(self)
            logger.debug('MIME STRUCT >>>>>'+str(mime_skeleton)+'/n')


            count, att_score, in_score = common.basic_attach_checker(mime_skeleton.values(), attach_regs, score)
            mime_dict['att_count'] = count
            mime_dict['att_score'] = att_score
            mime_dict['in_score'] = in_score
            if BasePattern.get_nest_level(self) > 2:
                mime_dict['nest_level'] = 1


            mime_dict['checksum'] = binascii.crc32(''.join(mime_skeleton.keys()))


        vector_dict.update(mime_dict)
        logger.debug('\t----->'+str(vector_dict))


        # 6. check urls
        logger.debug('>>>URL_CHECKS:')
        urls_list = BasePattern.get_url_list(self)
        logger.debug('URLS_LIST >>>>>'+str(urls_list))
        '''
        if urls_list:
            urls_features = ['score','distinct_domains','count']
            urls_dict = dict(map(lambda x,y: (x,y), urls_features, [INIT_SCORE]*len(urls_features)))

            urls_score, domains_list =  common.basic_url_checker(urls_list)
            urls_dict['score'] = urls_score

            urls_dict['distinct_domains'] = len(set(domains_list))
            urls_dict['count'] = len(domains_list)

        '''





        # analyse attachements extensions

        #vect_dict.update(common.get_body_skeleton(self.msg))

        return (vector_dict)


if __name__ == "__main__":

    formatter = logging.Formatter('%(filename)s: %(message)s')
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    try:
        pattern = SpamPattern(msg)
        vector = test.run(score)
        logger.debug(vector)


    except Exception as details:
        raise



		


	
			



