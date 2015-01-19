#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""Keeps and applies vectorising rules for spams."""

import os, sys, logging, re, common, binascii, urllib
from operator import add
from pattern_wrapper import BasePattern
from collections import OrderedDict, Counter

INIT_SCORE = BasePattern.INIT_SCORE
MIN_TOKEN_LEN = BasePattern.MIN_TOKEN_LEN
NEST_LEVEL_THRESHOLD = BasePattern.NEST_LEVEL_THRESHOLD

# formatter_debug = logging.Formatter('%(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

class SpamPattern(BasePattern):

    MAX_SUBJ_LEN = 5
    MIN_SUBJ_LEN = 70

    def run(self, score):

        vector_dict = OrderedDict()

        # 1. "Received:" Headers
        logger.debug('>>> 1. RCVD_CHECKS:')

        # get crc32 of only unique headers and their values
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
        rcvds = BasePattern.get_rcvds(self,n_rcvds)
        print('TYPE:'+str(type(rcvds)))
        logger.debug("my pretty rcvds headers:".upper()+str(rcvds))
        for rule in rcvd_rules:
            if filter(lambda l: re.search(rule, l), rcvds):
                vector_dict ["trace_rule"] = 1

        # get crc32 from first N trace fields
        rcvd_vect = tuple([r.partition('by')[0] for r in rcvds])

        logger.debug(rcvd_vect)
        vector_dict.update(common.get_trace_crc(rcvd_vect))
        logger.debug('\t----->'+str(vector_dict))


        # 2. "To:", "SMTP RCPT TO:" Headers
        logger.debug('>>> 2. DESTINATOR CHECKS:')

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

        smtp_to_list = filter(lambda x: x, tuple([(r.partition('for')[2]).strip() for r in rcvds]))

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


        # 3. "Subject:" Header
        logger.debug('>>> 3. SUBJECT CHECKS:')

        features = ['len','style','score','checksum','encoding']
        features_dict = dict(map(lambda x,y: ('subj_'+x,y), features, [INIT_SCORE]*len(features)))

        if self.msg.get("Subject"):

            total_score = INIT_SCORE
            unicode_subj, norm_words_list, encodings = common.get_subject(self.msg.get("Subject"), MIN_TOKEN_LEN)
            # check the length of subj in chars, unicode str was normilised by Unicode NFC rule, i.e.
            # use a single code point if possible, spams still use very short subjects like ">>:\r\n", or
            # very long
            if len(unicode_subj)< self.MAX_SUBJ_LEN or len(unicode_subj)> self.MIN_SUBJ_LEN:
                features_dict['subj_len'] = 1

            # check the origin of RE: and FW: prefixes in "Subject:" header value, according to RFC 5322 rules
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

            # some words in UPPER case or almoust all words in subj string are Titled
            if upper_flag or (len(norm_words_list) - title_flag) < 3:
                features_dict['subj_style'] = 1

            features_dict['subj_score'] = total_score + subj_score

            if len(set(encodings)) > 1:
                features_dict['encoding'] = score

            # take crc32, make line only from words on even positions, not all
            norm_words_list = tuple([norm_words_list[i] for i in filter(lambda i: i%2, range(len(norm_words_list)))])
            subj_trace = ''.join(tuple([w.encode('utf-8') for w in norm_words_list]))
            features_dict['subj_checksum'] = binascii.crc32(subj_trace)

        vector_dict.update(features_dict)
        logger.debug('\t----->'+str(vector_dict))


        # 4. Assert the absence of "List-*:" headers + some RFC 5322 compliences checks for other common headers
        logger.debug('>>> 4. LIST_CHECKS + ORIGINATOR_CHECKS:')

        list_features = ['list', 'sender', 'preamble', 'disp-notification']
        list_features_dict = dict(map(lambda x,y: (x,y), list_features, [BasePattern.INIT_SCORE]*len(list_features)))
        logger.debug('\t----->'+str(list_features_dict))

        if filter(lambda list_field: re.search('(List|Errors)(-.*)?', list_field), self.msg.keys()):
            # this unique spam author respects RFC 2369, his creation deservs more attentive check
            list_features_dict['list'] = common.basic_lists_checker(self.msg.items(), rcvd_vect, score)
            logger.debug('\t----->'+str(list_features_dict))

        elif (self.msg.keys().count('Sender') and self.msg.keys().count('From')):
            # if we don't have List header, From value has to be equal to Sender value (RFC 5322),
            # MUA didn't generate Sender field cause of redundancy
            list_features_dict ['sender'] = score
            logger.debug('\t----->'+str(list_features_dict))

        if self.msg.preamble and not re.search('This\s+is\s+a\s+(crypto.*|multi-part).*\sMIME\s.*', self.msg.preamble,re.I):

            list_features_dict ['preamble'] = score
            logger.debug('\t----->'+str(list_features_dict))

        vector_dict.update(list_features_dict)
        logger.debug('\t----->'+str(list_features_dict))

        if (self.msg.keys()).count('Disposition-Notification-To'):
            vector_dict ['disp-notification'] = score
            logger.debug('\t----->'+str(vector_dict))

        # 5. assert the absence of "Received-SPF:", "Authentication-Results:" and "DKIM-*" headers,
        # that's very typically for unconditional spam
        logger.debug('>>> 5. SPF/DKIM_CHECKS:')

        dmarc_dict, dkim_domain = common.basic_dmarc_checker(self.msg.items(), score)
        vector_dict.update(dmarc_dict)


        # 6. Body "From:" values
        logger.debug('>>> 6. ORIGINATOR_CHECKS:')

        vector_dict['from_checksum']=0
        logger.debug('\t----->'+str(vector_dict))

        if self.msg.get('From'):
            from_values = common.get_addr_values(self.msg.get('From'))[0]

            if from_values:
                vector_dict['from_checksum'] = binascii.crc32(reduce(add,from_values[:1]))
                logger.debug('\t----->'+str(vector_dict))


        # 7. MIME-headers checks
        logger.debug('>>> 7. MIME_CHECKS:')

        mime_features = [ 'mime_score', 'checksum', 'nest_level', 'att_count', 'att_score', 'in_score' ]
        mime_dict = dict(map(lambda x,y: (x,y), mime_features, [INIT_SCORE]*len(mime_features)))

        if self.msg.get('MIME-Version') and not self.msg.is_multipart():
            mime_dict['mime_score'] = score

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
            # defines by count of inline attachements
            mime_dict['in_score'] = in_score

            if BasePattern.get_nest_level(self) > NEST_LEVEL_THRESHOLD:
                mime_dict['nest_level'] = score

            mime_dict['checksum'] = binascii.crc32(''.join(mime_skeleton.keys()))

        vector_dict.update(mime_dict)
        logger.debug('\t----->'+str(vector_dict))

        # 8. URL-checks
        logger.debug('>>> 8. URL_CHECKS:')

        urls_list = BasePattern.get_url_list(self)
        logger.debug('URLS_LIST >>>>>'+str(urls_list))

        features = ['url_upper', 'repetitions', 'punicode', 'domain_name_level']
        features_dict = OrderedDict(map(lambda x,y: (x,y), features, [INIT_SCORE]*len(features)))

        if urls_list:

            domain_regs = [
                                ur'tinyurl\.',
                                ur'(\w{3,6}-){1,3}\w{2,45}(\.\w{2,5}){0,3}',
                                ur'\D{1,3}(\.|-)\w{1,61}(\.\w{2,5}){0,3}',
                                # match if contains only non-ascii
                                ur'[^\u0000-\u002C\u002E-\u005E\u0061-\u007F]{1,61}\.[^\u0000-\u002C\u002E-\u005E\u0061-\u007F]{1,6}',
                                ur'(\w{1,10}\.)?[^\u0000-\u002C\u002E-\u005E\u0061-\u007F]{1,61}\.[^\u0000-\u002C\u002E-\u005E\u0061-\u007F]{1,6}',
                                ur'(\d{1,10}\.)?[^\u0000-\u002C\u002E-\u005E\u0061-\u007F]{1,61}\.[^\u0000-\u002C\u002E-\u005E\u0061-\u007F]{1,6}',
                                ur'([0-9-]{1,61}\.?){1,3}(\D{2,5}\.?){0,3}',
                                ur'(\w{3,6}-){1,3}\w{2,45}\.(\w{2,5}){0,3}',
                                ur'\w{1,61}(\.[a-zA-z]{1,4}){0,2}\.(in|me|ua|ru|mobi|red|es)',
                                ur'\w{1,61}\.(in.ua|ru.all.biz|gl|ee|pp.ua|kiev.ua|com.ua|ro|lviv.ua|ly|pro|co.jp|c|c=|lt|by|asia)',
                                ur'\w{1,3}(\.[a-zA-Z]{1,4}){1,3}',
                                ur'(.*-loader|lets-|youtu.be|goo.gl|wix.com|us\d.|jujf.ru)',
                                ur'\w{1,61}(\.\w{1,4}){0,3}\.\w{1,3}([^\u0000-\u007F]{1,3}|\d{1,5})'
                        ]

            regs = [
                                ur'(click|here|link|login|update|confirm|legilize|now|buy|online)+',
                                ur'(Free|Shipping|Options|Pills|Every?|Order|Best|Deal|Today|Now|Contact|Pay|go)+',
                                ur'(Ccылк|Курс|Цен|Посмотреть|Каталог|Здесь|Сюда|Регистрация|бесплатное|участие|на\s+сайт|подробн)',
                                ur'(горяч|скидк|отписаться|отказаться)',
                                ur'(message|view|can\'t\see)',
                                ur'(background-color|text-decoration|font\scolor|color|underline|font\ssize|img|style|<\/?wbr>|font\sface|<strong>|<em>)',
                                ur'\/[\u0000-\u001F\u0041-\u005A\u0061-\u007A]{1,3}[^\u0000-\u007F]{2,}',
                                ur'[^\u0000-\u007F]{2,}(\.|\?|!|;){0,}',
                                ur'(cid:)?\w{1,40}@(\d{1,3}-){1,3}\d{1,3}(\.[A-Za-z]{1,10}){1,3}',
                                ur'([\a\b\t\r\n\f\v]{0,}|[\?!])',
                                ur'(\S*)http:.*',
                                ur'[\u0000-\u001F\u0041-\u005A\u0061-\u007A]{3,}',
                                ur'[\+=\$]{1,3}(\w){0,}',
                                ur'\+?\d(\[|\()\d{3}(\)|\])\s?[\d~-]{0,}'
                    ]

            basic_features_dict, netloc_list = common.basic_url_checker(urls_list, rcvd_vect, score, domain_regs, regs)
            basic_features_dict.pop('url_count') # for spams url count may be totally different


            print('NETLOC_LIST >>>'+str(netloc_list))
            print('DICT >>>'+str(basic_features_dict))

            if netloc_list:
                for met in [ unicode.isupper, unicode.istitle ]:
                #for met in [unicode.isupper, unicode.istitle]:
                    features_dict['url_upper'] += len(filter(lambda s: met(s), netloc_list))*score

                puni_regex = ur'xn--[0-9a-z-]+(\.xn--[0-9a-z]+){1,3}'
                features_dict['punicode'] = len(filter(lambda u: re.search(puni_regex,u,re.I), netloc_list))*score

                features_dict['domain_name_level'] = len(filter(lambda n: n>=2, [s.count('.') for s in netloc_list]))*score


            repet_regex = ur'(https?:\/\/|www\.)\w{1,61}(\.\w{2,10}){1,5}'
            urls = [x.geturl() for x in urls_list]

            if filter(lambda l: len(l)>1, map(lambda url: re.findall(repet_regex,url,re.I), urls)):
                features_dict['repetitions'] = 1

        else:
            basics = ['url_score', 'distinct_count', 'sender_count']
            basic_features_dict = dict(map(lambda x,y: (x,y), basics, [INIT_SCORE]*len(basics)))

        vector_dict.update(basic_features_dict)
        vector_dict.update(features_dict)
        logger.debug('\t----->'+str(vector_dict))


        # 9. check body
        logger.debug('>>> 9. BODY\'S TEXT PARTS CHECKS:')

        body_features = [ 'regexp_score', 'body_checksum' ]
        body_dict = Counter(dict(map(lambda x,y: (x,y), body_features, [INIT_SCORE]*len(body_features))))

        text_parts = self.get_text_parts()
        logger.debug('TEXT_PARTS: '+str(text_parts))

        html_text = ''
        for line, content_type in text_parts:
            # parse by lines
            if 'html' in content_type:
                soup = BeautifulSoup(line)
                html_content = common.get_content(soup)
                if html_content:
                    body_dict['regexp_score'] += common.basic_text_checker(html_content)

            else:
                body_dict['regexp_score'] += common.basic_text_checker(line)

        vector_dict.update(body_dict)

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



		


	
			



