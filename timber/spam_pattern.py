#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
""" Keeps and applies vectorising rules for spams.

    todo: refactor architecture of particular patterns (now it's shame, of course)
    Real architecture of particular patterns modules should be like this:
        class SpamPattern(BasePattern):

            def __rule_1(self, *args, **kwargs):
                ...
                return metric1

            def __rule_N(self, *args, **kwargs):
                ...
                return metricN

            also need to generate and append new trigger-rules as methods to pattern class in runtime

            def run(self, score):

                features_vector.update[f_1] = self.__rule_1()
                features_vector.update[f_N] = self.__rule_N()

                return(features_vector)

"""

import os, sys, logging, re, binascii, math

from operator import add, itemgetter
from collections import OrderedDict, Counter, namedtuple
from pattern_wrapper import BasePattern

#formatter_debug = logging.Formatter('%(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

class SpamPattern(BasePattern):
    """
    Pattern class for build vectors, based on typical spam's features:
    -- if email looks like unconditional spam, it's vector will contain
        values, which are mostly don't equal to zeros ;
    """

    # todo: get rid of magic numbers and unicorns
    __RCVDS_NUM = 2

    def run(self, score):

        vector_dict = OrderedDict()

        # 1. "Received:" Headers
        logger.debug('>>> 1. RCVD_CHECKS:')

        # get crc32 of only unique headers and it's values
        excluded_heads = [
                            'Received', 'From', 'Subject', 'Date', 'MIME-Version', 'To', 'Message-ID', 'Cc','Bcc','Return-Path',\
                            'X-Drweb-.*', 'X-Spam-.*', 'X-Maild-.*','Resent-.*'
                         ]

        logger.debug(str(self._msg.items()))
        vector_dict['all_heads_crc'] = self.get_all_heads_crc(excluded_heads)
        logger.debug('\t----->'+str(vector_dict))

        # keep the count of traces fields
        vector_dict ["rcvd_traces_num"] = self._msg.keys().count('Received')
        logger.debug('\t----->'+str(vector_dict))

        # basic parsing and dummy checks with regexps (takes only first n_rcvds headers)
        vector_dict ["rcvd_trace_rule"] = self.INIT_SCORE
        logger.debug('\t----->'+str(vector_dict))
        rcvd_rules = [
                        r'(public|airnet|wi-?fi|a?dsl|dynamic|pppoe|static|account)+',
                        r'(\(|\s+)(([a-z]+?)-){0,2}(\d{1,3}-){1,3}\d{1,3}([\.a-z]{1,63})+\.(ru|in|id|ua|ch|)',
                        r'(yahoo|google|bnp|ca|aol|cic|([a-z]{1,2})?web|([a-z]{1-15})?bank)?(\.(tw|in|ua|com|ru|ch|msn|ne|nl|jp|[a-z]{1,2}net)){1,2}'
        ]

        rcvds = self.get_rcvds(self.__RCVDS_NUM)
        print('TYPE:'+str(type(rcvds)))
        logger.debug("my pretty rcvds headers:".upper()+str(rcvds))
        vector_dict ["rcvd_rules"] = self.INIT_SCORE
        for rule in rcvd_rules:
            if filter(lambda l: re.search(rule, l), rcvds):
                vector_dict ["rcvd_rules"] += score

        vector_dict.update(self.get_trace_crc())
        logger.debug('\t----->'+str(vector_dict))

        # 2. "To:", "SMTP RCPT TO:" Headers
        logger.debug('>>> 2. DESTINATOR CHECKS:')

        vector_dict['rcpt_smtp_to'], vector_dict['rcpt_body_to'] = self.get_rcpts_metrics(score)

        # 3. "Subject:" Header
        logger.debug('>>> 3. SUBJECT CHECKS:')

        features = ('len','style','score','checksum','encoding')
        features_dict = dict(zip(['subj_'+f for f in features], [self.INIT_SCORE]*len(features)))

        if self._msg.get("Subject"):

            total_score = self.INIT_SCORE
            unicode_subj, norm_words_list, encodings = self.get_decoded_subj()
            features_dict['subj_len'] = len(unicode_subj)

            # check the origin of RE: and FW: prefixes in "Subject:" header value, according to RFC 5322 rules
            prefix_heads_map = {
                                    'RE' : ['In-Reply-To', 'Thread(-.*)?', 'References'],
                                    'FW' : ['(X-)?Forward']
            }

            for k in prefix_heads_map.iterkeys():
                if re.match(ur''+k+'\s*:', unicode_subj, re.I):
                    heads_list  = prefix_heads_map.get(k)

                    for h_name in self._msg.keys():
                        found_heads = filter(lambda reg: re.match(reg,h_name,re.I),h_name)
                        total_score += (len(prefix_heads_map.get(k)) - len(found_heads))*score

            # some self greedy regexes
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

            subj_score, upper_flag, title_flag = self.get_subject_metrics(subject_rule, score)

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


        # 4. Assert the absence of "List-*:" headers + some RFC 5322 compliences checks for other self headers
        logger.debug('>>> 4. LIST_CHECKS + ORIGINATOR_CHECKS:')

        list_features = ('list', 'sender', 'preamble', 'disp-notification')
        list_features_dict = dict(map(lambda x,y: (x,y), list_features, [self.INIT_SCORE]*len(list_features)))
        logger.debug('\t----->'+str(list_features_dict))

        if filter(lambda list_field: re.search('(List|Errors)(-.*)?', list_field), self._msg.keys()):
            # this unique spam author respects RFC 2369, his creation deservs more attentive check
            list_features_dict['list'] = self.get_list_metrics(score)
            logger.debug('\t----->'+str(list_features_dict))

        elif (self._msg.keys().count('Sender') and self._msg.keys().count('From')):
            # if we don't have List header, From value has to be equal to Sender value (RFC 5322),
            # MUA didn't generate Sender field cause of redundancy
            list_features_dict ['sender'] = score
            logger.debug('\t----->'+str(list_features_dict))

        if self._msg.preamble and not re.search('This\s+is\s+a\s+(crypto.*|multi-part).*\sMIME\s.*', self._msg.preamble,re.I):

            list_features_dict ['preamble'] = score
            logger.debug('\t----->'+str(list_features_dict))

        vector_dict.update(list_features_dict)
        logger.debug('\t----->'+str(list_features_dict))

        if (self._msg.keys()).count('Disposition-Notification-To'):
            vector_dict ['disp-notification'] = score
            logger.debug('\t----->'+str(vector_dict))

        # 5. assert the absence of "Received-SPF:", "Authentication-Results:" and "DKIM-*" headers,
        # that's very typically for unconditional spam
        logger.debug('>>> 5. SPF/DKIM_CHECKS:')

        dmarc_score, dmarc_dict, dkim_domain = self.get_dmarc_metrics(score)
        vector_dict['dmarc_score'] = dmarc_score
        vector_dict.update(dmarc_dict)


        # 6. Body "From:" values
        logger.debug('>>> 6. ORIGINATOR_CHECKS:')

        vector_dict['from_checksum'] = self.INIT_SCORE
        logger.debug('\t----->'+str(vector_dict))

        if self._msg.get('From'):
            name_addr_tuples = self.get_addr_values(self._msg.get_all('From'))[:1]
            logger.debug('\tFROM:----->'+str(name_addr_tuples))
            print(name_addr_tuples)

            if len(name_addr_tuples) != 1:
                logger.warning('\t----->'+str(name_addr_tuples))

            if name_addr_tuples:
                from_value, from_addr = reduce(add, name_addr_tuples)
                vector_dict['from_checksum'] = binascii.crc32(from_value.encode(self.DEFAULT_CHARSET))
                logger.debug('\t----->'+str(vector_dict))


        # 7. MIME-headers checks
        logger.debug('>>> 7. MIME_CHECKS:')

        mime_features = ('mime_score', 'checksum', 'nest_level', 'att_count', 'att_score', 'in_score')
        mime_dict = dict(zip(mime_features, [self.INIT_SCORE]*len(mime_features)))

        if self._msg.get('MIME-Version') and not self._msg.is_multipart():
            mime_dict['mime_score'] = score

        elif self._msg.is_multipart():

            attach_regs = [
                                r'(application\/(octet-stream|pdf|vnd.*|ms.*|x-.*)|image\/(png|gif|message\/))',
                                r'.*\.(exe|xlsx?|pptx?|txt|maild.*|docx?|html|js|bat|eml|zip|png|gif|cgi)',
            ]

            mime_skeleton = self.get_mime_struct()
            logger.debug('MIME STRUCT >>>>>'+str(mime_skeleton)+'/n')

            count, att_score, in_score = self.get_attach_metrics(mime_skeleton.values(), attach_regs, score)
            mime_dict['att_count'] = count
            mime_dict['att_score'] = att_score
            # defines by count of inline attachements
            mime_dict['in_score'] = in_score

            mime_dict['nest_level'] = self.get_nest_level()
            mime_dict['checksum'] = binascii.crc32(''.join(mime_skeleton.keys()))

        vector_dict.update(mime_dict)
        logger.debug('\t----->'+str(vector_dict))

        # 8. URL-checks
        logger.debug('>>> 8. URL_CHECKS:')

        urls_list = self.get_url_list()
        logger.debug('URLS_LIST >>>>>'+str(urls_list))

        features = ('url_upper', 'repetitions', 'punicode', 'domain_name_level', 'url_avg_len', \
                    'onMouseOver', 'hex', 'at_sign')
        # URL_UPPER: presense of elements in upper-case in URL
        # REPETITIONS: presense of repetitions like:
        # PUNICODE: respectively (very often for russian spams)
        # DOMAIN NAME LEVEL: very often russian spams are send from third-level domains
        # URL_AVG_LENGTH: they are short in general, cause of url-short services, etc
        # many usual and not usual ideas about phising urls:
        # http://www.isteams.org/conference/pdf/Paper%20111-%20iSTEAMS%202014%20-Asani%20et%20al%20-%20MAXIMUM%20PHISH%20BAIT%20-%20TOWARDS%20FEATURE%20BASED%20DETECTION%20OF%20PHISING%20USING%20MAXIMUM%20ENTROPY%20CLASSIFICATION%20TECHNIQUE.pdf
        # (Now I'm not having time to code all features by day or two ;-((( )
        features_dict = OrderedDict(zip(features, [self.INIT_SCORE]*len(features)))

        if urls_list:

            regs_for_dom_pt = [
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

            regs_for_txt_pt = [
                                ur'(click|here|link|login|update|confirm|legilize|now|buy|online|movie|s0x(room|boat)?)+',
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

            basic_features_dict, netloc_list = self.get_url_metrics(regs_for_dom_pt, regs_for_txt_pt, score)
            basic_features_dict.pop('url_count') # for spams url count may be totally different

            print('NETLOC_LIST >>>'+str(netloc_list))
            print('DICT >>>'+str(basic_features_dict))

            if netloc_list:
                for method in [ unicode.isupper, unicode.istitle ]:
                    features_dict['url_upper'] += len(filter(lambda s: method(s), netloc_list))*score

                # mostly thinking about shortened urls, created by tinyurl and other services,
                # but maybe this is weak feature
                features_dict['url_avg_len'] = math.ceil(float(sum([len(s) for s in netloc_list]))/len(netloc_list))

                puni_regex = ur'xn--[0-9a-z-]+(\.xn--[0-9a-z]+){1,3}'
                features_dict['punicode'] = len(filter(lambda u: re.search(puni_regex,u,re.I), netloc_list))*score

                features_dict['domain_name_level'] = len(filter(lambda n: n>=2, [s.count('.') for s in netloc_list]))*score

            repet_regex = ur'(https?:\/\/|www\.)\w{1,61}(\.\w{2,10}){1,5}'
            urls = [x.geturl() for x in urls_list]

            if filter(lambda l: len(l)>1, map(lambda url: re.findall(repet_regex,url,re.I), urls)):
                features_dict['repetitions'] = 1

        else:
            basics = ('url_score', 'distinct_count', 'sender_count')
            basic_features_dict = dict(map(lambda x,y: (x,y), basics, [self.INIT_SCORE]*len(basics)))

        vector_dict.update(basic_features_dict)
        vector_dict.update(features_dict)
        logger.debug('\t----->'+str(vector_dict))


        # 9. check body

        logger.debug('>>> 9. BODY\'S TEXT PARTS CHECKS:')

            # some simple greedy regexp, don't belive in them at all
            # this like good all tradition of antispam filter's world
        regexp_list = [
                            ur'(vrnospam|not\s+a?.*spam|bu[ying]\s+.*(now|today|(on)?.*sale)|(click|go|open)[\\s\.,_-]+here)',
                            ur'(viagra|ciali([sz])+|doctors?|d(y|i)sfunction|discount\s+(on\s+)?all?|free\s+pills?|medications?|remed[yie]|\d{1,4}mg)',
                            ur'(100%\s+GUARANTE?D||no\s*obligation|no\s*prescription\s+required?|(whole)?sale\s+.*prices?|phizer|pay(ment)?)',
                            ur'(candidate|sirs?|madam|investor|travell?er|car\s+.*shopper|free\s+shipp?ing|(to)?night|bed|stock|payroll)',
                            ur'(prestigi?(ous)|non-accredit[ed]\s+.*(universit[yies]|institution)|(FDA[-\s_]?Approved|Superb?\s+Qua[l1][ity])\s+.*drugs?(\s+only)?)',
                            ur'(accept\s+all?\s+(major\s+)?(credit\s+)?cards?|(from|up)\s+(\$|\u20ac|\u00a3)\d{1,3}[\.\,:\\]\d{1,3}|Order.*Online.*Save)',
                            ur'(автомати([зиче])*.*\sдоход|халяв([аыне])*.*деньг|куп.*продае|объявлен.*\sреклам|фотки.*смотр.*зажгл.*|франши.*|киев\s+)',
                            ur'(улица.*\s+фонарь.*\s+виагра|икра.*(в)?\s+офис.*\s+секретар([ьша])*|ликвидац[иярова].*\s(по)?\s+законy?.*\s+бухгалтер([ия])?)',
                            ur'((рас)?таможн|валют|переезд|жил|вконтакт|одноклассник|твит.*\s+(как)?.*\s+труд)',
                            ur'(мазь\s+(как\s+средство\s+от\s+жизни)?.*для\s+.*похуд|диет|прибыль|итальянск|франц|немец|товар|ликвидац|брус|\s1С)',
                            ur'(rubil\s+skor\s+ruxnet|Pereved\s+v|doll[oa]r\s+deposit|dengi|zakon|gosuslugi|tamozhn)',
                            ur'(\+\d)?(\([Ч4]\d{2}\))?((\d\s{0,2}\s?){2,3}){1,4}'
        ]

        tags_map = {

                        'table':{
                                    'width'                 : '[1-9]{3}[^%]',
                                    'height'                : '[1-9]{1,3}',
                                    'cell(padding|spacing)' : '[1-9]',
                                    'border-color'          : '#[0-9A-F]{3,6}',
                                    'border'                : '[1-9]',
                                    'style'                 : '([A-Z-][^(a-z)]){3,10}'
                        },
                        'span' :{
                                    'style'                 : '(mso-.*|(x-)?large|([A-Z-][^(a-z)]){3,10}|VISIBILITY.*hidden|WEIGHT:.*bold)',
                                    'lang'                  : '(RU|EN-US)'
                        },
                        'p'    :{
                                    'style'                 : '(DISPLAY:\s*none|([A-Z-][^(a-z)]){3,10})|)',
                                    'class'                 : '\[\'(Mso.*|.*)\'\]',
                                    'align'                 : 'center',
                                    'css'                   : ''
                        }
        }

        # todo: ask somebody smart how to kill yourself immediately
        # about this acrh problem : repeate 2 lines in each class or
        # call these functions with method_getter() in random_forest namespace + __get_atribute__()
        # for args


        vector_dict.update(dict(zip(('html_score', 'html_checksum'), self.get_html_parts_metrics(score, tags_map))))
        vector_dict['text_score'] = self.get_text_parts_metrics(score, regexp_list)
        vector_dict['avg_entropy'] = self.get_text_parts_avg_entropy()
        vector_dict['compression_ratio'] = self.get_text_compress_ratio()

        logger.debug('MSG VECTOR --> '+str(vector_dict))

        return vector_dict

if __name__ == "__main__":

    formatter = logging.Formatter('%(filename)s: %(message)s')
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    try:
        pattern = SpamPattern(msg)
        vector = pattern.run(score)
        logger.debug(vector)


    except Exception as details:
        raise



		


	
			



