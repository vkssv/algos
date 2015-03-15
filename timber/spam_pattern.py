#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-


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
    __EXCLUDED_HEADS = [
                            'Received', 'From', 'Subject', 'Date', 'MIME-Version', 'To', 'Message-ID', 'Cc','Bcc','Return-Path',\
                            'X-Drweb-.*', 'X-Spam-.*', 'X-Maild-.*','Resent-.*'
    ]

    def __init__(self, **kwds):
        '''
        :param kwds:
        # todo: initialize each <type>-pattern with it's own penalizing self.score,
        will be useful in vector-distance calculations, for axes stretching

        :return: expand msg_vector, derived from BasePattern class with
        less-correlated metrics, which are very typical for spams,
        '''
        super(SpamPattern, self).__init__(**kwds)
        # 0. initialize vector of features explicitly,
        # for avoiding additional headaches and investigations with Python GC
        features = [
                            'rcvd_score'
                        ]

        [ self.__setattr__(f, SpamPattern._INIT_SCORE) for f in features ]
        #self.forged_sender = self.score
        #features = ('style','score','checksum','encoding')
        #mime_score
        #]


        # 1. all headers
        self.get_all_heads_crc(SpamPattern.__EXCLUDED_HEADS)

        # 2. Received headers

        # expands only spam-vectors, so function defined here
        self.get_rcvd_score()

        self.__dict__.update(self.get_rcvd_checksum(SpamPattern.__RCVDS_NUM))

        '''
        # 3. Originator checks
        self.spam_originator_checks()

        # 4. Subject
        self.msg_vector.update(self.spam_subj_checks())

        # 5. Typical spams headers
        if self._msg.keys().count('Disposition-Notification-To'):
            self.spam_vector['disp-notification'] = self.score

        # 6. Checks for MIME-skeleton attributes
        self.msg_vector['mime_score'] = self.spam_mime_checks()


        # 7. URL-checks
        self.msg_vector.update(self.spam_url_checks())

        # 8. Text-content metrics
        self.msg_vector.update(self.spam_content_checks())

        # 9. Attachments metrics
        self.msg_vector['attach_score'] = self.spam_attach_checks()
        '''
        logger.debug('SpamPattern was created')


    def get_rcvd_score(self):


        # 1. "Received:" Headers
        logger.debug('>>> 1. RCVD_CHECKS:')

        rcvd_rules = [
                        r'(public|airnet|wi-?fi|a?dsl|dynamic|pppoe|static|account)+',
                        r'(\(|\s+)(([a-z]+?)-){0,2}(\d{1,3}-){1,3}\d{1,3}([\.a-z]{1,63})+\.(ru|in|id|ua|ch|)',
                        r'(yahoo|google|bnp|ca|aol|cic|([a-z]{1,2})?web|([a-z]{1-15})?bank)?(\.(tw|in|ua|com|ru|ch|msn|ne|nl|jp|[a-z]{1,2}net)){1,2}'
        ]

        for rule in rcvd_rules:
            if filter(lambda l: re.search(rule, l), self.get_rcvds(SpamPattern.__RCVDS_NUM)):
                self.rcvd_score += self.penalty_score

        return self.rcvd_score

    '''''

    def spam_originator_checks(self):

        if not filter(lambda list_field: re.search('(List|Errors)(-.*)?', list_field), self._msg.keys()):
            if self._msg.keys().count('Sender') and self._msg.keys().count('From')):
            # if we don't have List header, From value has to be equal to Sender value (RFC 5322),
            # MUA didn't generate Sender field cause of redundancy
                self.forged_sender = self.score

    @classmethod
    def spam_subj_checks(cls):

        # 3. "Subject:" Header
        # this is alchemy
        logger.debug('>>> 2. SUBJECT CHECKS:')

        features = ('style','score','checksum','encoding')
        subj_features_dict = cls._get_empty_features_dict('subj', features, container_type='counter')

        if cls._msg.get("Subject"):

            total_score = cls.INIT_SCORE
            unicode_subj, norm_words_list, encodings = cls.get_decoded_subj()

            # todo: magic number!
            if len(set(encodings)) > 1:
                subj_features_dict['encoding'] = cls.score

            # check the origin of RE: and FW: prefixes in "Subject:" header value, according to RFC 5322 rules
            prefix_heads_map = {
                                    'RE' : ['In-Reply-To', 'Thread(-.*)?', 'References'],
                                    'FW' : ['(X-)?Forward']
            }

            for k in prefix_heads_map.iterkeys():
                if re.match(ur''+k+'\s*:', unicode_subj, re.I):
                    heads_list  = prefix_heads_map.get(k)

                    for h_name in cls._msg.keys():
                        found_heads = filter(lambda reg: re.match(reg, h_name, re.I), h_name)
                        total_score += (len(prefix_heads_map.get(k)) - len(found_heads))*cls.score

            # try greedy regexes, maybe will precise them in future
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

            subj_features_dict['subj_score'], upper_flag, title_flag = self.get_subject_metrics(subject_rule)

            # some words in UPPER case or almoust all words in subj string are Titled
            # todo: 3 is a magic number!
            if upper_flag or (len(norm_words_list) - title_flag) < 3:
                subj_features_dict['subj_style'] = self.score

            subj_features_dict['subj_score'] += total_score

            # take crc32, make line only from words on even positions, not all
            norm_words_list = tuple(norm_words_list[i] for i in filter(lambda i: i%2, range(len(norm_words_list))))
            subj_trace = ''.join(tuple([w.encode('utf-8') for w in norm_words_list]))
            subj_features_dict['subj_checksum'] = binascii.crc32(subj_trace)

        logger.debug('\t----->'+str(subj_features_dict))

        return subj_features_dict

    @classmethod
    def spam_mime_checks(cls):

        # 7. MIME-headers checks
        logger.debug('>>> 7. MIME_CHECKS:')

        mime_score = cls.INIT_SCORE

        if not cls._msg.is_multipart() and cls._msg.get('MIME-Version'):
            mime_score += cls.score
            return mime_score

        elif not cls._msg.is_multipart():
            return mime_score

        #', 'checksum', 'nest_level', 'att_count', 'att_score', 'in_score')
        #mime_features = ('mime_score', 'checksum', 'att_count', 'att_score', 'in_score', 'nest_level')
        #mime_features = ('mime_score', 'checksum', 'att_score', 'att_count', 'nest_level')

        if cls._msg.preamble and not re.search('This\s+is\s+a\s+(crypto.*|multi-part).*\sMIME\s.*', cls._msg.preamble, re.I):
            mime_score += cls.score
            logger.debug('\t----->'+str(mime_score))

        return mime_score

    @classmethod
    def spam_url_checks(cls):


        # 8. URL-checks
        logger.debug('>>> 8. URL_CHECKS:')

        features = ('score', 'upper', 'repetitions', 'punicode', 'domain_name_level', \
                        'avg_len', 'onMouseOver', 'hex', 'at_sign')
        url_features_dict = cls._get_empty_features_dict('url', features)
        # URL_UPPER: presense of elements in upper-case in URL
        # REPETITIONS: presense of repetitions like:
        # PUNICODE: respectively (very often for russian spams)
        # DOMAIN NAME LEVEL: very often russian spams are send from third-level domains
        # URL_AVG_LENGTH: they are short in general, cause of url-short services, etc
        # todo: many usual and not usual ideas about phising urls:
        # http://www.isteams.org/conference/pdf/Paper%20111-%20iSTEAMS%202014%20-Asani%20et%20al%20-%20MAXIMUM%20PHISH%20BAIT%20-%20TOWARDS%20FEATURE%20BASED%20DETECTION%20OF%20PHISING%20USING%20MAXIMUM%20ENTROPY%20CLASSIFICATION%20TECHNIQUE.pdf

        if not cls.netloc_list:
            return url_features_dict

        fqdn_regs = [
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

        txt_regs = [
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

        # cause also uses cls.netloc_list
        url_features_dict['url_score'] = cls.get_url_score(fqdn_regs, txt_regs)

        for method in [ unicode.isupper, unicode.istitle ]:
            url_features_dict['url_upper'] += len(filter(lambda s: method(s), cls.netloc_list))*cls.score

        # mostly thinking about shortened urls, created by tinyurl and other services,
        # but maybe this is weak feature
        url_features_dict['url_avg_len'] = math.ceil(float(sum([len(s) for s in cls.netloc_list]))/len(cls.netloc_list))

        puni_regex = ur'xn--[0-9a-z-]+(\.xn--[0-9a-z]+){1,3}'
        url_features_dict['punicode'] = len(filter(lambda u: re.search(puni_regex, u, re.I), cls.netloc_list))*cls.score

        url_features_dict['domain_name_level'] = len(filter(lambda n: n>=2, [s.count('.') for s in cls.netloc_list]))*cls.score

        return url_features_dict

    @classmethod
    def spam_content_checks(cls):
        # 9. check body
        logger.debug('>>> 9. CONTENT\'S TEXT PARTS CHECKS:')
        features = ('text_score', 'html_score', 'html_checksum')
        content_features_dict = cls._get_empty_features_dict('content', features)


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
                                    'width' : '[1-9]{3}[^%]',
                                    'height' : '[1-9]{1,3}',
                                    'cell(padding|spacing)' : '[1-9]',
                                    'border-color' : '#[0-9A-F]{3,6}',
                                    'border' : '[1-9]',
                                    'style' : '([A-Z-][^(a-z)]){3,10}'
                                },
                        'span' :{
                                    'style' : '(mso-.*|(x-)?large|([A-Z-][^(a-z)]){3,10}|VISIBILITY.*hidden|WEIGHT:.*bold)',
                                    'lang' : '(RU|EN-US)'
                                },
                        'p' :   {
                                    'style' : '(DISPLAY:\s*none|([A-Z-][^(a-z)]){3,10})|)',
                                    'class' : '\[\'(Mso.*|.*)\'\]',
                                    'align' : 'center',
                                    'css' : ''
                                }
                    }


        content_features_dict['text_score'] = cls.get_text_parts_metrics(regexp_list)
        content_features_dict['html_score'] = cls.get_html_parts_metrics(tags_map)

        return content_features_dict

    @classmethod
    def spam_attach_checks(cls):


        attach_score = cls.INIT_SCORE
        if not cls._msg.is_multipart():
            return attach_score

        attach_regs = [
                                r'(application\/(octet-stream|pdf|vnd.*|ms.*|x-.*)|image\/(png|gif|message\/))',\
                                r'.*\.(exe|xlsx?|pptx?|txt|maild.*|docx?|html|js|bat|eml|zip|png|gif|cgi)',
        ]

        attach_score = cls.get_attach_score(attach_regs, cls.score)

        return attach_score


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



'''''


	
			



