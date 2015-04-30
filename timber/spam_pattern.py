#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-

import sys, logging, re

from pattern_wrapper import BasePattern
import checkers

logger = logging.getLogger('')
#logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(levelname)s %(funcName)s: %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#ch.setLevel(logging.DEBUG)
#ch.setFormatter(formatter)
#logger.addHandler(ch)

#from email import parser
#parser = parser.Parser()
#with open('','rb') as f:
#    M = parser.parse(f)


class SpamPattern(BasePattern):
    """
    Pattern class for build vectors, based on typical spam's features:
    -- if email looks like unconditional spam, it's vector will contain
        values, which are mostly don't equal to zeros ;
    """

    AXIS_STRETCHING = 2.0
    RCVDS_NUM = 2
    RCVD_RULES = [
                            r'(public|airnet|wi-?fi|a?dsl|dynamic|pppoe|static|account|unknown|trap)', \
                            r'(\(|\s+)(([a-z]+?)-){0,2}(\d{1,3}-){1,3}\d{1,3}([\.a-z]{1,63})+\.(ru|in|id|ua|ch|)', \
                            r'(bnp|ca|aol|cic|([a-z]{1,2})?web|([a-z]{1-15})?bank)?(\.(tw|in|ua|ru|ch|msn|ne|nl|jp|[a-z]{1,2}net)){1,2}'
    ]
    EXCLUDED_HEADS = [

                            'Received', 'From', 'Subject', 'Date', 'MIME-Version', 'To', 'Message-ID', 'Cc','Bcc','Return-Path',\
                            'X-Drweb-.*', 'X-Spam-.*', 'X-Maild-.*','Resent-.*'
    ]
    # try greedy regexes, maybe will precise them in future

    ORIGINATOR_LOCALNAMES_RULES = [
                                        r'(flyboy|girl|passion|lady)'
    ]

    ORIGINATOR_MAILBOX_RULES = [
                                    ur'((top)?meds|miss.*you|flyboy|pfizer|fellowship|invacare)', \
                                    ur'(passion|kiss(-you)?|lipstick|wine.*red|face.*to.*face)', \
                                    ur'(pickup|cute.*girl|(happy|good).*letter|real-time|sweet_mail)', \
                                    ur'(dark|gray|green|blue|turquoise|one-stop-log-in|cool-cool|eyes)'
    ]

    ORIGINATOR_LOCAL_NAME_LEN = 15


    SUBJ_RULES = [

                            ur'(s+n|v+i+a+g+r+a+|c+i+a+(l|1)+i+(s|\$|z)+|pfizer|discount|med|click)', \
                            ur'([0-9]{1,2}\s+[\d]{1,2}[0]{1,3}\s+|Best.*Deal.*Ever|\!|\?!|>>\:|sale|-)', \
                            ur'(-?[0-9]{1,2}\s+%\s+|[0-9](-|\s+)?\S{1,4}(-|\s+)?[\d]\s+)', \
                            ur'([\*-=\+~]{1,}\S+[\*-=\+~]{1,}|(eml|spam)|tablet.*(split?ed?)?.*(has?le)?)', \
                            ur'(free.*(pills?)?.*(every?)?.*(order)|online.*&.*(save)?)', \
	                        ur'(cheap[est]?|satisf[ied]?|(uk|us|canad[ian]?).*customer)', \
	                        ur'((100%)?.*guarantee?d.*(100%)?|free.*instant|express.*online|no\s?obligation)',\
	                        ur'(dear|candidates?|sirs?|madam|investor|travell?er|car.*shopper|ship[ing]?)', \
                            ur'(hello|discree?t|fast|hi|good.*(morning|evening)|hey([:;\)])?)', \
                            ur'(meet.*now.*(greasy|dear|darling|babe|lady)|satisf(y|ied).*((to)?night|customer))', \
                            ur'(pay(ment)?|receipt?|attach(ed)?|extra.*inches|to.*be.*remov[ed]?.*(please)?)', \
                            ur'(такси|услуги.*чреждениям|реклама|рассылк.*недорого|арбитражн.*суд)', \
                            ur'(таможен.*(союз|пошлин.*|налог.*|сбор.*|правил.*)|деклараци.*|налог.*)', \
                            ur'(больше.*заказ|ликвид|помоги|деньи|нужны||только.*для.*(владельца?|директора?))'
    ]

    SUBJ_TITLES_THRESHOLD = 3
    ATTACHES_RULES = [
                            r'(application\/(octet-stream|pdf|vnd.*|ms.*|x-.*)|image\/(png|gif|message\/))',\
                            r'.*\.(exe|xlsx?|pptx?|txt|maild.*|docx?|html|js|bat|eml|xz|rar|zip|png|gif|cgi)'
    ]

    TEXT_REGEXP_LIST = [

                            ur'(opportunit[eé]|exception?nel+e?|gratui?te?[ment]?)',\
                            ur'(ventes+.*priv[ée]|pea\s+enterpris[ing]?|tablet.*(split?ed?)?.*(has?le)?)',\
                            ur'(order.*ciali[zs].*viagra|0nline|extremely.*avalanche)',\
                            ur'(order.*today!|cialis.*levitre?|free|combo|superb?.*qua[l1ity])',\
                            ur'(bu[ying]|hey(-hey)?|(on)?sale|click|open|trad[eing]?)', \
                            ur'(free.*(pills?)?.*(every?)?.*(order)?|online.*&.*(save)?)', \
	                        ur'(cheap[est]?|satisf[ied]?|(uk|us|canad[ian]).*(customer)?)',\
	                        ur'(to.*(be)?.*remov[eding].*(please)?|drugs?.*(only)?)', \
	                        ur'((100%)?.*guarantee?d.*(100%)?|free.*instant|express.*online|no\s?obligation)',\
                            ur'(v?i?a?g?r?a?|ciali[sz]|doctors?|d(y|i)sfunction|discount.*(on)?.*(all)?)',\
                            ur'(medications?|remed[yie]*|[0-9]{1,4}mg|(to)?night|bed|stock|payroll?|pharmacy?)',\
                            ur'(no\s+prescriptions?|(whole)?.*sale.*prices?|phizer|pay(ment)?)', \
                            ur'(candidate|sirs?|inves(tor)?|travell?er|car.*shopp?[er]|free.*shipp?[ing]?)', \
                            ur'(prestigi?[ous]|(non-)?accredit[ed]?.*(universit[yies]|institution)|approv[ed]?)', \
                            ur'(accept.*all.*credit.*cards|(\$|\u20ac|\u00a3)[0-9]{1,3}[\.\,:\\][0-9]{1,3})',\
                            ur'(автомати[зиче].*доход|халяв[аыне].*деньг|куп.*продае|объявлен.*реклам|фотки.*смотр.*зажгл.*)',\
                            ur'(виагра|икра.*(в)?.*офис|ликвидац[иярова]?.*(по)?.*законy?|бухгалтер[ия]?|франши.*|киев)',\
                            ur'(\+[0-9])?(\([Ч4][0-9]{2}\))?(([0-9]\s{0,2}\s?){2,3}){1,4}',\
                            ur'((augment|gain|profit|demand)[ezntsor]?|facile|maigri[rstonezt]?|cash|liquide|perfomance)'
    ]

    URL_FQDN_REGEXP =       [
                            ur'tinyurl\.', \
                            ur'(\w{3,6}-){1,3}\w{2,45}(\.\w{2,5}){0,3}', \
                            ur'\D{1,3}(\.|-)\w{1,61}(\.\w{2,5}){0,3}', \
                            # match if contains only non-ascii
                            ur'[^\u0000-\u002C\u002E-\u005E\u0061-\u007F]{1,61}\.[^\u0000-\u002C\u002E-\u005E\u0061-\u007F]{1,6}', \
                            ur'(\w{1,10}\.)?[^\u0000-\u002C\u002E-\u005E\u0061-\u007F]{1,61}\.[^\u0000-\u002C\u002E-\u005E\u0061-\u007F]{1,6}', \
                            ur'(\d{1,10}\.)?[^\u0000-\u002C\u002E-\u005E\u0061-\u007F]{1,61}\.[^\u0000-\u002C\u002E-\u005E\u0061-\u007F]{1,6}', \
                            ur'([0-9-]{1,61}\.?){1,3}(\D{2,5}\.?){0,3}', \
                            ur'(\w{3,6}-){1,3}\w{2,45}\.(\w{2,5}){0,3}', \
                            ur'\w{1,61}(\.[a-zA-z]{1,4}){0,2}\.(in|me|ua|ru|mobi|red|es)', \
                            ur'\w{1,61}\.(in.ua|ru.all.biz|gl|ee|pp.ua|kiev.ua|com.ua|ro|lviv.ua|ly|pro|co.jp|c|c=|lt|by|asia)', \
                            ur'\w{1,3}(\.[a-zA-Z]{1,4}){1,3}', \
                            ur'(.*-loader|lets-|youtu.be|goo.gl|wix.com|us[0-9].|jujf.ru)', \
                            ur'\w{1,61}(\.\w{1,4}){0,3}\.\w{1,3}([^\u0000-\u007F]{1,3}|[0-9]{1,5})'

    ]

    URL_TXT_REGEXP = [
                            ur'(click|here|link|login|update|confirm|legilize|now.*buy|online|movie|s(0|e)x(room|boat))', \
                            ur'(free|shipp[ing]?|options?|pill?s?|every?|order|best|deal|today|now|contact|pay|go)', \
                            ur'(сcылк|курс|цен|посмотреть|каталог|здесь|сюда|регистрация)', \
                            ur'(горяч|скидк|отписаться|отказаться|бесплатное|участие|на.*сайт|подробн)', \
                            ur'\/[\u0000-\u001F\u0041-\u005A\u0061-\u007A]{1,3}[^\u0000-\u007F]{2,}', \
                            ur'[^\u0000-\u007F]{2,}(\.|\?|!|;){0,}', \
                            ur'(cid:)?\w{1,40}@([0-9]{1,3}-){1,3}[0-9]{1,3}(\.[A-Za-z]{1,10}){1,3}', \
                            ur'([\a\b\t\r\n\f\v]{0,}|[\?!])', \
                            ur'(\S*)http:.*', \
                            ur'[\u0000-\u001F\u0041-\u005A\u0061-\u007A]{3,}', \
                            ur'[\+=\$]{1,3}(\w){0,}', \
                            ur'\+?[0-9](\[|\()[0-9]{3}(\)|\])\s?[0-9~-]{0,}'
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

        features_map = {
                         'pattern_score'    : ['rcvd', 'mime', 'disp_notification'], \
                         'subject'          : ['score','encoding','upper','checksum'], \
                         'url'              : ['score','avg_len','distinct_count','sender_count',\
                                                'uppercase','punicode', 'repetitions'], \
                         'list'             : ['score'], \
                         'attaches'         : ['score','in_score','count'], \
                         'originator'       : ['checksum','addr_score'], \
                         'content'          : ['txt_score']
        }

        for key in features_map.iterkeys():

            if key == 'pattern_score':
                features = ['get_'+name+'_'+key for name in features_map[key]]
                checker_obj = self
            else:
                features = ['get_'+key+'_'+name for name in features_map[key]]
                # initialize  checker_obj with decorated particular Checker class,
                # see Wrapper class-decorator from decorators.py module

                checker_obj = checkers.__getattribute__(key.title()+'Checker')
                # if fails in checker_obj.__init__() --> checker_obj will be
                # intercepted by Wrapper decorated class itself from decorators.py module
                checker_obj = checker_obj(self)

            functions_map = [(name.lstrip('get_'), getattr(checker_obj, name, lambda : self.INIT_SCORE)) for name in features]

            for name, f in functions_map:
                feature_value = self.INIT_SCORE
                try:
                    feature_value = f()
                except Exception as err:
                    logger.error(f.func_name+': '+str(err))
                    pass

                self.__setattr__(name, feature_value)

        #  try to switch on/off features in attempt to improve this pythonic-chaos
        self.__delattr__('all_heads_checksum')


    def __str__(self):
        return('SPAM')

    def get_rcvd_pattern_score(self):

        rcvd_score = self.INIT_SCORE
        rcvds = self.get_rcvds(self.RCVDS_NUM)

        #logger.debug('get_rcvd_score : '+str(rcvds))

        for rule in self.RCVD_RULES:
            if filter(lambda l: re.search(rule, l), rcvds):
                rcvd_score += self.PENALTY_SCORE*2

        return rcvd_score

    def get_mime_pattern_score(self):

        mime_score = self.INIT_SCORE
        if not self.msg.is_multipart() and self.msg.get('MIME-Version'):
            mime_score += self.PENALTY_SCORE

        if not self.msg.is_multipart():
            mime_score += self.PENALTY_SCORE

        if self.msg.preamble and not re.search('This\s+is\s+a\s+(crypto.*|multi-part).*\sMIME\s.*', self.msg.preamble, re.I):
            mime_score += self.PENALTY_SCORE

        return mime_score

    def get_disp_notification_pattern_score(self):

        disp_notification = self.INIT_SCORE
        if self.msg.keys().count('Disposition-Notification-To'):
            disp_notification = self.PENALTY_SCORE

        return disp_notification


'''''
 different features maps, tune and try, according to obtained results and Classifier's strong features estimation

 features_map = {
                         'pattern_score'    : ['rcvd', 'mime', 'disp_notification'], \
                         'subject'          : ['score','encoding','upper','checksum'], \
                         'url'              : ['score','avg_len','distinct_count','sender_count',\
                                                'uppercase','punicode', 'repetitions'], \
                         'list'             : ['score'], \
                         'attaches'         : ['score','in_score','count'], \
                         'originator'       : ['checksum','addr_score'], \
                         'content'          : ['txt_score']
        }
'''''