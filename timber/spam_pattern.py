#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-


import os, sys, logging, re, binascii, math

from operator import add, itemgetter
from collections import OrderedDict, Counter, namedtuple

import checkers
from pattern_wrapper import BasePattern


logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(filename)s %(message)s')
ch = logging.StreamHandler(sys.stdout)
logger.addHandler(ch)

from email import parser
parser = parser.Parser()
with open('/home/calypso/train_dir/abusix/0000006192_1422258877_ff43700.eml','rb') as f:
#with open('/tmp/201501251750_abusix/0000006194_1422258936_10744700.eml','rb') as f:
    M = parser.parse(f)

class SpamPattern(BasePattern):
    """
    Pattern class for build vectors, based on typical spam's features:
    -- if email looks like unconditional spam, it's vector will contain
        values, which are mostly don't equal to zeros ;
    """
    print('SPAMPATTERN ----------> FILL CLASS ATTRIBUTE TABLE')
    RCVDS_NUM = 2
    RCVD_RULES = [
                            r'(public|airnet|wi-?fi|a?dsl|dynamic|pppoe|static|account)+',
                            r'(\(|\s+)(([a-z]+?)-){0,2}(\d{1,3}-){1,3}\d{1,3}([\.a-z]{1,63})+\.(ru|in|id|ua|ch|)',
                            r'(yahoo|google|bnp|ca|aol|cic|([a-z]{1,2})?web|([a-z]{1-15})?bank)?(\.(tw|in|ua|com|ru|ch|msn|ne|nl|jp|[a-z]{1,2}net)){1,2}'
    ]
    EXCLUDED_HEADS = [
                            'Received', 'From', 'Subject', 'Date', 'MIME-Version', 'To', 'Message-ID', 'Cc','Bcc','Return-Path',\
                            'X-Drweb-.*', 'X-Spam-.*', 'X-Maild-.*','Resent-.*'
    ]
    # try greedy regexes, maybe will precise them in future


    SUBJ_RULES = [

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
                            ur'(ТАКСИ|Услуги\s+.*\s+учреждениям|Реклама|Рассылк.*\s+недорого|арбитражн.*\s+суд|ssТолько\s+для\s+(владельц.*|директор.*))',
                            ur'(Таможен.*(союз|пошлин.*|налог.*|сбор.*|правил.*)|деклараци.*|налог.*|больше\s+.*\s+заказ|ликвид|помоги)'
    ]

    SUBJ_FUNCTION = lambda z,x,y: y.index(x)%2

    SUBJ_TITLES_THRESHOLD = 3
    ATTACHES_RULES = [
                            r'(application\/(octet-stream|pdf|vnd.*|ms.*|x-.*)|image\/(png|gif|message\/))',\
                            r'.*\.(exe|xlsx?|pptx?|txt|maild.*|docx?|html|js|bat|eml|zip|png|gif|cgi)',
    ]

    TEXT_REGEXP_LIST = [
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

    HTML_TAGS_MAP = {
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

    URL_FQDN_REGEXP =       [
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

    URL_TXT_REGEXP = [
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

    print('SPAMPATTERN ----------> FISNISH CLASS ATTRIBUTE TABLE')

    def __init__(self, score, **kwds):
        '''
        :param kwds:
        # todo: initialize each <type>-pattern with it's own penalizing self.score,
        will be useful in vector-distance calculations, for axes stretching

        :return: expand msg_vector, derived from BasePattern class with
        less-correlated metrics, which are very typical for spams,

        '''
        self.PENALTY_SCORE = score

        super(SpamPattern, self).__init__(**kwds)




        features_map = {
                         'score'        : ['rcvd', 'mime', 'disp_notification'],
                         'subject'      : ['score','encoding','style','checksum'],
                         'dmarc'        : ['spf','score'],
                         'url'          : ['score','avg_len','distinct_count','sender_count',\
                                        'uppercase','punicode','fqdn','ascii','repetitions'],
                         'list'         : ['score'],
                         'attaches'     : ['score','in_score','count'],
                         'originator'   : ['checksum'],
                         'content'      : ['compress_ratio','avg_entropy','txt_score','html_score']
                         # would it be usefull compress_ratio for spams (search consequences here)
        }

        for key in features_map.iterkeys():
            logger.debug('Add '+key+'features to '+str(self.__class__))


            if key == 'score':
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


            # todo: probably less memory consuming for each iteration (create one checker instance, compute all features, ),
            # thought : what if features keeps all pattern's features

            # checker_obj.__getattr__(), which is overloaded in Wrapper class, would be called for instances intercepted by Wrapper ;
            # checker_obj.__getattr__() raises AttributeError, if attribute-method in < name > wasn't implemented in real Checker instance :
            # cause this is interface mistake, rooted from code architecture, not from processing email's oddities.
            functions_map = [(name.lstrip('get_'), getattr(checker_obj, name)) for name in features]

            print('call functions')
            for name, f in functions_map:
                feature_value = lambda: self.INIT_SCORE
                print(name)
                print(f)
                try:
                    feature_value = f()
                except Exception as err:
                    logger.error(str(err).upper())
                    pass

                self.__setattr__(name, feature_value)

        logger.debug('SpamPattern was created'.upper()+' :'+str(id(self)))
        logger.debug('SpamPattern instance final dict '+str(self.__dict__))
        logger.debug("++++++++++++++++++++++++++++++++++++++++++++++++++")
        logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))


    def get_rcvd_score(self):

        # 1. "Received:" Headers
        rcvd_score = self.INIT_SCORE
        logger.debug('>>> 1. RCVD_CHECKS:')
        for rule in self.RCVD_RULES:
            if filter(lambda l: re.search(rule, l), self.get_rcvds(self.RCVDS_NUM)):
                rcvd_score += self._penalty_score

        return rcvd_score

    # particular feature and method
    def get_mime_score(self):

        mime_score = self.INIT_SCORE
        if not self.msg.is_multipart() and self.msg.get('MIME-Version'):
            mime_score += self._penalty_score
            logger.debug(mime_score)

        elif not self.msg.is_multipart():
            logger.debug(mime_score)

        if self.msg.preamble and not re.search('This\s+is\s+a\s+(crypto.*|multi-part).*\sMIME\s.*', self.msg.preamble, re.I):
            mime_score += self._penalty_score
            logger.debug('\t----->'+str(mime_score))

        logger.debug('mime_score: '.upper() +str(mime_score))

        return mime_score

    def get_disp_notification_score(self):

        disp_notification = self.INIT_SCORE
        if self.msg.keys().count('Disposition-Notification-To'):
            disp_notification = self._penalty_score

        return disp_notification


