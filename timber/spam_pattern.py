#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-


import os, sys, logging, re, binascii, math

from operator import add, itemgetter
from collections import OrderedDict, Counter, namedtuple

from pattern_wrapper import BasePattern
import checkers

logger = logging.getLogger('')
#logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(filename)s >>> %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#logger.addHandler(ch)


#from email import parser
#parser = parser.Parser()
#with open('/home/calypso/debug/spam/0000000175_1422266129_bc57f700.eml','rb') as f:
#with open('/home/calypso/train/ham/without_rcvds.eml','rb') as f:
#with open('/home/calypso/train_dir/abusix/0000006192_1422258877_ff43700.eml','rb') as f:
#with open('/tmp/201501251750_abusix/0000006194_1422258936_10744700.eml','rb') as f:
#    M = parser.parse(f)


class SpamPattern(BasePattern):
    """
    Pattern class for build vectors, based on typical spam's features:
    -- if email looks like unconditional spam, it's vector will contain
        values, which are mostly don't equal to zeros ;
    """

    RCVDS_NUM = 2
    RCVD_RULES = [
                            r'(public|airnet|wi-?fi|a?dsl|dynamic|pppoe|static|account|unknown|trap)+',
                            r'(\(|\s+)(([a-z]+?)-){0,2}(\d{1,3}-){1,3}\d{1,3}([\.a-z]{1,63})+\.(ru|in|id|ua|ch|)',
                            r'(yahoo|google|bnp|ca|aol|cic|([a-z]{1,2})?web|([a-z]{1-15})?bank)?(\.(tw|in|ua|com|ru|ch|msn|ne|nl|jp|[a-z]{1,2}net)){1,2}'
    ]
    EXCLUDED_HEADS = [

                            'Received', 'From', 'Subject', 'Date', 'MIME-Version', 'To', 'Message-ID', 'Cc','Bcc','Return-Path',\
                            'X-Drweb-.*', 'X-Spam-.*', 'X-Maild-.*','Resent-.*'
    ]
    # try greedy regexes, maybe will precise them in future

    ORIGINATOR_LOCALNAMES_RULES = [
                                        r'^(\d{1,4}[\w_-]+)+$',
                                        r'^([\w_-]+(\d{1,4})?)+$',
                                        r'(webmaster|admin|mail|info|contact|flyboy|girl|passion|lady)'
    ]

    ORIGINATOR_MAILBOX_RULES = [
                                    ur'((top)?meds|miss\s+you|flyboy|pfizer|fellowship)\s+.*',
                                    ur'(mail|admin|(passion|kiss(-you)?)(-info)?|lipstick|wine\s+red|face\s+to\s+face)\s+.*',
                                    ur'(pickup|cute girl|(happy|good)letter|real-time|sweet_mail|security)\s+.*',
                                    ur'(dark|gray|green|blue|turquoise|one-stop-log-in|cool-cool|eyes|updating)\s+.*'
    ]

    ORIGINATOR_LOCAL_NAME_LEN = 15


    SUBJ_RULES = [

                            ur'((s)?sn|v+i+a+g+r+a+|c+i+a+(l|1)+i+(s|\$|z)+|pfizer|discount|med|click|Best\s+Deal\s+Ever|,|\!|\?!|>>\:|sale|-)+',
                            ur'[\d]{1,2}\s+[\d]{1,2}[0]{1,3}\s+.*',
                            ur'-?[\d]{1,2}\s+%\s+.*',
                            ur'[\d](-|\s+)?\S{1,4}(-|\s+)?[\d]\s+.*',
                            ur'[\*-=\+~]{1,}\S+[\*-=\+~]{1,}',
                            ur'(free.*(pills?).*(every?)*.*(order)*|online.*&.*(save)*|tablet.*(split?ed?)*.*has?le)',
	                        ur'(cheap([est])?.*(satisf[ied]?)*.*(u[sk])*.*(canadian)*.*customer|to.*be.*remov([ed])?.*(please?)*)',
	                        ur'(100%\s+guarantee?d|free.{0,12}(?:(?:instant|express|online|no.?obligation).{0,4})+.{0,32})',
	                        ur'(dear.*(?:it\w|internet|candidate|sirs?|madam|investor|travell?er|car\sshopper|ship))+',
                            ur'^\s*(hello|hi|good\s+(morning|evening)|hey([:;\)])?)\s+.*',
                            ur'^\s*(meet\s+now\s+(greasy|dear|darling|babe|lady)\s+)|satisf(y|ied)\s+.*((to)?night|customer)\s+.*',
                            ur'.*(eml|spam).*',
                            ur'.*(payment|receipt|attach(ed)?|extra\s+inches)',
                            ur'(такси|услуги\s+.*\s+учреждениям|реклама|рассылк.*\s+недорого|арбитражн.*\s+суд|ssтолько\s+для\s+(владельц.*|директор.*))',
                            ur'(таможен.*(союз|пошлин.*|налог.*|сбор.*|правил.*)|деклараци.*|налог.*|больше\s+.*\s+заказ|ликвид|помоги)'
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
                            ur'(100%\s+guarantee?d||no\s*obligation|no\s*prescription\s+required?|(whole)?sale\s+.*prices?|phizer|pay(ment)?)',
                            ur'(candidate|sirs?|madam|investor|travell?er|car\s+.*shopper|free\s+shipp?ing|(to)?night|bed|stock|payroll)',
                            ur'(prestigi?(ous)|non-accredit[ed]\s+.*(universit[yies]|institution)|(fda[-\s_]?approved|superb?\s+qua[l1][ity])\s+.*drugs?(\s+only)?)',
                            ur'(accept\s+all?\s+(major\s+)?(credit\s+)?cards?|(from|up)\s+(\$|\u20ac|\u00a3)\d{1,3}[\.\,:\\]\d{1,3}|order.*online.*save)',
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
                            ur'(free|shipping|options|pills|every?|order|best|deal|today|now|contact|pay|go)+',
                            ur'(сcылк|курс|цен|посмотреть|каталог|здесь|сюда|регистрация|бесплатное|участие|на\s+сайт|подробн)',
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
                         'pattern_score'    : ['rcvd', 'mime', 'disp_notification'],
                         'subject'          : ['score','encoding','upper','titled','checksum'],
                         'url'              : ['score','avg_len','distinct_count','sender_count',\
                                                'uppercase','punicode','fqdn','ascii','repetitions'],
                         'list'             : ['score'],
                         'attaches'         : ['score','in_score','count'],
                         'originator'       : ['checksum','addr_score'],
                         'content'          : ['compress_ratio','avg_entropy','txt_score','html_score']
                         # would it be usefull compress_ratio for spams (search consequences here)
        }

        for key in features_map.iterkeys():
            logger.debug('Add '+key.upper()+' features to SpamPattern vector :')


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


            # todo: probably less memory consuming for each iteration (create one checker instance, compute all features, ),

            functions_map = [(name.lstrip('get_'), getattr(checker_obj, name, lambda : self.INIT_SCORE)) for name in features]

            for name, f in functions_map:
                feature_value = self.INIT_SCORE
                print(name)
                print(f)
                try:
                    feature_value = f()
                except Exception as err:
                    logger.error(str(err).upper())
                    pass

                logger.debug((name+' ==> '+str(feature_value)).upper())
                self.__setattr__(name, feature_value)

            print('===========\n'+str(self.__dict__).upper()+'\n')

        logger.debug('SpamPattern was created'.upper()+' :'+str(id(self)))

        for (k,v) in sorted(self.__dict__.items()):
            logger.debug(str(k).upper()+' ==> '+str(v).upper())


        logger.debug("++++++++++++++++++++++++++++++++++++++++++++++++++")
        logger.debug("total vect len : "+str(len(self.__dict__.items())-1))
        non_zero = [v for k,v in self.__dict__.items() if float(v) !=0.0 ]
        logger.debug("non_zero features count : "+str(len(non_zero)))
        #logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))


    def get_rcvd_pattern_score(self):

        # 1. "Received:" Headers
        rcvd_score = self.INIT_SCORE
        rcvds = self.get_rcvds(self.RCVDS_NUM)
        logger.debug('get_rcvd_score : '+str(rcvds))

        for rule in self.RCVD_RULES:
            if filter(lambda l: re.search(rule, l), rcvds):
                rcvd_score += self.PENALTY_SCORE

        for rcvd in [tuple(l.split()) for l in rcvds]:
            if rcvd[0] == 'from' and rcvd[1].count('.') == 0:
                rcvd_score += self.PENALTY_SCORE

        return rcvd_score

    # particular feature and method
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


