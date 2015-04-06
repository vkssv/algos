#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
""" Keeps and applies vectorising rules for infos. """

import os, sys, logging, re, binascii, math, string

from operator import add
from collections import OrderedDict, Counter

from pattern_wrapper import BasePattern

formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
logger.addHandler(ch)


class InfoPattern(BasePattern):
    """
    Pattern class for build vectors, based on typical newsletters
    and ads-mails features :

        -- if email looks like news-letter, it's vector will contain
            values, which are mostly don't equal to zeros ;
    """

    RCVDS_NUM = 0

    EXCLUDED_HEADS = [
                            'Received', 'Subject', 'From', 'Date', 'Received-SPF', 'To', 'Content-Type',\
                            'Authentication-Results', 'MIME-Version', 'DKIM-Signature', 'Message-ID', 'Reply-To'
    ]

    EMARKET_HEADS = r'^X-(EM(ID|MAIL|V-.*)|SG-.*|(rp)?campaign(id)?)$'
    KNOWN_MAILERS   = [ r'MailChimp', r'PHPMailer', r'GetResponse\s+360', 'GreenArrow', 'habrahabr', 'nlserver' ]

    # take crc32 from the second half (first can vary cause of personalisation, etc)
    SUBJ_FUNCTION = lambda z,y: y[len(y)/2:]
    SUBJ_TITLES_THRESHOLD = 3

    # try greedy regexes, maybe will precise them in future
    SUBJ_RULES = [

                            ur'([\u25a0-\u29ff]|)', # dingbats
                            ur'([\u0370-\u03ff]|[\u2010-\u337b]|)', # separators, math, currency signs, etc
                            ur'^(Hi|Hello|Good\s+(day|(morn|even)ing)|Dear\s+){0,1}\s{0,}[\w-]{2,10}(\s+[\w-]{2,10}){0,3},.*$',
                            ur'^\s*(what\s+(are|is)|why|how\s+(do)?|when|since|could|may|is|in).*[\?!:;\s-]{0,}.',
                            ur'(SALE|FREE|News?|Do\s+not\s+|Don\'t\s+|miss\s+|They.*back|is\s+here|now\s+with)+',
                            ur'(interesting|announcing|hurry|big(gest)?|great|only|deal|groupon|tour|travel|hot|inside)+',
                            ur'(all\s+for|price|vip|special|trends|brands|shopping|hysteria|save|kick|super(b)?)+',
                            ur'(Now\s+or\s+Never|call|share|stock|exclusive|free\s+shipping|car|shopper|bonus)+',
                            ur'(lpg|spa|trend|brand|opportunity|be\s+the\s+first|get\s+it\s+now|see|look|watch)+'
                            ur'(Нов|Скидк|(Сам|Ожидаем)[аяыйео]|Распродаж|Покупк|Товар|Выгодн|Внутри)+',
                            ur'(Дар|Отда[мёе]|предложени|горяч|Здравствуйте|Спасибо|Привет|Внимание|Больше|бешен)+',
                            ur'(Скидк|Акци|Купон|Групон|Тур|Открой|Лет|много|Уведомля|Только|Сегодня|Сезонн|Вс(е|ё)\s+д(о|ля))+',
                            ur'(Жар|Выходн[ыоей]|Посетите|Подготовьте|Отпуск|режем\s+цены|купи|мода|шопинг)+',
                            ur'(теперь\s+и\s+для|ликвид|эксклюзив|информационн\s+(выпуск|анонс)|продаж|рублей|хит|топ)+',
                            ur'(доставка\s+(бесплатн)?|сниж|низк|магаз|курьер|специал|перв|супер)+',
                            ur'(Зим|Осен|Вес[енa]|Каникул|Празник|Год)+',
                            ur'([\w\s-]{2,10}){1,2}\s*:([\w\s+,\.\$!]{2,15})+',
                            ur'[\d]{1,2}\s+[\d]{1,2}[0]{1,3}\s+.*',
                            ur'-?[\d]{1,2}\s+%\s+.*',
                            ur'[\d](-|\s+)?\S{1,4}(-|\s+)?[\d]\s+.*',
                            ur'[\*-=\+~]{1,}\S+[\*-=\+~]{1,}'
    ]

    ATTACHES_RULES = [
                                r'format\s?=\s?.fixed.'
    ]

    TEXT_REGEXP_LIST = [
                                ur'(styl(ish)?|perfect|beauti|winter|summer|fall|spring|look|blog|spot)',
                                ur'(news|letter|discount|sale|info|unsubscribe|bonus|ads|market)',
                                ur'((social)?media|partage|share|actu|publicité|télécharger|download)',
                                ur'(RECOMMENDA[TIONS]*)'
    ]

    HTML_TAGS_MAP = {

                            'img'   :{
                                        'alt'   : '',
                                        'src'   : '(logo|promo|content|btn\.|butt\.|avatar|user|banner|content|download|send(friend)?|actions)',
                                        'title' : '.*'
                            },
                            'span'  :{
                                        'style' : 'color\s?:\s?(\w{3,10}|#[a-z0-9]{3,6})',
                                        'class' : '(\[\'.*\'\]|recommenda.*)'
                            }

    }

    URL_FQDN_REGEXP =   [
                                    ur'(news(letter)?|trip|sales+|offer|journal|event|post|asseccories|rasprodaga)',
                                    ur'(global|response|click|shop|sale|flight|hotel|cit(y|ies)|campaign|bouquet)',
                                    ur'(celebration|friday|binus|magazin|cheap|subscibe|manage|feed|list|blog)',
                                    ur'(programm|online|create|amazon|meetup|book|flowers|app|connect|emea|habrahabr|media)',
                                    ur'(citilink|ulmart|lamoda|nero-|vip|ideel|quora|yves-rocher|fagms.de|wix.com|papers)',
                                    ur'(opportunity|whites+|chance|email|practice|yr-ru|us\d-|stanford|brands+|labels+)',
                                    ur'(look-at-media|digest|the-village|ozon.ru|enter.ru)'

    ]

    URL_TXT_REGEXP = [
                                    ur'(cheap.*|prices+|clothes+|action|shoes+|women|label|brand|zhensk|odezhd)',
                                    ur'(campaign|rasprodaga|requirements|choice|personal|track|click|customer|product)',
                                    ur'(meetup|facebook|twitter|pinterest|vk|odnoklassinki|google)_footer',
                                    ur'(training|mailing|modify|unsub|newsletter|catalog|mdeia|graphics|announcement)',
                                    ur'(utm_medium=|utm_source=|utm_term=|utm_campaign=|applications+|upn=|aspx\?)',
                                    ur'(shop|magazin|collections+|lam|(mail_link_)?track(er)?|EMID=|EMV=|genders)'

    ]

    def __init__(self, **kwds):
        '''
        :param kwds:
        # todo: initialize each <type>-pattern with it's own penalizing self.score,
        will be useful in vector-distance calculations, for axes stretching

        :return: expand msg_vector, derived from BasePattern class with
        less-correlated metrics, which are very typical for spams,
        '''
        print('IN INFO_PATTERN CONSTRUCTOR, DELEGATE INSTANCE CREATION')

        super(InfoPattern, self).__init__(**kwds)


        features_map = {
                         'score'        : ['mime'],
                         'subject'      : ['score','len','encoding','style','checksum'],
                         'emarket'      : ['score','flag'],
                         'url'          : ['score','count','avg_query_len','distinct_count','sender_count','ascii',\
                                           'query_sim','path_sim','avg_path_len'],
                         'list'         : ['score','delivered_to'],
                         'attach'       : ['score','in_score','count'],
                         'originator'   : ['checksum'],
                         'content'      : ['compress_ratio','avg_entropy','txt_score','html_score','html_checksum']
        }

        for key in features_map.iterkeys():
            logger.debug('Add '+key+'features to '+str(self.__class__))

            if key == 'score':
                features = ['get_'+name+'_'+key for name in features_map[key]]
                checker_obj = self
            else:
                features = ['get_'+key+'_'+name for name in features_map[key]]
                checker_obj = checkers.__getattribute__(key.title()+'Checker')
                checker_obj = checker_obj(self)

            functions_map = [(name.lstrip('get_'), checker_obj.__getattribute__(name)) for name in features]
            [self.__setattr__(name, f()) for name,f in functions_map]

            self.dmarc_x_score = len(filter(lambda h: re.match('X-DMARC(-.*)?', h, re.I), self._msg.keys()))


        logger.debug('SpamPattern was created'.upper()+' :'+str(id(self)))
        logger.debug('SpamPattern instance final dict '+str(self.__dict__))

        logger.debug("++++++++++++++++++++++++++++++++++++++++++++++++++")

        logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))
        super(InfoPattern, self).__init__(**kwds)





        # 2. Subject
        #self.get_subj_features(['subj_'+name for name in features_dict.get('subj')])



        # 6. Checks for MIME attributes


        # 7. URL-checks
        #self.get_url_features(['url_'+name for name in features_dict.get('url')])

        logger.debug('InfoPattern was created'.upper()+' :'+str(id(self)))
        #logger.debug(self.__dict__)
        for (k,v) in self.__dict__.iteritems():
            logger.debug(str(k).upper()+' ==> '+str(v).upper())
        logger.debug("++++++++++++++++++++++++++++++++++++++++++++++++++")
        #logger.debug(SpamPattern.__dict__)
        for (k,v) in self.__dict__.iteritems():
            logger.debug(str(k).upper()+' ==> '+str(v).upper())
        logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))





        def get_list_features():
            # 5. List checks and some other RFC 5322 compliences checks for headers
            logger.debug('>>> 5. LIST CHECKS:')
            list_features = ('basic_checks', 'ext_checks','sender','precedence','typical_heads','reply-to','delivered')
            list_features_dict = dict(zip(['list_'+x for x in list_features], [self.INIT_SCORE]*len(list_features)))

            logger.debug('\t----->'+str(list_features_dict))

            if filter(lambda list_field: re.match('(List|Errors)(-.*)?', list_field,re.I), self._msg.keys()):
                list_features_dict['basic_checks'] = self.get_list_metrics(score)
                logger.debug('\t----->'+str(list_features_dict))

            # for old-school style emailings
            matched = filter(lambda h_name: re.match('List-(Id|Help|Post|Archive)', h_name, re.I), self._msg.keys())
            list_features_dict['ext_checks'] = len(matched)

            keys = tuple(filter(lambda k: self._msg.get(k), ['From','Sender','Reply-To','Delivered-To','To']))
            #addr_dict = dict([(k,self.get_addr_values(value)[1][0]) for k,value in zip(keys, tuple([self._msg.get(k) for k in keys]))])
            logger.debug(str([ self.get_addr_values(self._msg.get_all(k)) for k in keys]))
            addr_dict = dict([(k, (self.get_addr_values(self._msg.get_all(k)))[0]) for k in keys])
            logger.debug('>>>>>'+str(addr_dict))

            if addr_dict.get('Sender') and addr_dict.get('Sender') != addr_dict.get('From'):
                list_features_dict['sender'] = 1
                logger.debug('\t----->'+str(features_dict))

                if addr_dict.get('Reply-To'):
                    domains = [(addr_dict.get(n)).partition('@')[2] for n in ['Reply-To','Sender']]
                    if len(set(domains)) == 1:
                        list_features_dict['reply-to'] = 1

            if addr_dict.get('Delivered-To') and addr_dict.get('Delivered-To') != addr_dict.get('To'):
                list_features_dict['delivered'] = 1

            if self._msg.get('Precedence') and self._msg.get('Precedence').strip() == 'bulk':
                list_features_dict['precedence'] = 1

            for name_reg in [r'Feedback(-ID)?', r'.*Campaign(-ID)?','Complaints(-To)?']:
                matched_list = filter(lambda head_name: re.match(r'(X-)?'+name_reg,head_name,re.I),self._msg.keys())
                list_features_dict['typical_heads'] = len(matched_list)

            vector_dict.update(list_features_dict)
            logger.debug('\t----->'+str(vector_dict))

            # 4. crc for From values
            # move to BasePattern
            logger.debug('>>> 6. ORIGINATOR_CHECKS:')
            vector_dict['from'] = self.INIT_SCORE
            logger.debug('\t----->'+str(vector_dict))

            if self._msg.get('From'):
                from_value, from_addr = reduce(add, self.get_addr_values(self._msg.get_all('From')))
                logger.debug(from_value)

                if from_value:
                    vector_dict['from_checksum'] = binascii.crc32(from_value.encode(self.DEFAULT_CHARSET))
                    logger.debug('\t----->'+str(vector_dict))

            logger.debug('\t----->'+str(vector_dict)+'\n')


    def get_mime_score(self):

        logger.debug('>>> 7. MIME CHECKS:')
        logger.debug('IS MULTI >>>>>> '+str(self._msg.is_multipart()))
        if not self.msg.is_multipart():
            return self.mime_score

        # all infos are attractive nice multiparts...
        self.mime_score += self._penalty_score

        first_content_type = self.msg.get('Content-Type')
        if 'text/html' in first_content_type and re.search('utf-8', first_content_type, re.I):
            self.mime_score += self._penalty_score

        mime_skeleton = self.get_mime_struct()
        logger.debug('MIME STRUCT: '+str(mime_skeleton))
        if (mime_skeleton.keys()).count('text/html') and 'inline' in mime_skeleton.get('text/html'):
            self.mime_score += self._penalty_score

        logger.debug(self.mime_score)
        return mime_score

if __name__ == "__main__":

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    try:
        test = InfoPattern(env)
        vector = test.run()
        logger.debug(str(vector))


    except Exception as details:
        raise



	
			



