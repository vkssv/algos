#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
""" Keeps and applies vectorising rules for infos. """

import os, sys, logging, re, binascii, math, string

from operator import add
from collections import OrderedDict, Counter

from pattern_wrapper import BasePattern

# formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class InfoPattern(BasePattern):
    """
    Pattern class for build vectors, based on typical newsletters
    and ads-mails features :

        -- if email looks like news-letter, it's vector will contain
            values, which are mostly don't equal to zeros ;
    """
    #MAX_SUBJ_LEN = 2
    #MIN_SUBJ_LEN = 7

    def run(self, score):

        vector_dict = OrderedDict()

        # 1. "Received:" Headers
        logger.debug('>>> 1. RCVD_CHECKS:')

        # get crc32 of only unique headers and their values
        excluded_heads = [
                            'Received', 'Subject', 'From', 'Date', 'Received-SPF', 'To', 'Content-Type',\
                            'Authentication-Results', 'MIME-Version', 'DKIM-Signature', 'Message-ID', 'Reply-To'
                         ]

        vector_dict['all_heads_crc'] = self.get_all_heads_crc(excluded_heads)
        logger.debug('\t----->'+str(vector_dict))

        # keep the count of traces fields
        vector_dict ["traces_num"] = self._msg.keys().count('Received')
        logger.debug('\t----->'+str(vector_dict))

        # get crc32 from first N trace fields
        rcvd_vect = tuple([r.partition('by')[0] for r in self.get_rcvds()])
        logger.debug(rcvd_vect)
        vector_dict.update(self.get_trace_crc())
        logger.debug('\t----->'+str(vector_dict))

        # 2. "To:", "SMTP RCPT TO:" Headers
        logger.debug('>>> 2. DESTINATOR CHECKS:')

        vector_dict['rcpt_smtp_to'], vector_dict['rcpt_body_to'] = self.get_rcpts_metrics(score)


        logger.debug('>>> 3. SPF/DKIM_CHECKS:')
        logger.debug('>>>'+str(self.get_dmarc_metrics(score)))
        dmarc_score, dmarc_dict, dkim_domain = self.get_dmarc_metrics(score)
        logger.debug(str(dmarc_dict))
        vector_dict['dmarc_score'] = dmarc_score
        vector_dict.update(dmarc_dict)
        vector_dict['dmarc_x_heads'] = len(filter(lambda h: re.match('X-DMARC(-.*)?', h, re.I), self._msg.keys()))


        # 4. Presense of X-EMID && X-EMMAIL, etc
        logger.debug('>>> 4. Specific E-marketing headers checks:')

        head_pattern = r'^X-(EM(ID|MAIL|V-.*)|SG-.*|(rp)?campaign(id)?)$'
        known_mailers = [ r'MailChimp', r'PHPMailer', r'GetResponse\s+360', 'GreenArrow', 'habrahabr', 'nlserver' ]

        vector_dict.update(self.get_emarket_metrics(head_pattern, known_mailers, score))

        # 4. Subject checks
        logger.debug('>>> 4. SUBJ CHECKS:')

        features = ('len', 'style', 'score', 'checksum', 'encoding')
        features_dict = dict(zip(['subj_'+f for f in features], [self.INIT_SCORE]*len(features)))

        if self._msg.get('Subject'):

            total_score = self.INIT_SCORE
            unicode_subj, norm_words_list, encodings = self.get_decoded_subj()

            subject_rules = [
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

            subj_score, upper_flag, title_flag = self.get_subject_metrics(subject_rules, score)
            # almoust all words in subj string are Titled
            if (len(norm_words_list) - title_flag ) < 3:
                features_dict['subj_style'] = 1

            # all advertising emails are made up with very similar html-patterns and rules for headers
            # http://emailmarketing.comm100.com/email-marketing-tutorial/
            features_dict['subj_len'] = len(norm_words_list)
            features_dict['subj_score'] = total_score + subj_score

            # in general infos have subj lines in utf-8 or pure ascii
            if len(set(encodings)) == 1 and set(encodings).issubset(['utf-8','ascii']):
                features_dict['encoding'] = 1

            # take crc32 from the second half (first can vary cause of personalisation, etc)
            subj_trace = tuple([w.encode('utf-8') for w in norm_words_list[len(norm_words_list)/2:]])
            subj_trace = ''.join(subj_trace[:])
            logger.debug(subj_trace)
            features_dict['subj_checksum'] = binascii.crc32(subj_trace)

        vector_dict.update(features_dict)
        logger.debug('\t----->'+str(vector_dict))

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


        # 7. Check MIME headers
        logger.debug('>>> 7. MIME CHECKS:')

        mime_features = ('mime_score', 'checksum', 'att_count', 'att_score', 'in_score', 'nest_level')
        mime_dict = OrderedDict(zip(mime_features, [self.INIT_SCORE]*len(mime_features)))

        logger.debug('IS MULTI >>>>>> '+str(self._msg.is_multipart()))
        if self._msg.is_multipart():
            mime_dict['mime_score'] += score

            first_content_type = self._msg.get('Content-Type')
            if 'text/html' in first_content_type and re.search('utf-8', first_content_type, re.I):
                mime_dict['mime_score'] += score

            mime_skeleton = self.get_mime_struct()
            logger.debug('MIME STRUCT: '+str(mime_skeleton))

            # some particular rules for infos
            if (mime_skeleton.keys()).count('text/html') and 'inline' in mime_skeleton.get('text/html'):
                mime_dict['mime_score'] += score

            mime_dict['checksum'] = self.get_mime_crc(mime_skeleton)
            logger.debug('\t----->'+str(vector_dict))

            # todo: why only one here ?
            attach_regs = [ r'format\s?=\s?.fixed.']

            count, att_score, in_score = self.get_attach_metrics(mime_skeleton.values(), attach_regs, score)
            mime_dict['att_count'] = count
            mime_dict['att_score'] = att_score
            mime_dict['in_score'] = in_score

            # helps to outline difference between spams, which were made very similar to infos
            mime_dict['nest_level'] = self.get_nest_level()

        vector_dict.update(mime_dict)
        logger.debug('\t----->'+str(vector_dict))

        # 8. check urls
        logger.debug('>>> 8. URL_CHECKS:')

        urls_list = self.get_url_list()

        if urls_list:
            logger.debug('URLS_LIST >>>>>'+str(urls_list))

            regs_for_dom_pt = [
                                ur'(news(letter)?|trip|sales+|offer|journal|event|post|asseccories|rasprodaga)',
                                ur'(global|response|click|shop|sale|flight|hotel|cit(y|ies)|campaign|bouquet)',
                                ur'(celebration|friday|binus|magazin|cheap|subscibe|manage|feed|list|blog)',
                                ur'(programm|online|create|amazon|meetup|book|flowers|app|connect|emea|habrahabr|media)',
                                ur'(citilink|ulmart|lamoda|nero-|vip|ideel|quora|yves-rocher|fagms.de|wix.com|papers)',
                                ur'(opportunity|whites+|chance|email|practice|yr-ru|us\d-|stanford|brands+|labels+)',
                                ur'(look-at-media|digest|the-village|ozon.ru|enter.ru)'
            ]

            regs_for_txt_pt = [
                                ur'(cheap.*|prices+|clothes+|action|shoes+|women|label|brand|zhensk|odezhd)',
                                ur'(campaign|rasprodaga|requirements|choice|personal|track|click|customer|product)',
                                ur'(meetup|facebook|twitter|pinterest|vk|odnoklassinki|google)_footer',
                                ur'(training|mailing|modify|unsub|newsletter|catalog|mdeia|graphics|announcement)',
                                ur'(utm_medium=|utm_source=|utm_term=|utm_campaign=|applications+|upn=|aspx\?)',
                                ur'(shop|magazin|collections+|lam|(mail_link_)?track(er)?|EMID=|EMV=|genders)'
            ]

            basic_features_dict, netloc_list = self.get_url_metrics(regs_for_dom_pt, regs_for_txt_pt, score)

            urls_features = ('query_sim', 'path_sim', 'avg_query_len', 'avg_path_len', 'ascii')
            # initialize OrderedDict exactly by this way cause of
            # http://stackoverflow.com/questions/16553506/python-ordereddict-iteration
            # and vector of metrics is wanted, so order is important
            print('NETLOC_LIST >>>'+str(netloc_list))
            print('DICT >>>'+str(basic_features_dict))

            urls_dict = OrderedDict(zip(urls_features, [self.INIT_SCORE]*len(urls_features)))

            url_lines = [ ''.join(u._asdict().values()) for u in urls_list ]
            if list( x for x in  [line for line in url_lines] if x in string.printable ):
                urls_dict['ascii'] = score

            for attr in ['path','query']:
                obj_list = [ url.__getattribute__(attr) for url in urls_list ]

                lengthes_list = [len(line) for line in obj_list]
                urls_dict['avg_'+attr+'_len'] = sum(lengthes_list)/len(obj_list)

                if math.ceil(float(len(set(obj_list)))/float(len(urls_list))) < 1.0:
                    urls_dict[attr+'_sim'] = score

        else:
            basics = ('url_count', 'url_score', 'distinct_count', 'sender_count')
            basic_features_dict = dict(zip(basics, [self.INIT_SCORE]*len(basics)))

        vector_dict.update(basic_features_dict)
        vector_dict.update(urls_dict)

        # 9. check body
        logger.debug('>>> 9. BODY\'S TEXT PARTS CHECKS:')

        regexp_list = [
                        ur'(styl(ish)?|perfect|beauti|winter|summer|fall|spring|look|blog|spot)',
                        ur'(news|letter|discount|sale|info|unsubscribe|bonus|ads|market)',
                        ur'((social)?media|partage|share|actu|publicité|télécharger|download)',
                        ur'(RECOMMENDA[TIONS]*)'
        ]

        tags_map = {
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


        # move to BasePattern
        vector_dict.update(dict(zip(('html_score', 'html_checksum'), self.get_html_parts_metrics(score, tags_map))))
        vector_dict['text_score'] = self.get_text_parts_metrics(score, regexp_list)
        vector_dict['avg_entropy'] = self.get_text_parts_avg_entropy()
        vector_dict['compression_ratio'] = self.get_text_compress_ratio()

        logger.debug('MSG VECTOR --> '+str(vector_dict))

        return vector_dict

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



		


	
			



