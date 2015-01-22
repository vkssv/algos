#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""Keeps and applies vectorising rules for infos.
If doc(email) is very similar to this pattern
its vector will be filled by "1" or score value > 0
or crc32 value for each feature, otherwise - "0" """

import os, sys, logging, common, re, binascii, math, string
from operator import add
from pattern_wrapper import BasePattern
from collections import OrderedDict, Counter


INIT_SCORE = BasePattern.INIT_SCORE
MIN_TOKEN_LEN = BasePattern.MIN_TOKEN_LEN

# formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class InfoPattern(BasePattern):
    MAX_SUBJ_LEN = 2
    MIN_SUBJ_LEN = 7

    def run(self, score):

        vector_dict = OrderedDict()

        # 1. "Received:" Headers
        logger.debug('>>> 1. RCVD_CHECKS:')

        # get crc32 of only unique headers and their values
        excluded_heads = [
                            'Received', 'Subject', 'From', 'Date', 'Received-SPF', 'To', 'Content-Type',\
                            'Authentication-Results', 'MIME-Version', 'DKIM-Signature', 'Message-ID', 'Reply-To'
                          ]
        vector_dict.update(common.get_all_heads_crc(self.msg.items(), excluded_heads))
        logger.debug('\t----->'+str(vector_dict))

        # keep the count of traces fields
        vector_dict ["traces_num"] = self.msg.keys().count('Received')
        logger.debug('\t----->'+str(vector_dict))

        # get crc32 from first N trace fields
        rcvd_vect = tuple([r.partition('by')[0] for r in BasePattern.get_rcvds(self)])
        logger.debug(rcvd_vect)
        vector_dict.update(common.get_trace_crc(rcvd_vect))
        logger.debug('\t----->'+str(vector_dict))


        # 2. "To:", "SMTP RCPT TO:" Headers
        logger.debug('>>> 2. DESTINATOR CHECKS:')

        # check that rcpt from trace field and To the same and the one (in general)
        vector_dict['to'] = common.basic_rcpts_checker(score, self.msg.get_all('Received'), self.msg.get_all('To'))


        logger.debug('>>> 3. SPF/DKIM_CHECKS:')
        logger.debug('>>>'+str(common.basic_dmarc_checker(self.msg.items(), score)))
        dmarc_dict_checks, dkim_domain = common.basic_dmarc_checker(self.msg.items(), score)
        logger.debug(str(dmarc_dict_checks))
        vector_dict.update(dmarc_dict_checks)
        vector_dict['dmarc'] = len(filter(lambda h: re.match('X-DMARC(-.*)?', h, re.I),self.msg.keys()))


        # 4. Presense of X-EMID && X-EMMAIL, etc
        logger.debug('>>> 4. Specific E-marketing headers checks:')

        heads_pattern = r'^X-(EM(ID|MAIL|V-.*)|SG-.*|(rp)?campaign(id)?)$'
        known_senders = [r'MailChimp', r'PHPMailer', r'GetResponse\s+360', 'GreenArrow', 'habrahabr', 'nlserver']

        heads_score, known_mailer_flag = common.basic_headers_cheker(heads_pattern, known_senders, self.msg.items(), score)

        vector_dict['emarket_heads_score'] = heads_score
        vector_dict['known_sender'] = known_mailer_flag

        # 4. Subject checks
        logger.debug('>>> 4. SUBJ CHECKS:')

        features = ['len','style','score','checksum','encoding']
        features_dict = dict(map(lambda x,y: ('subj_'+x,y), features, [INIT_SCORE]*len(features)))

        if self.msg.get('Subject'):

            total_score = INIT_SCORE
            unicode_subj, norm_words_list, encodings = common.get_subject(self.msg.get("Subject"))

            subject_regs = [
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


            subj_score, upper_flag, title_flag = common.basic_subjects_checker(unicode_subj, subject_regs, score)
            # almoust all words in subj string are Titled
            if (len(norm_words_list) - title_flag ) < 3:
                features_dict['subj_style'] = 1

            # un mine d'or for infos  http://emailmarketing.comm100.com/email-marketing-tutorial/
            if self.MIN_SUBJ_LEN < len(norm_words_list) < self.MAX_SUBJ_LEN:
                features_dict['subj_len'] = 1

            features_dict['subj_score'] = total_score + subj_score

            # infos generally have subj lines in utf-8 or pure ascii
            if len(set(encodings)) == 1 and set(encodings).issubset(['utf-8','ascii']):
                features_dict['encoding'] = 1

            # take crc32 from the second half (first can vary cause of personalisation, etc.)
            subj_trace = tuple([w.encode('utf-8') for w in norm_words_list[len(norm_words_list)/2:]])
            subj_trace = ''.join(subj_trace[:])
            logger.debug(subj_trace)
            features_dict['subj_checksum'] = binascii.crc32(subj_trace)

        vector_dict.update(features_dict)
        logger.debug('\t----->'+str(vector_dict))

        # 5. List checks and some other RFC 5322 compliences checks for headers
        logger.debug('>>> 5. LIST CHECKS:')
        list_features = ['basic_checks', 'ext_checks','sender','precedence','typical_heads','reply-to','delivered']
        list_features_dict = dict(map(lambda x,y: ('list_'+x,y), list_features, [INIT_SCORE]*len(list_features)))

        logger.debug('\t----->'+str(list_features_dict))

        if filter(lambda list_field: re.match('(List|Errors)(-.*)?', list_field,re.I), self.msg.keys()):
            # well, this unique spam author respects RFC 2369, his creation deservs more attentive check
            list_features_dict['basic_checks'] = common.basic_lists_checker(self.msg.items(), rcvd_vect, score)
            logger.debug('\t----->'+str(list_features_dict))

        # for old-school style emailings
        matched = filter(lambda h_name: re.match('List-(Id|Help|Post|Archive)', h_name, re.I), self.msg.keys())
        list_features_dict['ext_checks'] = len(matched)

        keys = tuple(filter(lambda k: self.msg.get(k), ['From','Sender','Reply-To','Delivered-To','To']))
        #addr_dict = dict([(k,common.get_addr_values(value)[1][0]) for k,value in zip(keys, tuple([self.msg.get(k) for k in keys]))])
        logger.debug(str([ common.get_addr_values(self.msg.get(k)) for k in keys]))
        addr_dict = dict([(k, (common.get_addr_values(self.msg.get(k))[1])[0]) for k in keys])
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

        if self.msg.get('Precedence') and self.msg.get('Precedence').strip() == 'bulk':
            list_features_dict['precedence'] = 1

        for name_reg in [r'Feedback(-ID)?', r'.*Campaign(-ID)?','Complaints(-To)?']:
            matched_list = filter(lambda head_name: re.match(r'(X-)?'+name_reg,head_name,re.I),self.msg.keys())
            list_features_dict['typical_heads'] = len(matched_list)

        vector_dict.update(list_features_dict)
        logger.debug('\t----->'+str(vector_dict))

        # 4. crc for From values
        logger.debug('>>> 6. ORIGINATOR_CHECKS:')
        vector_dict['from'] = INIT_SCORE
        logger.debug('\t----->'+str(vector_dict))

        if self.msg.get('From'):
            from_values = common.get_addr_values(self.msg.get('From'))[0]
            logger.debug(str(from_values))
            logger.debug(str(type(from_values)))

            if from_values:
                vector_dict['from'] = binascii.crc32((reduce(add,from_values)).strip())
                logger.debug('\t----->'+str(vector_dict))


        logger.debug('\t----->'+str(vector_dict)+'\n')


        # 7. Check MIME headers
        logger.debug('>>> 7. MIME CHECKS:')

        mime_features = [ 'mime_score', 'checksum', 'att_count', 'att_score', 'in_score', 'nest_level']
        mime_dict = OrderedDict(map(lambda x,y: (x,y), mime_features, [INIT_SCORE]*len(mime_features)))

        logger.debug('IS MULTI >>>>>> '+str(self.msg.is_multipart()))
        if self.msg.is_multipart():
            mime_dict['mime_score'] = score

            mime_skeleton = BasePattern.get_mime_struct(self)

            logger.debug('MIME STRUCT: '+str(mime_skeleton))

            # some particular rules for infos
            if (mime_skeleton.keys()).count('text/html') and 'inline' in mime_skeleton.get('text/html'):
                mime_dict['mime_score'] += score

            mime_dict['checksum'] = common.get_mime_crc(mime_skeleton)

            logger.debug('\t----->'+str(vector_dict))

            attach_regs = [
                                r'format\s?=\s?.fixed.'
            ]

            count, att_score, in_score = common.basic_attach_checker(mime_skeleton.values(), attach_regs, score)
            mime_dict['att_count'] = count
            mime_dict['att_score'] = att_score
            mime_dict['in_score'] = in_score

            # helps to outline difference between spams, which were made very similar to infos
            if BasePattern.get_nest_level(self) <= NEST_LEVEL_THRESHOLD:
                mime_dict['nest_level'] = score

        vector_dict.update(mime_dict)
        logger.debug('\t----->'+str(vector_dict))

        # 8. check urls
        logger.debug('>>> 8. URL_CHECKS:')

        urls_list = BasePattern.get_url_list(self)

        if urls_list:
            logger.debug('URLS_LIST >>>>>'+str(urls_list))

            domain_regs = [
                                ur'(news(letter)?|trip|sales+|offer|journal|event|post|asseccories|rasprodaga)',
                                ur'(global|response|click|shop|sale|flight|hotel|cit(y|ies)|campaign|bouquet)',
                                ur'(celebration|friday|binus|magazin|cheap|subscibe|manage|feed|list|blog)',
                                ur'(programm|online|create|amazon|meetup|book|flowers|app|connect|emea|habrahabr|media)',
                                ur'(citilink|ulmart|lamoda|nero-|vip|ideel|quora|yves-rocher|fagms.de|wix.com|papers)',
                                ur'(opportunity|whites+|chance|email|practice|yr-ru|us\d-|stanford|brands+|labels+)',
                                ur'(look-at-media|digest|the-village|ozon.ru|enter.ru)'
            ]

            regs = [
                                ur'(cheap.*|prices+|clothes+|action|shoes+|women|label|brand|zhensk|odezhd)',
                                ur'(campaign|rasprodaga|requirements|choice|personal|track|click|customer|product)',
                                ur'(meetup|facebook|twitter|pinterest|vk|odnoklassinki|google)_footer',
                                ur'(training|mailing|modify|unsub|newsletter|catalog|mdeia|graphics|announcement)',
                                ur'(utm_medium=|utm_source=|utm_term=|utm_campaign=|applications+|upn=|aspx\?)',
                                ur'(shop|magazin|collections+|lam|(mail_link_)?track(er)?|EMID=|EMV=|genders)'
                    ]

            basic_features_dict, netloc_list = common.basic_url_checker(urls_list, rcvd_vect, score, domain_regs, regs)

            urls_features = ['query_sim', 'path_sim', 'avg_query_len', 'avg_path_len', 'ascii']
            # initialize OrderedDict exactly by this way cause of
            # http://stackoverflow.com/questions/16553506/python-ordereddict-iteration
            # and vector of metrics is wanted, so order is important
            urls_dict = OrderedDict(map(lambda x,y: (x,y), urls_features, [INIT_SCORE]*len(urls_features)))

            print('NETLOC_LIST >>>'+str(netloc_list))
            print('DICT >>>'+str(basic_features_dict))

            url_lines = [ ''.join(u._asdict().values()) for u in urls_list ]
            if filter(lambda x: x in string.printable, [line for line in url_lines]):
                urls_dict['ascii'] = score

            for attr in ['path','query']:
                obj_list = [url.__getattribute__(attr) for url in urls_list]

                lengthes_list = [len(line) for line in obj_list]
                urls_dict['avg_'+attr+'_len'] = sum(lengthes_list)/len(obj_list)

                if math.ceil(float(len(set(obj_list)))/float(len(urls_list))) < 1.0:
                    urls_dict[attr+'_sim'] = score

        else:
            basics = ['url_count', 'url_score', 'distinct_count', 'sender_count']
            basic_features_dict = dict(map(lambda x,y: (x,y), basics, [INIT_SCORE]*len(basics)))

        vector_dict.update(basic_features_dict)
        vector_dict.update(urls_dict)

        # 9. check body
        logger.debug('>>> 9. BODY\'S TEXT PARTS CHECKS:')

        body_features = [ 'regexp_score', 'html_score', 'body_checksum' ]
        body_dict = Counter(dict(map(lambda x,y: (x,y), body_features, [INIT_SCORE]*len(body_features))))

        text_parts = self.get_text_parts()
        logger.debug('TEXT_PARTS: '+str(text_parts))

        html_text = ''
        for line, content_type in text_parts:
            # parse by lines
            if 'html' in content_type:
                soup = BeautifulSoup(line)

                if soup.table:
                    if len(filter(lambda i: i.name == 'table', [i for i in soup.table.descendants])) > self.NEST_TAB_THRESHOLD:
                        body_dict['html_score'] += score

                    tab_mandatory_attr = {
                                            r'width$'                  : r'100%$',
                                            r'id$'                     : r'^.*Table$',
                                            r'(bg|background-)color$'  : '#[0-9A-F]{6}'
                    }

                    img_mandatory_attr = {
                                            'alt':  r'.*',
                                            'style': r'.*vertical-align\:(middle|bottom|top);.*border\:\d;.*text-decoration\:.*;.*',
                                            'width': r'\d{2,3}',
                                            'height': r'\d{2,3}',
                                            'title' : r'.*'
                    }

                    table_attr = list()
                    for k in patterns_attr.iterkeys():
                        attr = filter(lambda attr: re.match(k,attr,re.I), soup.table.attrs.keys())
                        if attr and re.match(patterns_attr.get(k), soup.table.attr, re.I):
                            body_dict['html_score'] += score

                    if soup.img:
                        all_img_attrs = [i.attrs for i in soup.find_all('img')]
                        for k in img_mandatory_attr.iterkeys():
                            for d in all_img_attrs:
                                attr = filter(lambda attr: re.match(k,attr,re.I), [d.keys() for d in all_img_attrs])
                            if attr and re.match(patterns_attr.get(k), soup.table.attr, re.I):
                            body_dict['html_score'] += score

                    








                html_content = common.get_content(soup)
                if html_content:
                    body_dict['regexp_score'] += common.basic_text_checker(html_content)

            else:
                body_dict['regexp_score'] += common.basic_text_checker(line)


        vector_dict.update(body_dict)

        return (vector_dict)

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

			


		


	
			



