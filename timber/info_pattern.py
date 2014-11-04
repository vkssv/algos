#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""Keeps and applies vectorising rules for infos.
If doc(email) is very similar to this pattern
its vector will be filled by "1" or score value > 0
or crc32 value for each feature, otherwise - "0" """

import os, sys, logging, common, re, binascii
from operator import add
from pattern_wrapper import BasePattern
INIT_SCORE = BasePattern.INIT_SCORE
MIN_TOKEN_LEN = BasePattern.MIN_TOKEN_LEN


# formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class InfoPattern(BasePattern):

    def run(self, score):

        vector_dict = {}

        # 1. Received headers

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

        # basic parsing and dummy checks with regexps (takes only first n_rcvds headers)
        n_rcvds = 0
        rcvd_values = tuple(self.msg.get_all('Received'))[-1*n_rcvds:]
        #print('rcvd_values: '+str(rcvd_values))
        parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in rcvd_values[:]])
        #logger.debug('parsed_rcvds -->'+str(parsed_rcvds))


        # get crc32 from first N trace fields
        rcvd_vect = tuple([rcvd.partition('by')[0] for r in parsed_rcvds])
        logger.debug(rcvd_vect)
        vector_dict.update(common.get_trace_crc(rcvd_vect))
        logger.debug('\t----->'+str(vector_dict))

        # check that rcpt from trace field and To the same and the one (in general)
        vector_dict['to'] = common.basic_rcpts_checker(score, self.msg.get_all('Received'), self.msg.get_all('To'))

        # DMARC checks
        print('>>>'+str(common.basic_dmarc_checker(self.msg.items(), score)))
        dmarc_dict_checks, dkim_domain = common.basic_dmarc_checker(self.msg.items(), score)
        print(dmarc_dict_checks)
        vector_dict.update(dmarc_dict_checks)
        vector_dict['dmarc'] = len(filter(lambda h: re.match('X-DMARC(-.*)?', h, re.I),self.msg.keys()))

        # Presense of X-EMID && X-EMMAIL
        em_names = ['X-EMID','X-EMMAIL']
        sc = 0
        pat = '^X-EM(ID|MAIL)$'

        if len(set(filter(lambda xx: re.match(pat,xx,re.I),self.msg.keys()))) == len(em_names):
            if self.msg.get('X-EMMAIL') == self.msg.get('To'):
                sc = 1

        em_dict = dict(map(lambda x,y: (x,y),em_names,[sc]*len(em_names)))
        vector_dict.update(em_dict)

        # 2. Subject checks

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
            if 2 < len(norm_words_list) < 7:
                features_dict['subj_len'] = 1

            features_dict['subj_score'] = total_score + subj_score

            # infos statistically have subj lines in utf-8 or pure ascii
            if len(set(encodings)) == 1 and set(encodings).issubset(['utf-8','ascii']):
                features_dict['encoding'] = 1

            # take crc32 from the second half (first can vary cause of personalisation, etc.)
            subj_trace = tuple([w.encode('utf-8') for w in norm_words_list[len(norm_words_list)/2:]])
            subj_trace = ''.join(subj_trace[:])
            print(subj_trace)
            features_dict['subj_checksum'] = binascii.crc32(subj_trace)

        vector_dict.update(features_dict)
        logger.debug('\t----->'+str(vector_dict))

        # 3. List checks and some other RFC 5322 compliences checks for headers

        list_features = ['basic_checks', 'ext_checks','sender','precedence','typical_heads','reply-to','delivered']
        list_features_dict = dict(map(lambda x,y: ('list_'+x,y), list_features, [INIT_SCORE]*len(list_features)))

        logger.debug('\t----->'+str(list_features_dict))

        if filter(lambda list_field: re.match('(List|Errors)(-.*)?', list_field,re.I), self.msg.keys()):
            # well, this unique spam author respects RFC 2369, his creation deservs more attentive check
            list_features_dict['basic_checks'] = common.basic_lists_checker(self.msg.items(), score)
            logger.debug('\t----->'+str(list_features_dict))

        # for old-school style emailings
        matched = filter(lambda h_name: re.match('List-(Id|Help|Post|Archive)', h_name, re.I), self.msg.keys())
        list_features_dict['ext_checks'] = len(matched)

        keys = tuple(filter(lambda k: self.msg.get(k), ['From','Sender','Reply-To','Delivered-To','To']))
        #addr_dict = dict([(k,common.get_addr_values(value)[1][0]) for k,value in zip(keys, tuple([self.msg.get(k) for k in keys]))])
        print([ common.get_addr_values(self.msg.get(k)) for k in keys])
        addr_dict = dict([(k, (common.get_addr_values(self.msg.get(k))[1])[0]) for k in keys])
        print('>>>>>'+str(addr_dict))

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
        vector_dict['from'] = INIT_SCORE
        logger.debug('\t----->'+str(vector_dict))

        if self.msg.get('From'):
            from_values = common.get_addr_values(self.msg.get('From'))[0]
            print(from_values)
            print(type(from_values))

            if from_values:
                vector_dict['from'] = binascii.crc32((reduce(add,from_values)).strip())
                logger.debug('\t----->'+str(vector_dict))


        logger.debug('\t----->'+str(vector_dict))

        '''
        # 5. Check MIME headers
        attach_score =0
        attach_regs = [
                        r'image\/(png|gif)',
                        r'.*\.(html|js|jpeg|png|gif|cgi)',
        ]

        mime_heads_vect = common.get_mime_info(msg)
        count, att_score, in_score = common.basic_attach_checker(mime_heads_vect,attach_regs,score)
        vector_dict['att_count'] = count
        vector_dict['att_score'] = att_score
        vector_dict['in_score'] = in_score
        vector_dict['nest_level'] = common.get_nest_level(mime_heads_vect)

        '''
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
        logger.debug(vector)


    except Exception as details:
        raise

			


		


	
			



