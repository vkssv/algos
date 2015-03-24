#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""Keeps and applies vectorising rules for hams. """

import os, sys, logging, math
from collections import OrderedDict, Counter

from pattern_wrapper import BasePattern

#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class HamPattern(BasePattern):
    """
    Pattern class for build vectors, based on features
    suitable for transactional emails : msgs from banks,
    e-shops, bills, etc:
    -- if email looks like ham, it's vector will contain
        values, mostly don't equal to zeros ;
    """

    RCVDS_NUM = 3

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
                             ur'(Re\s*:|Fw(d)?\s*:|fly|ticket|account|payment|verify\s+your\s+(email|account)|bill)',
                             ur'(support|help|participate|registration|electronic|answer|from|update|undelivered)',
                             ur'от\s+[\w\.-]{3,10}\s+(счет|отчет|выписка|электронный\s+(билет)?)'

    ]
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

                                'img' :{
                                            'src'             : '(cid:(_.*|part.*|profile|photo|logo|google|ima?ge?\d{1,3}.*@[\w.])|assets|track(ing)?|api|ticket|logo|fb|vk|tw)',
                                            'moz-do-not-send' : 'true'
                                },
                                'li'  :{
                                            'dir'             : 'ltr',
                                            'class'           : '\[\'.*\'\]'
                                }
                    }


    URL_FQDN_REGEXP = [
                            ur'(www\.)?(registration|account|payment|confirmation|password|intranet|emarket)',
                            ur'(www\.)?(tickets+|anywayanyday|profile|job|my\.|email|blog|support)',
                            ur'(www\.)?(meetup\.com|odnoklassniki\.ru|vk\.com|my\.mail\.ru|facebook\.com)',
                            ur'(www\.)?(linkedin\.com|facebook\.com|linternaute\.com|blablacar\.com)',
                            ur'(www\.)?(youtube\.com|plus\.google\.com|twitter\.com|pinterest\.com|tumblr\.com)',
                            ur'(www\.)?(instagram\.com|flickr\.com|vine\.com|tagged\.com|ask\.fm|meetme\.com)',
                            ur'(www\.)?classmates'

    ]

    URL_TXT_REGEXP = [
                            ur'(users?\/|id|sign[_\s]{0,1}(in|up)|e?ticket|kassa|account|payment|confirm(ation)?|password)',
                            ur'(support|settings|orders?|product|disclosures?|privacy|\?user_id|validate_e?mail\?)'
    ]

    def run(self, score):

        # 1. "Subject:" Header
        logger.debug('>>> 1. SUBJECT CHECKS:')

        features = ('len','style','score')
        features_dict = OrderedDict(map(lambda x,y: ('subj_'+x,y), features, [self.INIT_SCORE]*len(features)))

        if self._msg.get('Subject'):

            total_score = self.INIT_SCORE
            unicode_subj, tokens, encodings = self.get_decoded_subj(self._msg.get("Subject"))

            features_dict['subj_len'] = len(unicode_subj)
            #if self.MIN_SUBJ_LEN < len(unicode_subj) < self.MAX_SUBJ_LEN:
            #    features_dict['subj_len'] = 1

            subject_rule = [

            ]

            subj_score, upper_words_num, title_words_num = self.get_subjects_metrics(unicode_subj, subject_rule, self.score)

            #features_dict['subj_style'] = title_words_num

            features_dict['subj_score'] += subj_score

        vector_dict.update(features_dict)
        logger.debug('\t----->'+str(vector_dict))

        # 2. check urls
        logger.debug('>>> 2. URL_CHECKS:')

        urls_list = self.get_url_list()
        urls_features = ('avg_length', 'query_absence', 'url_score')
        urls_dict = OrderedDict(map(lambda x,y: (x,y), urls_features, [self.INIT_SCORE]*len(urls_features)))

        if urls_list:
            logger.debug('URLS_LIST >>>>>'+str(urls_list))

            domain_regs = [


            regs = [

            ]

            rcvds = self.get_rcvds(self.__RCVDS_NUM)
            rcvd_vect = tuple([r.partition('by')[0] for r in rcvds])

            d, netloc_list = self.get_url_metrics(urls_list, rcvd_vect, score, domain_regs, regs)
            urls_dict['url_score'] = d.get('url_score')

            queries_count = float(len(filter(lambda line: line, [ u.query for u in urls_list ])))
            if math.floor(queries_count/float(len(urls_list))) == 0.0:
                urls_dict['query_absence'] = score

            length_list = [ len(url) for url in [ obj.geturl() for obj in urls_list ]]
            urls_dict['avg_length'] = math.ceil(float(sum(length_list))/float(len(urls_list)))

        vector_dict.update(urls_dict)

        logger.debug('>>> 3. BODY\'S TEXT PARTS CHECKS:')



        regexp_list= [
                        ur'(track(ing)?\s+No|proc(é|e)+d(er)?|interview|invit[eation]|welcom(ing)?|introduc(tion)?|your\s.*(ticket|order)\s.*(\#|№)|day|quarter|inquir[yies])',
                        ur'(feature|questions?|support|request|contrac?ts?|drafts?|teams?|priorit[yies]|details?|attach(ed)?|communic.*|train(ing)?)',
                        ur'(propos[eal]|found\s+this|concern(ing|ant)?|remind[ers]|contrac?t|act|s(e|é)curit[yieés]|during\s+.*(the)?\s+period)',
                        ur'(reports?|logs?|journals?|(re)?scheduled?|(specif[yied]|conference|call)\s+.*time|transfer|cancel(ed)?|payment|work|labour|mis\s+(à|a)\s+jour)',
                        ur'(profile\s+activation|invit(aion)?|registration|forgot.*password|pre-.*|post-.*|document(ation)?|compte)',
                        ur'((d\')?expiration|exchange|service|requisition|albeit|compl(é|e)mentaire(es)?|addition(al)?|terms?\s+and\s+conditions?)',
                        ur'(en\s+invitant|ci-(jointe|dessous)|trans(mette|mis)|souscription|sp(é|e)siale?|procéd[eré]|(e|é)change|us(age|ing|er))',
                        ur'(valider\s+les?|donnéés|дата|недел|тариф|уведомлен|связ|по\s+причин|магазин|поступил|отмен).*',
                        ur'(заказ|сч(е|ё)т|предложен|контракт|отмена?|платеж|чек|данн|подтвер(ждение|ит[еть])|билет|номер|трэк|(тех)?поддерж).*',
                        ur'(аккаунт|парол|доступ|истек[лоает]|договор|справка|интервью|встреча?|приглашен|собеседован|офис|врем|график|адрес).*',
                        ur'(баланс|детали|выписк|прикреплен|(набор\s)?.*услуг).*'
        ]

        vector_dict.update(dict(zip(('html_score','html_checksum'), self.get_html_parts_metrics(score, tags_map))))
        vector_dict['text_score'] = self.get_text_parts_metrics(score, regexp_list)

        return vector_dict


if __name__ == "__main__":

	formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
	ch = logging.StreamHandler(sys.stdout)
	ch.setLevel(logging.DEBUG)
	ch.setFormatter(formatter)
	logger.addHandler(ch)

	try:
		test=HamPattern(env)
		vector = test.run()
		logger.debug(vector)


	except Exception as details:
		raise

			


		


	
			



