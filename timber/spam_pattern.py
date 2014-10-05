#! /usr/bin/env python

import os, sys, logging, re, common, binascii
from operator import add

# formatter_debug = logging.Formatter('%(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class SpamPattern():

    def __init__(self, msg):
        self.msg = msg

    # ?
    def __str__(self):
        return("Keeps and applies vectorising rules for spams.")

    def run(self, score):

        vector_dict = {}

        # 1. Received headers

        # get crc32 of only unique headers and their values
        excluded_heads = ['Received', 'Subject', 'From', 'Date', 'MIME-Version', 'To', 'Message-ID', 'Cc','Bcc']
        vector_dict.update(common.get_heads_crc(self.msg.items(), excluded_heads))
        logger.debug('\t----->'+str(vector_dict))

        # keep the count of traces fields
        vector_dict ["traces_num"] = self.msg.keys().count('Received')
        logger.debug('\t----->'+str(vector_dict))

        # basic parsing and dummy checks with regexps (takes only first n_rcvds headers)
        n_rcvds = 2
        rcvd_values = tuple(self.msg.get_all('Received'))[-1*n_rcvds:]
        #print('rcvd_values: '+str(rcvd_values))
        parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in rcvd_values[:]])
        #logger.debug('parsed_rcvds -->'+str(parsed_rcvds))

        vector_dict ["trace_rule"] = 0
        logger.debug('\t----->'+str(vector_dict))
        rcvd_rules = [
                        r'(public|airnet|wi-?fi|a?dsl|dynamic|pppoe|static|account)+',
                        r'(\(|\s+)(([a-z]+?)-){0,2}(\d{1,3}-){1,3}\d{1,3}([\.a-z]{1,63})+\.(ru|in|id|ua|ch)'
        ]

        for rule in rcvd_rules:
            if filter(lambda l: re.search(rule, l), parsed_rcvds):
                vector_dict ["trace_rule"] = 1


        # deep parsing and checks for some wellknown spammers tricks with To: header
        vector_dict ['smtp_to'] = 0
        vector_dict ['to'] = 0
        logger.debug('\t----->'+str(vector_dict))

        to_values, to_addrs = common.get_addr_fields(self.msg.get('To'))
        if to_values and filter(lambda x: re.search(r'undisclosed-recipients',x,re.I), to_values):
            vector_dict['to'] += score
            logger.debug('\t----->'+str(vector_dict))

        if not to_addrs:
            vector_dict['to'] += score
            logger.debug('\t----->'+str(vector_dict))

        smtp_to_list = filter(lambda x: x, tuple([(r.partition('for')[2]).strip() for r in parsed_rcvds]))

        if smtp_to_list:
            trace_str_with_to = smtp_to_list[0]
            smtp_to = re.search(r'<(.*@.*)?>', trace_str_with_to)
            if smtp_to:
                smtp_to = smtp_to.group(0)
                #logger.debug(smtp_to)

                if len(to_addrs) == 1 and smtp_to != to_addrs[0]:
                    vector_dict['to'] += score
                    logger.debug('\t----->'+str(vector_dict))

                elif len(to_addrs) > 2 and smtp_to != '<multiple recipients>':
                    vector_dict['to'] += score
                    logger.debug('\t----->'+str(vector_dict))

        else:
            vector_dict ['smtp_to'] += 1
            logger.debug('\t----->'+str(vector_dict))

        # get crc32 from first N trace fields
        rcvd_vect = tuple([rcvd.partition('by')[0] for r in parsed_rcvds])
        logger.debug(rcvd_vect)
        vector_dict.update(common.get_trace_crc(rcvd_vect))
        logger.debug('\t----->'+str(vector_dict))

        # 2. Subject checks

        if self.msg.get('Subject'):

            subject_rule = [
                                r'(SN|viagra|ciali(s|\$)|pfizer|discount|pill|med|free|click|Best\s+Deal\s+Ever|,|!|\?!|\>\>\:|sale)+',
                                r'[\d]{1,2}\s+[\d]{1,2}[0]{1,3}\s+.*',
                                r'-?[\d]{1,2}\s+%\s+.*',
                                r'[\d](-|\s+)?\S{1,4}(-|\s+)?[\d]\s+.*',
                                r'[\*-=\+~]{1,}\S+[\*-=\+~]{1,}'
                            ]
            len_threshold = 70

            heads_dict = {key: value for (key, value) in self.msg.items()}
            subj_score, subj_trace = common.basic_subjects_checker(heads_dict, subject_rule, len_threshold, score)

            vector_dict ['subj_score'] = subj_score
            vector_dict ['subj_trace'] = subj_trace

        else:

            vector_dict ['subj_score'] = 1
            vector_dict ['subj_trace'] = 0

        logger.debug('\t----->'+str(vector_dict))
        # 3. List checks and some other RFC 5322 compliences checks for headers

        temp_dict = dict([('list',score), ('sender',0), ('preamble',0), ('disp-notification',0)])
        logger.debug('\t----->'+str(temp_dict))

        if filter(lambda list_field: re.search('(List|Errors)(-.*)?', list_field), self.msg.keys()):
            # well, this unique spam author respects RFC 2369, his creation deservs more attentive check
            temp_dict['list'] = common.basic_lists_checker(self.msg.items(), score)
            logger.debug('\t----->'+str(temp_dict))

        elif (self.msg.keys().count('Sender') and self.msg.keys().count('From')):
            # if we don't have List header From = Sender (RFC 5322),
            # MUA didn't generate Sender field cause of redundancy
            temp_dict ['sender'] = 1
            logger.debug('\t----->'+str(temp_dict))

        if self.msg.preamble and not re.search('This\s+is\s+a\s+(crypto.*|multi-part).*\sMIME\s.*', self.msg.preamble,re.I):

            temp_dict ['preamble'] = 1
            logger.debug('\t----->'+str(temp_dict))

        vector_dict.update(temp_dict)
        logger.debug('\t----->'+str(vector_dict))

        if (self.msg.keys()).count('Disposition-Notification-To'):
            vector_dict ['disp-notification'] = 1
            logger.debug('\t----->'+str(vector_dict))

        # 4. crc for From values
        vector_dict['from']=0
        logger.debug('\t----->'+str(vector_dict))

        if self.msg.get('From'):
            from_values = common.get_addr_fields(self.msg.get('From'))[0]

            if from_values:
                vector_dict['from'] = binascii.crc32(reduce(add,from_values[:1]))
                logger.debug('\t----->'+str(vector_dict))

        # 5. Check MIME headers

        mime_heads = common.get_mime_info(msg)

        vector_dict['struct_crc']=common.get_mime_structure_crc(mime_heads)
        vector_dict['attach']=common.basic_attach_checker(mime_heads)







        # analyse attachements extensions

        #vect_dict.update(common.get_body_skeleton(self.msg))

        return (vector_dict)


if __name__ == "__main__":

    formatter = logging.Formatter('%(filename)s: %(message)s')
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    try:
        pattern = SpamPattern(msg)
        vector = test.run(score)
        logger.debug(vector)


    except Exception, details:
        raise



		


	
			



