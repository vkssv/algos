#! /usr/bin/env python

import os, sys, logging, re, common

# formatter_debug = logging.Formatter('%(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class SpamPattern():

    def __init__(self, msg):
        self.msg = msg

    def __doc__(self):
        print("Keeps and applies vectorising rules for spams.")

    def run(self, score):

        vector_dict = {}

        # 1. Received headers

        # get crc32 of only unique headers vector
        heads_vect = tuple(self.msg.keys())

        excluded_heads = ['Received', 'Subject', 'From', 'Date', 'MIME-Version', 'To', 'Message-ID', 'Return-Path']
        vector_dict ['heads_crc'] = common.get_heads_crc(heads_vect, excluded_heads)

        # keep the count of traces fields
        vector_dict ["traces_num"] = self.msg.keys().count('Received')

        # basic parsing and dummy checks with regexp (takes only first n_rcvds headers)
        n_rcvds = 2
        rcvd_values = tuple(self.msg.get_all('Received'))[-1*n_rcvds:]
        parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in rcvd_values[:]])
        logger.debug('parsed_rcvds -->'+str(parsed_rcvds))

        vector_dict ["trace_rule"] = 0
        rcvd_rules = [
                        '(public|airnet|wi-?fi|a?dsl|dynamic|pppoe|static)+',
                        r'(\(|\s+)(([a-z]+?)-){0,2}(\d{1,3}-){1,3}\d{1,3}([\.a-z]{1,63})+\.(ru|in|id|ua|ch)'
        ]

        for rule in rcvd_rules:
            if filter(lambda l: re.search(rule, l), parsed_rcvds):
                vector_dict ["trace_rule"] = 1

        # deep parsing and some kind of spam-specifique checks
        vector_dict ['smtp_to'] = 0
        vector_dict ['to'] = 0

        rcvd_vect = tuple([rcvd.partition('for')[2] for r in parsed_rcvds])
        logger.debug('rcvd_vect -->'+str(rcvd_vect))

        # don't need to validate email address, just match it within the whole string
        if not filter(lambda l: re.search('<(.*@.*)?>', l, re.I), rcvd_vect):
            vector_dict ['smtp_to'] = 1

        else:

            body_to = common.get_decoded_headers(self.msg.items(), ['To'])
            body_to = [pair[0] for pair in body_to.get('To')]
            print('body_to: '+str(body_to))

            # filter from unicode
            for_filter = re.compile(r'[a-z0-9\.-_]{1,64}@[a-z0-9]{1,63}(?:\.[a-z0-9]{2,4})+')
            # crunch only addresses
            for_crunch = re.compile(r'(?<=[A-Za-z\x20])?[a-z0-9\._-]{1,64}@[a-z0-9\._-]{1,63}(?:\.[a-z0-9]{2,4})+')

            addr_list = filter(lambda line: for_filter.findall(line), body_to)
            print('addr_list'+str(addr_list))

            if len(body_to) > 1:
                addr_list = filter(lambda p: for_crunch.findall(p), addr_list)
                print('addr_list'+str(addr_list))

            print(str(rcvd_vect))
            smtp_to = filter(lambda l: re.search('<(.*@.*)?>', l, re.I), rcvd_vect)
            smtp_to_traces = [tr.group(0).strip() for tr in smtp_to]
            logger.debug(str(smtp_to_traces))

            if filter(lambda y: y == '<multiple recipients>', smtp_to_traces) and len(addr_list) <= 1:
                vector_dict ['to'] = score

            elif not filter(lambda y: y == '<multiple recipients>', smtp_to_traces) and len(addr_list) > 1:
                vector_dict ['to'] = score

            if len(addr_list) == 1 and smtp_to [0] != addr_list [0]:
                vector_dict ['to'] = score

        rcvd_vect = tuple([rcvd.partition('by')[0] for r in parsed_rcvds])[-1*n_rcvds:]
        logger.debug(rcvd_vect)
        vector_dict.update(common.get_trace_crc(rcvd_vect))

        # 2. Subject checks

        if self.msg.get('Subject'):

            subject_rule = [r'(SN|viagra|ciali(s|\$)|pfizer|discount|pill|med|free|click|Best\s+Deal\s+Ever|,|!|\?!|\>\>\:|sale)+']
            len_threshold = 70

            subj_score, subj_trace = common.basic_subjects_checker(self.msg.items(), subject_rule, len_threshold, score)

            vector_dict ['subj_score'] = subj_score
            vector_dict ['subj_trace'] = subj_trace

        else:

            vector_dict ['subj_score'] = 1
            vector_dict ['subj_trace'] = 0

        # 3. List checks and some other RFC 5322 compliences checks for headers

        temp_dict = dict.fromkeys([('list',score), ('sender',0), ('preamble',0), ('disp-notification',0)])

        if filter(lambda list_field: re.search('(List|Errors)(-.*)?', list_field), self.msg.keys()):
            # well, this unique spam author respects RFC 2369, his creation deservs more attentive check
            temp_dict['list'] = common.basic_lists_checker(self.msg.items(), score)

        elif not self.msg.keys().count('List') and (self.msg.keys().count('Sender') and self.msg.keys().count('From')):
            # if we don't have List header From = Sender (RFC 5322),
            # MUA didn't generate Sender field cause of redundancy
            temp_dict ['sender'] = 1

        if self.msg.get('Content-Type') and self.msg.get('Content-Type').startswith('multipart') and (not self.msg.preamble):
            temp_dict ['preamble'] = 1

        vector_dict.update(temp_dict)

        if (self.msg.keys()).count('Disposition-Notification-To'):
            vector_dict ['disp-notification'] = 1

        # 6. Check MIME headers



        # analyse attachements extensions

        #vect_dict.update(common.get_body_skeleton(self.msg))
        logger.debug('----> '+str(vector_dict))
        return (vector_dict)


if __name__ == "__main__":

    formatter = logging.Formatter('%(message)s')
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


# from - crc32 addr
# from - crc32 name

# url
# body

		


	
			



