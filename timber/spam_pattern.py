#! /usr/bin/env python

import os, sys, logging, re, common
from email.header import decode_header

#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

class SpamPattern():
	"Keeps and applies vectorising rules for spams."

	def __init__(self,msg,score):
		self.msg = msg

	def run(self):

		vector_dict = {}

        # 1. size
		vector_dict['size'] = 0
		if (float(os.stat(doc_path).st_size)/1024) < 4:
			vector_dict['size'] = 1

		logger.debug("SIZE: "+str(float(os.stat(doc_path).st_size)/1024))

		# 2. Received headers

		# get crc32 of only unique headers vector
		heads_vect = tuple(self.msg.keys())

		excluded_heads = ['Received', 'Subject', 'From', 'Date', 'MIME-Version', 'To', 'Message-ID', 'Return-Path']
		vector_dict ['heads_crc'] = common.get_heads_crc(excluded_heads, heads_vect)

		# keep the count of traces fields
		vector_dict["traces_num"] = self.msg.keys().count('Received')

		# basic parsing and dummy checks with regexp (takes only first n_rcvds headers)
		n_rcvds = 2
		rcvd_values = tuple(msg.get_all('Received'))[-1*n_rcvds:]
		parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in rcvds_tuple[:]])

		vector_dict ["trace_rule"]=0
		rcvd_rules = [
						'(public|airnet|wi-?fi|a?dsl|dynamic|static)+',
						'(\(|\s+)(([a-z]+?)-){0,2}(\d{1,3}-){1,3}\d{1,3}([\.a-z]{1,63})+\.(ru|in|id|ua|ch)'
					]

		for rule in rcvd_rules:
			if filter(lambda l: re.search(rule,l), parsed_rcvds)
				vector_dict ["trace_rule"]=1

		# deep parsing and some kind of spam-specifique checks
		vector_dict['smtp_to']=0
		vector_dict['to'] = 0

		rcvd_vect = tuple([rcvd.partition('for')[0] for r in parsed_rcvds])

		# don't need to validate email address, just match it within the whole string
		if not filter(lambda l: re.search('<(.*@.*)?>',l,re.I), rcvd_vect):
			vector_dict['smtp_to']=1

		else:

			body_to = common.get_decoded_headers(msg.items(),['To'])
			body_to = [pair[0] for pair in body_to.get('To')]
			smtp_to = filter(lambda l: re.search('<(.*@.*)?>',l,re.I), rcvd_vect)
			smtp_to_traces = [tr.group(0).strip() for tr in smtp_to]

			if filter(lamda y: y=='<multiple recipients>',smtp_to_traces) and  <=1:
				vector_dict['to'] = score

			elif not filter(lamda y: y=='<multiple recipients>',smtp_to_traces) and len(body_to)>1:
				vector_dict['to'] = score

			if len(body_to) == 1 and smtp_to[0] !=
				vector_dict['to'] = score


		# from first N trace values leave only gate IPv4 addr and domain value, pack in one line and take crc32
		# I've never seen spam from gates with IPv6 ifaces, IPv6 appears in hams usually ?
		regs = ['\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '\s((?!-)[a-z0-9-\.]{1,63}(?<!-))+(\.[a-z]{2,6}){0,}']

		rcvd_vect = tuple([rcvd.partition ('by') [0] for r in parsed_rcvds])
		rcvd_vect = rcvd_vect[-1*n_rcvds:]

		vector_dict.update(common.smtp_trace_crc(rcvd_vect,regs))

		# 3. Subject checks

		if self.msg.get('Subject'):

			subject_rule = ['(SN|viagra|ciali(s|\$)|pfizer|discount|pill|med|free|click|Best\s+Deal\s+Ever|,|!|?!|>>:|babe)+']
			subject_len_trashold = 70

			subj_score, subj_trace = common.check_subject(self.msg.items(),subject_rule,subject_len_trashold,score)
			vector_dict['subj_score'] = subj_score
			vector_dict ['subj_trace'] = subj_trace

		else:
			
			vector_dict['subj_score']=1
			vector_dict ['subj_trace']=0

		# 4. List checks and some other RFC 5322 compliences checks for headers

		temp_dict = dict.fromkeys('List','Sender','Preamble')

		temp_dict['List'] = score

		if filter(lambda list_field: re.search('^List(-.*)?',list_field), self.msg.items()):
			# well, this unique spam author respects RFC  rules about List fields,
			# his creation deserved the deep check
			temp_dict['List'] = common.check_lists(self.msg.items())

		elif not self.msg.keys().count('List') and (self.msg.keys().count('Sender') and self.msg.keys().count('From')):
			temp_dict['Sender'] = 1 # normally (except for info-pubs and messages from nets) From = Sender
									# MUA didn't generate Sender field cause of redundancy

        if not self.msg.preamble and self.msg.get('Content-Type').startswith('multipart')
	        temp_dict ['Preamble'] = 1

	    vector_dict.update(temp_dict)

	    if self.msg.keys.count('')


		# . check urls


		# 5. simple checks by regexp for unconditional spams
		vect_dict.update(common.get_body_skeleton(self.msg))
		logger.debug(vect)
		return(vect_dict)


if __name__ == "__main__":

	formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
	ch = logging.StreamHandler(sys.stdout)
	ch.setLevel(logging.DEBUG)
	ch.setFormatter(formatter)
	logger.addHandler(ch)

	try:
		pattern=SpamPattern(msg)
		vector = test.run()
		logger.debug(vector)


	except Exception, details:
		raise


# from - crc32 addr
# from - crc32 name

# url
# body

		


	
			



