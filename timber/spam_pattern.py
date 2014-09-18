#! /usr/bin/env python

import os, sys, logging, re, common
from email.header import decode_header

#formatter_debug = logging.Formatter('%(asctime)s %(levelname)s %(filename)s: %(message)s')
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

class SpamPattern():
	"Keeps and applies vectorising rules for spams."

	def __init__(self,msg):
		self.msg = msg

	def run(self):

		vector_dict = {}
        # size
		# 1. HEADERS
		# 1.1 get crc32 of just unique headers vector
		heads_vect = tuple(self.msg.keys())

		excluded_heads = ['Received', 'Subject', 'Date', 'MIME-Version', 'To', 'Message-ID', 'Return-Path']
		without_X_heads = True
		vector_dict['heads_crc'] = common.get_heads_crc(excluded_heads, heads_vect, without_X_heads)

		# 1.2 features for unconditional spams
        # Subject checks are valuable only for pure US-ASCII messages
        # or for Subjects: which contain Latin symbols

        subj_value = (decode_header(msg.get('Subject'))[0])
        decoded_heads ={}
        for h in regs_dict.keys():
            head_value, encoding = (decode_header(msg.get('Subject'))[0])
            decoded_heads[h] = head_value

        sus_tokens = {
	        'Subject': (['(SN|viagra|ciali(s|\$)|pfizer|discount|pill|med|free|click|Best\s+Deal\s+Ever|>>:||babe)+'], 1.0),
	        'Received': (['(.*public.*|.*airnet.*|.*wi-?fi.*|adsl|dsl|dynamic|static)+'], 1.0)
        }

        headers_scores = common.check_suspect_heads(decoded_heads, sus_tokens, with_noise = False)
		headers_scores ['Subject'] = headers_scores.get ('Subject') + score

        # 1.3 check correlated heads, MUA's try follow RFC 5322 for generating Replies and Forwards,
		# spammer's scripts not always

		correlated = {
						'Re'    :   ['In-Reply-To','(X-)?Thread(-.*)?','(X-)?References'],
		                'Fwd?'  :   ['(X-)?Forward']
					}

		for prefix in correlated.keys():
            logger.debug("prefix: "+prefix)

			if re.search('(prefix\s+:\s+)+', decoded_heads['Subject'],re.I):
                for regexp in correlated.get(prefix):
                    if not filter(lambda x: re.search(regexp,x,re.I),self.msg.keys()):
			            headers_scores ['Subject'] = headers_scores.get ('Subject') + 1.0

        vector_dict.update(headers_scores)

        list_patterns=[
                        '(.*-)?Unsubscribe(-.*)?',
                        '(.*-)?UnList(-.*)?',
                        '(-.*)?List-Help(-.*)?',
                        '(-.*)?List-Post(-.*)?',
                        ]

		if self.msg.keys().count('List') and not filter(lambda l: re.search(l, self.msg.keys(), re.I), list_patterns):
            vector_dict['UnSubscr'] = 1.0

        if self.msg.keys().count('List') and not self.msg.keys().count('Sender')
            vector_dict['UnSubscr'] = vector_dict.get('UnSubscr')+2.0

        if self.msg.keys().count('Sender') and self.msg.keys().count('From') and not self.msg.keys().count('List'):
            vector_dict['Sender'] = 1.0

		# 1.4 heuristics for Received: trace headers

		vector_dict["traces_num"] = self.msg.keys().count('Received')

        n_rcvds = 2
		parsed_rcvds = common.parse_trace_fields(msg,n_rcvds)

		# from Received trace value leave only lines with helo domain/IP addr + smtp "rcpt to:" value
		smtp_traces = tuple([((trace_line[0]).partition('by')[0], trace_line[2]) for trace_line in rcvds_vect[:]])

		ipv4_regexp = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
		keys = tuple(['rcvd' + str(i) for i in range(n_rcvds)])

		vector_dict['smtp_to']=1
		for key, trace in zip(keys[:],smtp_traces[:]):
            logger.debug(key, trace)
			result_str=''
            #smtp_
			# absence of smtp "rcpt to:" value threat as separate feature
			#if not filter(lambda smtp_to_trace: smtp_to_trace,trace)
			#	vector_dict['smtp_to']=0

			gate_ip = re.findall(ipv4_regexp,trace[0])[-1:]
			result_str=gate_ip + (trace[0]).partition('\r\n')[0].split()[1]

			vector_dict[key] = binascii.crc32(result_str)


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

			
# subj lenght
# from - crc32 addr
# from - crc32 name
# to, cc, bcc - count + crc32 addr + name
# url
# body

		


	
			



