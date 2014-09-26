#! /usr/bin/env python

import sys, os, logging, re, email
from optparse import OptionParser

# define needed functions
def cut_header_from_body ( email ):
	doc = open(email, "rb")
	doc_content = ''.join (doc.readlines())
	doc.close()
	# cut headers from body
	headers_str = re.split('\r\n\r\n', doc_content)[0]
	corp_lines = re.split('\r\n\r\n', doc_content)[1:]

	# normilize lines in body
	b_list = sum ([b.split('\r\n') for b in corp_lines], [])
	corp_lines_list = [l.strip () for l in b_list]
	corp_lines_list = filter (lambda x: len (x) != 0, corp_lines_list)

	return (headers_str, corp_lines_list)

def quote_the_value(value):
	return ('"'+str(value)+'"')

def headers_parser ( head_string,email ):
	d = os.path.basename(email)
	headers_dict = { }
	cur_header = None

	for h in head_string.split('\r\n'):
		#h = h.rstrip()
		# match the start of header
		if re.match ('^[\S]+:.*$', h):
			header_name, value = h.split(':', 1)
			headers_dict[header_name] = value
			cur_header = header_name
		# match the start of folded value of the header
		elif re.match('^(\t|\x20)+.*$', h):
			headers_dict[cur_header] = headers_dict.get(cur_header) + ' ' + h
		else:
			# just skip unmached headers
			continue

	for h_key in headers_dict.iterkeys():
		logger.debug ('__HEADER__('+(d)+'):\t'+ h_key + ' --> ' + quote_the_value(headers_dict.get(h_key)))

	return (headers_dict)

if __name__ == "__main__":

	usage = "usage: %prog [-t training_directory [-f file]]"
	parser = OptionParser(usage)

	parser.add_option ("-t", action = "store", type = "string", dest = "train_dir",
	                   help = "path to collections")
	parser.add_option ("-f", action = "store", type = "string", dest = "new_doc",
	                   help = "path to checking email")

	(options, args) = parser.parse_args()

	if len(options.__dict__.values()) < 2:
		print("")
		parser.print_help ()
		print("")
		sys.exit (1)


	# in case if options.verbose is True
	tmp='/tmp'
	formatter = logging.Formatter('%(message)s')
	logger = logging.getLogger()
	logger.setLevel(logging.DEBUG)
	ch = logging.StreamHandler(sys.stdout)
	fh = logging.FileHandler(os.path.join(tmp,'headers.log'),mode='w')
	ch.setFormatter(formatter)
	fh.setFormatter(formatter)
	logger.addHandler(ch)
	logger.addHandler (fh)

	# 1. create train dataset
	try:
		parser = email.Parser.Parser()

		for path, subdirs, docs in os.walk(options.train_dir):
			for d in docs:
				print(d)
				sample_path = os.path.join(path, d)
				f = open(sample_path, 'rb')
				msg = parser.parse(f)
				f.close()
				logger.debug('\nPATH: '+sample_path)
				logger.debug ('\n============== common garden parser ====================\n')
				headers_parser(cut_header_from_body(sample_path)[0],sample_path)

				logger.debug ('\n============== parser from STL email ====================\n')
				for k in msg.keys():
					logger.debug('HEADER('+(d)+'):\t'+k+' ==> '+quote_the_value(str(msg.get(k))))

				logger.debug ('EPILOGUE('+(d)+'): ==> '+quote_the_value(str(msg.epilogue)))
				logger.debug ('PREAMBLE('+(d)+'): ==> '+quote_the_value(str(msg.preamble)))


	except Exception, details:
		logger.error(str (details))
		raise

