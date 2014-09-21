#!/usr/bin/env python
"""
-can be imported as submodule to build feature vectors from emails collections,
using different presets of loaded heuristics

-returns NxM matrix --> N samples from collection x M features +label value
(or "test" label if not defined) in numpy array type
"""

import sys, os, logging, re, email
from optparse import OptionParser
# import matplotlib.pyplot as plt

from pattern_wrapper import MetaPattern

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

# define some functions
def vectorize_by_rules(doc_path,label):
	print(doc_path,label)
	"""
		Create feature vector for email from doc_path,
		if label is set => feature set is also predifined by category pattern

	"""

	logger.debug("Start processing: " + doc_path)
	vect_dict = {}

	parser=email.Parser.Parser()
	f = open(doc_path,"rb")
	msg = parser.parse(f)

	f.close()



	try:

		checks_set = MetaPattern.New(msg,label,score)
		#print (test)
		logger.debug ('\t CHECK_'+label.upper())
		vect_dict.update (checks_set.run())

	except Exception, details:
		logger.error(str(details))
		raise

	return (vect_dict, label)

def make_dataset(dir_path,category,score):

	if not os.listdir(dir_path):
		raise Exception ('Collection dir "'+dir_path+'" is empty.')

	print(category)
	X =[]
	  # NxM input matrix --> N samples x M features

	for path, subdir, docs in os.walk(dir_path):

		for d in docs:
			print(os.path.join(path, d))
			sample_path = os.path.join(path, d)

			if category == 'test':
				X={'ham':[],'spam':[],'info':[],'nets':[]}
				for label in X.iterkeys():
					vector_x = vectorize_by_rules(sample_path,label,score)
					(X.get(label)).append(vector_x)

			else:

				vector_x = vectorize_by_rules(sample_path,category,score)
				print(vector_x)
				X.append(vector_x)

			logger.debug(str(X))

	return(X)

'''''
def dump_data_set(data_set):

			f = open('data_from_'+os.path.basename(dir_path)+'.txt','w+b')
			for features_vect, class_vect, abs_path  in zip(X, Y, Z):
				logger.debug('-->'+str(features_vect+(class_vect,abs_path)))
				f.writelines(str(features_vect+(class_vect,abs_path))+'\n')
			f.close()



def plot_data_set(data_set):
'''''

if __name__ == "__main__":

	usage = "usage: %prog [options] -t samples_directory -p dump_dataset -v visualise_with_matplot -d debug"
	parser = OptionParser(usage)

	parser.add_option("-t", action="store", type="string", dest="collection", metavar="[REQUIRED]", help="path to samples collection")

	parser.add_option("-p", action="store_true", dest="dump", default=False, metavar=" ", help="safe data into file in libsvm format")
	parser.add_option("-s", type=float, dest = "score", default = 1.0, metavar = " ", help = "score penalty for matched feature, def = 1.0")
	parser.add_option("-v", action="store_true", dest="visualize", default=False, metavar=" ", help="visualise dataset with matplot")
	parser.add_option("-c", action="store", dest="category", default='test', metavar=" ", help="samples category, default=test, i.e. not defined")
	parser.add_option("-d", action="store_true", dest="debug", default=False, metavar=" ", help="be verbose")


	(options, args) = parser.parse_args()

	if options.__dict__.values().count(None) > 0:
		print("")
		parser.print_help()
		print("")
		sys.exit(1)


	# in case if options.debug is True
	formatter = logging.Formatter('%(message)s')
	logger.setLevel(logging.INFO)
	ch = logging.StreamHandler(sys.stdout)
	ch.setFormatter(formatter)
	logger.addHandler(ch)

	if options.debug:
		logger.setLevel(logging.DEBUG)

	# 1. create train dataset
	try:
		make_dataset(options.collection,options.category,options.score)

	except Exception, details:
		logger.error(str(details))
				#sys.exit(1)
		raise







