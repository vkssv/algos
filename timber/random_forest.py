#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
-- can be imported as submodule to build feature vectors from emails collections,
using different presets of loaded heuristics ;

-- returns NxM matrix --> N samples from collection x M features +label value
( or "test" label if not defined ) in numpy array type
"""

import sys, os, logging, re, email, argparse, stat, tempfile, math

from email.parser import Parser
from collections import defaultdict, OrderedDict

from franks_factory import MetaFrankenstein
from pattern_wrapper import BasePattern

#from sklearn.ensemble import RandomForestClassifier


#PYTHON_VERSION=(2,7)

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

# define some functions

#def check_python_version(version):
#    if version != (sys.version_info.major, sys.version_info.minor):
#        major, minor = version
#        sys.stderr.write( '[%s] - Error: Your Python interpreter must be %d.%d\n' % (sys.argv[0], major, minor))
#        sys.exit(-1)
#        return

# create feature vector for email from doc_path,
# if label is set => feature set is also predifined by pattern for this label

class EmailVectorizer(object):

    def get_dataset(self, path, label, penalty):

        if label not in ['spam','ham','nets','infos','test']:
            logger.error('Pattern for category '+label+' wasn\'t implemented!')
            sys.exit(1)

        return(X_train,Y_train)





def vectorize(doc_path, penalty_score):

    logger.debug("\n\nStart processing: " + doc_path + ' from "' + label + '" set')

    parser = Parser()
    with open(doc_path, 'rb') as f:
        M = parser.parse(f)

    vect_dict['size'] = math.ceil(float((os.stat(doc_path).st_size)/1024))
    logger.debug('----->'+str(vect_dict))

    try:

        Frankenstein_cls = MetaFrankenstein.New(label)
        logger.debug('\n\n\t CHECK_' + label.upper()+'\n')
        print('DNA: '+str(Frankenstein_cls.__dict__))
        vector = Frankenstein_cls(msg=M, score=penalty_score)
        vector.__setattr__('msg_size', math.ceil(float((os.stat(doc_path).st_size)/1024)))
        print('Current Frankenstein : '+str(vector.__dict__))

    except Exception as details:
        logger.error(str(details))
        raise

    return vector.__dict__

def __normalize(vect_dict):
    # remove feature tags ?
    #
    pass


#def get_jaccard_distance():
        # return nltk.jaccard_distance()


def __pathes_gen(path, st_mode):

    sample_path = path
    if st_mode == stat.S_IFREG:
        yield(sample_path)

    elif st_mode == stat.S_IFDIR:
        for path, subdir, docs in os.walk(path):
            for d in docs:
                sample_path = os.path.join(path,d)
                yield(sample_path)


'''''
def dump_data_set(data_set):

			f = open('data_from_'+os.path.basename(dir_path)+'.txt','w+b')
			for features_vect, class_vect, abs_path  in zip(X, Y, Z):
				logger.debug('-->'+str(features_vect+(class_vect,abs_path)))
				f.writelines(str(features_vect+(class_vect,abs_path))+'\n')
			f.close()


'''''

if __name__ == "__main__":

    usage = 'usage: %prog [ samples_directory | file ] -c category -s score -v debug'
    parser = argparse.ArgumentParser(prog='helper')
    parser.add_argument('PATH', type=str, metavar = 'PATH', help="path to dir with test collection")
    #parser.add_argument('-c', action = "store", dest = 'category',default = 'test',
    #                        help = "samples category, default=test, i.e. not defined")
    parser.add_argument('-t', type=str, action = "store", dest = "train_dir", \
                        help = "path to dir with categories collections")
    parser.add_argument('-s', type = float,  action = 'store', dest = "score", default = 1.0,
                            help = "penalty score for matched feature, def = 1.0")
    parser.add_argument('-v', action = "store_true", dest = "debug", default = False, help = "be verbose")
    parser.add_argument('-c', type=str, action = "store", dest = "criterion", default = 'gini', help = "the function name to measure the quality of a split")

    args = parser.parse_args()

    required_version = (2,7)


    formatter = logging.Formatter(' --- %(filename)s ---  %(message)s')
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler(sys.stdout)
    fh = logging.FileHandler(os.path.join(tempfile.gettempdir(), args.category+'.log'), mode = 'w')
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    logger.addHandler(ch)
    logger.addHandler(fh)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    # 1. check pathes
    subdirs = ['spam','ham','net','info','test']
    for path in [ os.path.join(args.PATH, subdir) for subdir in subdirs]:
        if not os.listdir(path):
            logger.error(path + '" is empty.')
            sys.exit(1)







    # 2. make datasets
    try:
        X = list()
        pathes_iterator = __pathes_gen(args.PATH, *mode)


        while(True):
            sample_path = next(pathes_iterator)
            logger.debug('PATH: '+sample_path)
            vector_x = dict()
            if args.category == 'test':
                for label in ('ham', 'spam', 'info', 'net'):

                    vector_x = vectorize(sample_path, args.score)
                    logger.debug('----->'+str(vector_x))
                    #vector_x = normilize(vector_x)
                    logger.debug('----->'+str(vector_x))
                    X.append(vector_x)
            else:

                vector_x = vectorize(sample_path, args.score)
                logger.debug('----->'+str(vector_x))
                X.append(vector_x)


        logger.debug(X)
        #clf = RandomForestClassifier(n_estimators=10, max_depth=None, min_samples_split=1, random_state=0, criterion=args.criterion)



    except StopIteration as details:
        pass

    except Exception as details:
        logger.error(str(details))
        #sys.exit(1)
        raise


'''
class forest(object):

    DEFAULT_LABELS = ('ham', 'spam', 'info', 'net')

    def vectorize(doc_path, label, score)
    def get_labeled_data_set (label)
    def fit(label)
    def predict(path)
    def get_trained_forest(label)
    def dump_data_set(label)
'''







