#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
-- can be imported as submodule to build feature vectors from emails collections,
using different presets of loaded heuristics ;

-- returns NxM matrix --> N samples from collection x M features +label value
( or "test" label if not defined ) in numpy array type
"""

import sys, os, logging, re, email, argparse, stat, tempfile, math
import numpy as np

from email.parser import Parser
from collections import defaultdict, OrderedDict
from operator import itemgetter

from franks_factory import MetaFrankenstein
from pattern_wrapper import BasePattern

from sklearn.ensemble import RandomForestClassifier


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


def vectorize(doc_path, label, penalty_score):

    logger.debug("\n\nStart processing: " + doc_path + ' from "' + label + '" set')

    parser = Parser()
    with open(doc_path, 'rb') as f:
        M = parser.parse(f)

    try:

        Frankenstein_cls = MetaFrankenstein.New(label)
        logger.debug('\n\n\t CHECK_' +doc_path+'\n')
        #logger.debug('DNA: '+str(Frankenstein_cls.__dict__))
        pattern_instance = Frankenstein_cls(msg=M, score=penalty_score)
        vector = pattern_instance.__dict__
        vector.pop('PENALTY_SCORE')
        vector['msg_size'] = math.ceil(float((os.stat(doc_path).st_size)/1024))
        vector = tuple((k.upper(),value) for k,value in sorted(vector.items()))
        logger.debug('vect : '+str(vector))

        print('\n\tCurrent Frankenstein ==> '+str(vector))
        msg_vector = tuple(map(itemgetter(1),vector))

    except Exception as details:
        logger.error(str(details))
        raise
    print('\nVECTOR ===> '+str(msg_vector)+'\n')
    return msg_vector

def __normalize(vect_dict):
    # remove feature tags ?
    #
    pass


#def get_jaccard_distance():
        # return nltk.jaccard_distance()

def get_validated_path(path):

    checks = {
                stat.S_IFREG : lambda fd: os.stat(fd).st_size,
                stat.S_IFDIR : lambda d: os.listdir(d)
    }

    mode = filter(lambda key: os.stat(path).st_mode & key, checks.keys())
    print('mode: '+str(mode))
    f = checks.get(*mode)
    if not f(path):
        raise Exception(path + '" is empty.')

    msg_path = path
    if mode[0] == stat.S_IFREG:
        print(msg_path)
        yield msg_path

    elif mode[0] == stat.S_IFDIR:
        for p, subdir, docs in os.walk(path):
            for d in docs:
                msg_path = os.path.join(p,d)
                yield msg_path


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
    parser.add_argument('PATH', type=str, metavar = 'PATH', help="path to dir with collections")
    #parser.add_argument('-c', action = "store", dest = 'category',default = 'test',
    #                        help = "samples category, default=test, i.e. not defined")
    parser.add_argument('-s', type = float,  action = 'store', dest = "score", default = 1.0,
                            help = "penalty score for matched feature, def = 1.0")
    parser.add_argument('-v', action = "store_true", dest = "debug", default = False, help = "be verbose")
    parser.add_argument('-c', type=str, action = "store", dest = "criterion", default = 'gini', help = "the function name to measure the quality of a split")

    args = parser.parse_args()

    required_version = (2,7)


    formatter = logging.Formatter(' --- %(filename)s ---  %(message)s')
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler(sys.stdout)
    #fh = logging.FileHandler(os.path.join(tempfile.gettempdir(), args.category+'.log'), mode = 'w')
    ch.setFormatter(formatter)
    #fh.setFormatter(formatter)
    logger.addHandler(ch)
    #logger.addHandler(fh)

    if args.debug:
        logger.setLevel(logging.DEBUG)


    #train_subdirs = ['spam','ham','net','info']
    train_subdirs = ['spam','ham']
    total = {}
    clf = RandomForestClassifier(n_estimators=10, criterion=args.criterion, max_depth=None,\
                                 min_samples_split=2, min_samples_leaf=1, \
                                 max_features='auto', max_leaf_nodes=None,bootstrap=True, oob_score=False, \
                                 n_jobs=-1, random_state=None, verbose=1)
    for label in train_subdirs :
        logger.debug('Create dataset for label '+str(label).upper())
        X_train = []
        Y_train = []
        X_test = []
        Y_test = []
        for path in [ os.path.join(args.PATH, subdir) for subdir in train_subdirs]:
            logger.debug('Processing subdir : '+str(path))
            pathes_gen = get_validated_path(path)

            while(True):

                try:

                    msg_path = next(pathes_gen)
                    x_vector = vectorize(msg_path, label, args.score)

                    if os.path.basename(path) == 'test':
                        X_test.append(x_vector)
                        Y_test.append(os.path.basename(msg_path))

                    else:
                        X_train.append(x_vector)
                        y_vector = [0.0]
                        if label == os.path.basename(path):
                            y_vector = [1.0]

                        Y_train.append(y_vector)

                except StopIteration as err:
                    break

        X_train = tuple(X_train)
        Y_train = tuple(Y_train)
        X_test = tuple(X_test)
        Y_test = tuple(Y_test)
        clf.fit(X_train, Y_train)

        predictions = []
        for x,y in zip(X_test,Y_test):
            predictions.append((y, clf.predict_proba(X_test)))

        total[label] = predictions

    print(total)









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







