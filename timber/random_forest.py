#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
-- can be imported as submodule to build feature vectors from emails collections,
using different presets of loaded heuristics ;

-- returns NxM matrix --> N samples from collection x M features +label value
( or "test" label if not defined ) in numpy array type
"""

import sys, os, logging, re, email, argparse, stat, tempfile, math, time
import numpy as np

from email.parser import Parser
from collections import defaultdict
from operator import itemgetter

from franks_factory import MetaFrankenstein
from pattern_wrapper import BasePattern
from vectorizer import Vectorizer
from timber_exceptions import NaturesError

from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn import svm

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

#def get_jaccard_distance():
        # return nltk.jaccard_distance()


if __name__ == "__main__":

    usage = 'usage: %prog [ samples_directory | file ] -c category -s score -v debug'
    parser = argparse.ArgumentParser(prog='helper')
    parser.add_argument('PATH', type=str, metavar = 'PATH',
                            help="path to dir with collections")

    parser.add_argument('-s', type = float,  action = 'store', dest = "score", default = 1.0,
                            help = "penalty score for matched feature, def = 1.0")

    parser.add_argument('-n', type = int,  action = 'store', dest = "estimators", default = 10,
                            help = "number of estimators, def = 10")

    parser.add_argument('-c', type=str, action = "store", dest = "criterion", default = 'gini',
                            help = "the function name to measure the quality of a split"),

    parser.add_argument('--svm', action = "store_true", dest = "svm", default = False,
                            help = "add SVM to classifiers list")
    parser.add_argument('-v', action = "store_true", dest = "info", default = False,
                            help = "be social (verbose)")
    parser.add_argument('-vv', action = "store_true", dest = "debug", default = False,
                            help = "be annoying (very very verbose)")


    args = parser.parse_args()

    required_version = (2,7)


    formatter = logging.Formatter('%(levelname)s %(filename)s : %(funcName)s : %(message)s')
    logger.setLevel(logging.WARN)
    ch = logging.StreamHandler(sys.stdout)
    fh = logging.FileHandler(os.path.join(tempfile.gettempdir(), time.strftime("%d%m%y_%H%M%S", time.gmtime())+'.log'), mode = 'w')
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    logger.addHandler(ch)
    logger.addHandler(fh)

    if args.info:
        logger.setLevel(logging.INFO)

    if args.debug:
        logger.setLevel(logging.DEBUG)


    parameters = dict(
                        n_estimators=args.estimators, criterion=args.criterion, max_depth=None,\
                        min_samples_split=2, min_samples_leaf=1, max_features='auto', max_leaf_nodes=None,\
                        oob_score=False, n_jobs=-1, random_state=None, verbose=1
    )
    classifiers = [('RandomForest', RandomForestClassifier(**parameters)), ('ExtraTrees', ExtraTreesClassifier(**parameters))]

    if args.svm:
        classifiers.append(('SVM', svm.SVC(C=1.0, kernel='rbf', degree=3, gamma=0.0, coef0=0.0, shrinking=True, probability=True, tol=0.001, \
                                        cache_size=200, class_weight=None, verbose=True, max_iter=-1, random_state=None)))

    #train_subdirs = ['spam','ham','net','info']
    labels = ['spam','ham']
    predicted_probs = defaultdict(list)
    predicted_classes = defaultdict(list)

    for label in labels :

        logger.info(('\n\n\t Create dataset for '+label+' class  :\n').upper())
        X_train = tuple()
        Y_train = tuple()
        X_test = tuple()
        Y_test = tuple()

        for path in [ os.path.join(args.PATH, subdir) for subdir in labels + ['test','ham']]:
            vectorizer = Vectorizer(path, label, args.score)
            X,Y = vectorizer.get_dataset()

            if os.path.basename(path) == 'test':
                X_test += X
                Y_test += Y

            else:

                X_train += X
                Y_train += Y

        logger.info('\nX_train :'+str(X_train))
        logger.info('\nY_train :'+str(Y_train))
        logger.info('\nX_test :'+str(X_test))

        # train classifiers instances and perform forecasting...

        for clf in classifiers:


            clf_name, obj = clf
            logger.info('\n\n\t Fit '+clf_name+' classifier for '+label.upper()+' class\n')
            obj.fit(X_train, Y_train)
            #logger.debug('\n'+clf_name+' was successfully trained with such classes list: '+str(obj._classes).upper()+'\n')

            logger.info('\n\n\t Try to make predictions...\n')

            for name, probability, class_flag in zip(Y_test, obj.predict_proba(X_test), obj.predict(X_test)):
                l = label+'_'+clf_name
                predicted_probs[name].append((l, probability))
                predicted_classes[name].append((l, class_flag))




    for d in [predicted_probs, predicted_classes]:
        print('\n========================================\n')
        for key,decisions in d.iteritems():
            print('\t'+key+' ==> '+str(decisions)+'\n')






'''''

class forest(object):

    DEFAULT_LABELS = ('ham', 'spam', 'info', 'net')

    def vectorize(doc_path, label, score)
    def get_labeled_data_set (label)
    def fit(label)
    def predict(path)
    def get_trained_forest(label)
    def dump_data_set(label)


and why I don't keep vectors and datasets in numpy arrays or in python arrays,
for those who don't know :

x = [1,2,3,4]*100
y = np.array([1,2,3,4]*100)
>>> sys.getsizeof(x)
3272
>>> sys.getsizeof(y)
80

Well,

>>> import cPickle
>>> x_s = cPickle.dumps(x)
>>> y_s = cPickle.dumps(y)
>>>
>>> sys.getsizeof(x_s)
1643
>>> sys.getsizeof(y_s)
12991

The real price of magic, so I mostly use good old tuples :

y = tuple([1,2,3,4]*100)
>>> y_s = cPickle.dumps(y)
>>> sys.getsizeof(y_s)
1243

>>> xx
(454079559, 0.0, 0.0, 0.0, 1.584962500721156, 1.5714285714285714, 0.0, 0.0, 0.0, 0.0, 2.0, 0.0, -1952929455, 1.0, -1215152318, 0, 1, 2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 12.0, 1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
>>>

>>> ar = array.array('f',xx)

>>> ff = tuple(float(i) for i in xx )

>>>
>>> ff
(454079559.0, 0.0, 0.0, 0.0, 1.584962500721156, 1.5714285714285714, 0.0, 0.0, 0.0, 0.0, 2.0, 0.0, -1952929455.0, 1.0, -1215152318.0, 0.0, 1.0, 2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 12.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

>>> ar_s = cPickle.dumps(ar)
>>> ff_s = cPickle.dumps(ff)
>>> sys.getsizeof(ar_s)
261
>>> sys.getsizeof(ff_s)
202


'''''







