#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import sys, os, logging, re, email, argparse, stat, tempfile, math, time, json
import numpy as np

from email.parser import Parser
from collections import defaultdict
from operator import itemgetter

from franks_factory import MetaFrankenstein
from pattern_wrapper import BasePattern
from vectorizer import Vectorizer
from clf_wrapper import ClfWrapper
from timber_exceptions import NaturesError

from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn import svm
from sklearn.metrics import accuracy_score

import numpy as np
import matplotlib.pyplot as plt

DEFAULT_FOREST_ARGS = dict(n_estimators=20, criterion='gini', max_depth = None, min_samples_split=2, min_samples_leaf=1,
                            max_features='auto', max_leaf_nodes=None, oob_score=False, n_jobs=-1, random_state=None, verbose=1)

logger = logging.getLogger('')

# define some functions

def create_report(predictions_dict, labels):

    report = dict()
    for key, decisions in predictions_dict.iteritems():
        logger.debug('\t'+key+' ==> '+str(decisions)+'\n')
        decisions = [(label, value) for label, value in decisions]

        if len(labels) == 1:
            to_substract = set([(label, value) for label, value in decisions if value < 0.50])
            diff = list(set(decisions) - to_substract)
            to_add = [('NON '+label, value) for label, value in decisions if value < 0.50]
            decisions = diff + to_add

        decisions = tuple(sorted(decisions))[:len(classifiers)]
        decisions = [(name.partition('_')[0], score) for name, score in decisions]

        logger.debug('\t'+key+' ==> '+str(decisions)+'\n')
        final = map(itemgetter(0), decisions)
        if len(set(final)) == 1:
            report[key] = ((final.pop()).upper(), decisions)

        elif len(set(final)) == 2:
            report[key] = (''.join([name for name in final if final.count(name)==2]).upper(), decisions)

        elif len(set(final)) == 3:
            report[key] = (''.join(sorted(decisions)[:1]).upper(), decisions)

    for k,v in report.iteritems():
        logger.debug(k+' ==> '+str(v))

    return report

def get_classifiers_stat(clfs_dict, plot_flag):
    logger.debug(str(clfs_dict))
    logger.debug(str(plot_flag))

    pass

if __name__ == "__main__":

    usage = 'usage: %prog [ samples_directory | file ] -c category -s score -v debug'
    parser = argparse.ArgumentParser(prog='helper')
    parser.add_argument('PATH', type=str, metavar = 'PATH',
                            help="path to dir with collections")

    parser.add_argument('-s', type = float,  action = 'store', dest = "score", default = 1.0,
                            help = "penalty score for matched feature, def = 1.0")

    parser.add_argument('--svm', action = "store_true", dest = "svm", default = False,
                            help = "add SVM to classifiers list")

    parser.add_argument('--forest-args',action = 'store', type=list, dest = "forest_args_dict", default = DEFAULT_FOREST_ARGS,
                            help = "list of forest classifier arguments")

    parser.add_argument('--accuracy', type = str, action = "store", dest = "accuracy_path", default = False,
                            help = "path to file with ground truth to estimate accuracy")

    parser.add_argument('--graph', action = "store_true", dest = "graph", default = False,
                            help = "plot feature impotances graph")

    parser.add_argument('--report', action = "store", dest = "report", default = False,
                            help = 'path to file, where final report will be dumped')

    parser.add_argument('-v', action = "store_true", dest = "info", default = False,
                            help = "be social (verbose)")
    parser.add_argument('-vv', action = "store_true", dest = "debug", default = False,
                            help = "be annoying (very very verbose)")

    args = parser.parse_args()

    # 1. preparations
    required_vers = '2.7'
    version = str(sys.version_info.major)+'.'+str(sys.version_info.minor)
    if version != required_vers:
        sys.stderr.write( '[%s] - Error: Your Python interpreter must be %d.%d\n' % (sys.argv[0], major, minor))
        sys.exit(-1)

    formatter = logging.Formatter('%(levelname)s %(filename)s : %(funcName)s : %(message)s')
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

    # 2. initialize classifiers
    classifiers = [
                    ('RandomForest', RandomForestClassifier(**DEFAULT_FOREST_ARGS)),
                    ('ExtraTrees', ExtraTreesClassifier(**DEFAULT_FOREST_ARGS))
    ]

    if args.svm:
        classifiers.append(('SVM', svm.SVC(C=1.0, kernel='rbf', degree=3, gamma=0.0, coef0=0.0, shrinking=True, probability=True, tol=0.001, \
                                        cache_size=200, class_weight=None, verbose=True, max_iter=-1, random_state=None)))


    #labels = ['spam','ham']
    labels = ['spam']

    predicted_probs = defaultdict(list)
    clf_properties = defaultdict(list)

    # 3. vectorize emails for each label in that way
    # as we have one-class classification problem
    for label in labels :

        logger.info(('\n\n\t Create dataset for '+label+' class  :\n').upper())

        vectorizer = Vectorizer(args.PATH, label, args.score)
        X_train, Y_train, X_test, Y_test = vectorizer.get_dataset()

        logger.info('\n\t\tX_train :'+str(X_train))
        logger.info('\n\t\tY_train :'+str(Y_train))
        logger.info('\n\t\tX_test :'+str(X_test)+'\n')
        logger.info('\n\t\tX_test :'+str(Y_test)+'\n')

        # 4. train classifiers instances and perform forecasting...
        results = dict
        for clf in classifiers:
            clf_name, clf_obj = clf
            clf_obj.fit(X_train, Y_train)
            classifier = ClfWrapper(clf_name, clf_obj, label)

            logger.debug(str(type(X_test)))
            logger.debug(str(type(Y_test)))

            probs_vector, predics_vect, probs, classes = classifier.predict(X_test, Y_test)
            logger.debug('+++PROBS '+str(probs))
            logger.debug('+++CLASSES '+str(classes))
            l = label.upper()+'_'+clf_name
            [ predicted_probs[name].append((l, probability)) for name, probability in probs_vector ]

            # 5. obtain some classifiers objects statistics
            classifier.get_recipe()
            if args.accuracy_path:
                classifier.get_accuracy(args.accuracy_path)

            classifier.__delattr__('obj')
            logger.debug('classifier.__dict__'.upper()+str(classifier.__dict__))
            clf_properties[clf_name].append(classifier.__dict__)

    # 6. sum up final decisions
    logger.debug('\n========================================\n')
    report = create_report(predicted_probs, labels)

    if args.report:
        with open(args.report, 'wb') as f:
            for k,v in report.iteritems():
                f.writeline(time.strftime("%d%m%y_%H%M%S", time.gmtime())+'\n')
                f.writeline(k+' --> '+str(v))

    # 7. classifiers benchmarking
    get_classifiers_stat(clf_properties, args.graph)





















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







