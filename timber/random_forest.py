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

def __get_validated_path(path):

    checks = {
                stat.S_IFREG : lambda fd: os.stat(fd).st_size,
                stat.S_IFDIR : lambda d: os.listdir(d)
    }

    mode = filter(lambda key: os.stat(path).st_mode & key, checks.keys())
    logger.debug('mode: '+str(mode))
    f = checks.get(*mode)
    if not f(path):
        raise Exception(path + '" is empty.')

    msg_path = path
    if mode[0] == stat.S_IFREG:
        logger.debug(msg_path)
        yield msg_path

    elif mode[0] == stat.S_IFDIR:
        for p, subdir, docs in os.walk(path):
            for d in docs:
                msg_path = os.path.join(p,d)
                yield msg_path


def vectorize(doc_path, label, penalty_score):

    logger.debug("\n\nStart processing: " + doc_path + ' from "' + label + '" set')

    parser = Parser()
    with open(doc_path, 'rb') as f:
        M = parser.parse(f)

    try:

        Frankenstein_cls = MetaFrankenstein.New(label)
        logger.debug('Frankenstein_cls :'+str(type(Frankenstein_cls)))
        logger.debug('Frankenstein_cls :'+str(Frankenstein_cls))
        logger.debug('\n\n\t CHECK_' +doc_path+'\n')
        #logger.debug('DNA: '+str(Frankenstein_cls.__dict__))
        pattern_instance = Frankenstein_cls(msg=M, score=penalty_score)
        vector = pattern_instance.__dict__
        vector.pop('PENALTY_SCORE')
        vector['msg_size'] = math.ceil(float((os.stat(doc_path).st_size)/1024))
        vector = tuple((k.upper(),value) for k,value in sorted(vector.items()))
        logger.debug('vect : '+str(vector))

        logger.debug('\n\tCurrent Frankenstein ==> '+str(vector))
        msg_vector = tuple(map(itemgetter(1),vector))

    except Exception as details:
        logger.error(str(details))
        raise
    logger.debug('\nVECTOR ===> '+str(msg_vector)+'\n')
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
    logger.debug('mode: '+str(mode))
    f = checks.get(*mode)
    if not f(path):
        raise Exception(path + '" is empty.')

    msg_path = path
    if mode[0] == stat.S_IFREG:
        logger.debug(msg_path)
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


    formatter = logging.Formatter(' %(module)s : %(funcName)s : %(message)s')
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler(sys.stdout)
    fh = logging.FileHandler(os.path.join(tempfile.gettempdir(), time.strftime("%d%m%y_%H%M%S", time.gmtime())+'.log'), mode = 'w')
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    logger.addHandler(ch)
    logger.addHandler(fh)

    if args.debug:
        logger.setLevel(logging.DEBUG)


    #train_subdirs = ['spam','ham','net','info']
    #labels = ['spam','ham']
    labels = ['spam']
    total = {}
    clf = RandomForestClassifier(n_estimators=10, criterion=args.criterion, max_depth=None,\
                                 min_samples_split=2, min_samples_leaf=1, \
                                 max_features='auto', max_leaf_nodes=None,bootstrap=True, oob_score=False, \
                                 n_jobs=-1, random_state=None, verbose=1)
    for label in labels :
        logger.debug('Create dataset for label '+str(label).upper())
        X_train = []
        Y_train = []
        X_test = []
        Y_test = []

        for path in [ os.path.join(args.PATH, subdir) for subdir in labels + ['test','ham']]:
            logger.debug('Open subdir : '+str(path))
            pathes_gen = get_validated_path(path)

            exp_len = None
            while(True):

                try:

                    msg_path = next(pathes_gen)
                    logger.debug(msg_path.upper())
                    x_vector = vectorize(msg_path, label, args.score)
                    if exp_len is None:
                        exp_len = len(x_vector)
                    elif exp_len != len(x_vector):
                        logger.debug('EXP_LEN: '+str(exp_len))
                        logger.debug('VV: '+str(len(x_vector)))
                        logger.debug('PATH: '+msg_path+' - '+label)
                        sys.exit(1)

                    logger.debug('\nx_vector ===> '.upper()+str(x_vector))

                    if os.path.basename(path) == 'test':
                        X_test.append(x_vector)
                        Y_test.append(os.path.basename(msg_path))

                    else:
                        X_train.append(x_vector)
                        y_vector = 0.0
                        if label == os.path.basename(path):
                            y_vector = 1.0

                        Y_train.append(y_vector)

                except StopIteration as err:
                    logger.error(str(err).upper())

                    break

        logger.debug('\n==============================================================\n')
        X_train = tuple(X_train)
        logger.debug('X data array: '+str(X_train))


        Y_train = tuple(Y_train)
        logger.debug('Y data array: '+str(Y_train))
        X_test = tuple(X_test)
        logger.debug('X test array: '+str(X_test))

        #logger.debug('X data: '+str(X_train))
        #logger.debug('Y data: '+str(Y_train))
        #xl = [len(vect) for vect in X_train]
        #yl = len(Y_train)
        #logger.debug('lengtes x: '+str(xl))
        #logger.debug('lengthe x: '+str(len(X_train)))
        #logger.debug('lengthe y: '+str(yl))
        #X_train = np.array(X_train)
        #Y_train = np.array(Y_train)
        #logger.debug(str(X_test))
        #logger.debug(str(Y_test))
        #logger.debug('lengtes x: '+str(len(X_test)))
        #logger.debug('lengthe y: '+str(len(Y_test)))
        #X_test = np.matrix(X_test)
        Y_test = tuple(Y_test)

        logger.debug('Fit classifier for : '+label+' label')
        clf.fit(X_train, Y_train)

        logger.debug('Try to make predictions...')
        z = clf.predict_proba(X_test)
        prediction = clf.predict(X_test)
        logger.debug('ZZZ'+str(z))
        logger.debug(prediction)
        cristal_ball = ((y,x) for y,x in zip(Y_test, clf.predict_proba(X_test)))
        glass_ball = ((y,x) for y,x in zip(Y_test, clf.predict(X_test)))

        logger.debug(str(tuple(glass_ball)))
        total[label] = tuple(cristal_ball)
        logger.debug('>>>>>>>> TOTAL : '+str(total))

    logger.debug('\n'+str(total))









'''
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


'''







