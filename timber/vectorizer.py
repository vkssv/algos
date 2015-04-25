#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

"""
-- can be imported as submodule to build feature vectors for e,


-- returns NxM matrix --> N samples from collection x M features +label value
( or "test" label if not defined ) in numpy array type
"""

import sys, os, logging, re, email, argparse, stat, tempfile, math, time
import numpy as np

from email.parser import Parser
from collections import defaultdict, OrderedDict
from operator import itemgetter

from timber_exceptions import NaturesError
from franks_factory import MetaFrankenstein


logger = logging.getLogger('')
#logger.setLevel(logging.WARN)

class Vectorizer(object):
    '''
    Build matrix MxN matrix :
        N samples in collection dir x M features,
        defined by amount of rules in appropriate
        pattern ;

    Appropriate pattern class :
        chosed according passed label value,
        supported patterns are : spam, ham, nets,
        infos ;
    '''
    SUPPORTED_CLASSES = ['spam','ham']

    def __init__(self, train_dir, label, score):

        if label in self.SUPPORTED_CLASSES:

            self.train_dir = train_dir
            self.label = label
            self.penalty = score
            logger.debug('Train dir : '+str(self.train_dir).upper())
            logger.debug('Current class : '+str(self.label).upper())
            logger.debug('Penalty score : '+str(self.penalty))

        else:
            raise Exception('Don\'t have any module with rules for '+label.upper()+' class.')

    def __get_path(self, path):

        checks = {
                    stat.S_IFREG : lambda fd: os.stat(fd).st_size,
                    stat.S_IFDIR : lambda d: os.listdir(d)
        }

        mode = filter(lambda key: os.stat(path).st_mode & key, checks.keys())
        logger.debug('file mode: '+str(mode))
        f = checks.get(*mode)
        if not f(path):
            logger.error('Collection dir : "'+path + '" is empty.')
            sys.exit(1)

        msg_path = path
        if mode[0] == stat.S_IFREG:
            logger.debug(msg_path)
            yield msg_path

        elif mode[0] == stat.S_IFDIR:
            for p, subdir, docs in os.walk(path):
                for d in docs:
                    msg_path = os.path.join(p,d)
                    yield msg_path

    def __vectorize(self, doc_path):

        logger.debug('\n\nStart vectorizing "'+doc_path+'" by '+self.label.upper()+' pattern...')

        parser = Parser()
        with open(doc_path, 'rb') as f:
            M = parser.parse(f)

        Frankenstein_cls = MetaFrankenstein.New(self.label)
        logger.debug('\n\n\t CHECK : ' +doc_path+'\n')

        pattern_instance = Frankenstein_cls(msg=M, score=self.penalty)
        vector = pattern_instance.__dict__
        vector.pop('PENALTY_SCORE')
        vector['msg_size'] = math.ceil(float((os.stat(doc_path).st_size)/1024))
        logger.debug('\n\tunsorted X_vector ==> '+str(vector))
        vector = tuple(sorted([(k.upper(),value) for k,value in vector.items()],key=itemgetter(0)))
        logger.debug('\n\tX_vector ==> '+str(vector))

        logger.debug('TEST >>>>'+str(dict(enumerate(map(itemgetter(0),vector)))))
        self.features_dict = dict(enumerate(tuple(map(itemgetter(0),vector))))
        logger.debug('TEST >>>>'+str(self.features_dict))

        msg_vector = tuple(map(itemgetter(1),vector))
        logger.debug('\nVECTOR ===> '+str(msg_vector)+'\n')

        return msg_vector

    def __normalize(self):

        pass

    def __cross_validation(self):
        pass

    def get_dataset(self):
        logger.debug('in dataset')
        X_train = list()
        Y_train = list()
        X_test = list()
        Y_test = list()

        for path in [ os.path.join(self.train_dir, subdir) for subdir in self.SUPPORTED_CLASSES+['test'] ]:
            logger.debug('Open collection subdir : '+path)
            pathes_gen = self.__get_path(path)
            logger.debug(list(pathes_gen))
            pathes_gen = self.__get_path(path)
            expected_len = None
            msg_path = ''
            while(True):

                try:
                    msg_path = next(pathes_gen)
                    logger.debug('PATH: '+(msg_path.upper()))

                    x_vector = self.__vectorize(msg_path)
                    logger.debug('\nx_vector ===> '.upper()+str(x_vector))

                    if expected_len is None:
                        expected_len = len(x_vector)

                    elif expected_len != len(x_vector):
                        logger.error('EXP_LEN: '+str(expected_len))
                        logger.error('VV: '+str(len(x_vector)))
                        logger.error('PATH: '+msg_path)
                        raise NaturesError('Vectors have different dimentions !')

                    y_vector = None

                    if os.path.basename(path) == 'test':

                        X_test.append(x_vector)
                        y_vector = os.path.basename(msg_path)
                        Y_test.append(y_vector)

                    else:

                        X_train.append(x_vector)
                        logger.debug('+++++++label :'+str(self.label))
                        logger.debug('+++++++path :'+str(os.path.basename(msg_path)))

                        if self.label == os.path.basename(path):
                            y_vector = 1.0

                        else:
                            y_vector = 0.0

                        Y_train.append(y_vector)

                except StopIteration as err:

                    logger.debug(str(X_train))
                    logger.debug(str(Y_train))
                    break

                except Exception as err:
                    logger.error('Can\'t extract features from "'+msg_path+'", so it will be skipped.')
                    logger.error(str(err))
                    raise
                    #pass

        f = lambda x: tuple(x)
        pack_to_tuples = (f(x) for x in (X_train, Y_train, X_test, Y_test))

        return tuple(pack_to_tuples)