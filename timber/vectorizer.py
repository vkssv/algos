#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-


import sys, os, logging, re, email, argparse, stat, tempfile, math, time
import numpy as np

from email.parser import Parser
from collections import defaultdict, OrderedDict
from operator import itemgetter

from timber_exceptions import NaturesError
from franks_factory import MetaFrankenstein


logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

class Vectorizer(object):
    '''
    '''

    def __init__(self, path, label, score):

        checks = {
                    stat.S_IFREG : lambda fd: os.stat(fd).st_size,
                    stat.S_IFDIR : lambda d: os.listdir(d)
        }

        self.mode = filter(lambda key: os.stat(path).st_mode & key, checks.keys())
        logger.debug('file mode: '+str(self.mode))
        f = checks.get(*self.mode)
        if not f(path):
            logger.error('Collection dir : "'+path + '" is empty.')
            sys.exit(1)

        self.path = path
        self.label = label
        self.penalty = score

        logger.debug('Current path : '+str(self.path).upper())
        logger.debug('Current class : '+str(self.label).upper())
        logger.debug('Penalty score : '+str(self.penalty))

    def __get_path(self):

        msg_path = self.path
        if self.mode[0] == stat.S_IFREG:
            logger.debug(msg_path)
            yield msg_path

        elif self.mode[0] == stat.S_IFDIR:
            for p, subdir, docs in os.walk(self.path):
                for d in docs:
                    msg_path = os.path.join(p,d)
                    yield msg_path

    def __vectorize(self, doc_path):

        logger.debug('\n\nStart vectorizing "'+doc_path+'" from '+self.label.upper()+' set...')

        parser = Parser()
        with open(doc_path, 'rb') as f:
            M = parser.parse(f)

        Frankenstein_cls = MetaFrankenstein.New(self.label)
        logger.debug('Frankenstein_cls :'+str(type(Frankenstein_cls)))
        logger.debug('Frankenstein_cls :'+str(Frankenstein_cls))
        logger.debug('\n\n\t CHECK : ' +doc_path+'\n')
        #logger.debug('DNA: '+str(Frankenstein_cls.__dict__))
        pattern_instance = Frankenstein_cls(msg=M, score=self.penalty)
        vector = pattern_instance.__dict__
        vector.pop('PENALTY_SCORE')
        vector['msg_size'] = math.ceil(float((os.stat(doc_path).st_size)/1024))
        vector = tuple((k.upper(),value) for k,value in sorted(vector.items()))

        logger.debug('\n\tCurrent Frankenstein ==> '+str(vector))
        msg_vector = tuple(map(itemgetter(1),vector))


        logger.debug('\nVECTOR ===> '+str(msg_vector)+'\n')
        return msg_vector

    def __normalize(self,vect_dict):

        pass

    def get_dataset(self):

        logger.debug('Open subdir : '+str(self.path))
        pathes_gen = self.__get_path()

        X = []
        Y = []

        expected_len = None
        msg_path = ''
        while(True):

            try:

                msg_path = next(pathes_gen)
                logger.debug('PATH: '+(msg_path.upper()))

                x_vector = self.__vectorize(msg_path)
                logger.debug('\nx_vector ===> '+str(x_vector))
                logger.debug('\nx_vector ===> '.upper()+str(x_vector))

                if expected_len is None:
                    expected_len = len(x_vector)

                elif expected_len != len(x_vector):
                    logger.error('EXP_LEN: '+str(exp_len))
                    logger.error('VV: '+str(len(x_vector)))
                    logger.error('PATH: '+msg_path+' - '+label)
                    raise NaturesError('Vectors have different dimentions !')

                X.append(x_vector)

                y_vector = 0.0
                if os.path.basename(self.path) == 'test':
                    y_vector = os.path.basename(msg_path)

                elif self.label == os.path.basename(self.path):
                    y_vector = 1.0

                Y.append(y_vector)

            except StopIteration as err:
                logger.error(str(err).upper())
                break

            except Exception as err:
                logger.error('Can\'t extract features from "'+msg_path+'", so it will be skipped.')
                logger.error(str(err))
                raise
                #pass

        return tuple(X), tuple(Y)