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

class ClfWrapper(object):
    '''
        Just wrap up SKlearn classifier object and its methods
        to incapsulate all routines and make the code of obtaining
        result report more understandable
    '''

    def __init__(self, clf_name, fitted_clf, label):

        self.clf_name = clf_name
        self.obj = fitted_clf
        self.label = label

    def predict(self, X_test, Y_test):
        """
        Those who lives by the crystal ball must
        sooner or later learn to chew glass...
        and to swallow nails of its Destiny...
        """

        logger.info('\n\n\t Try to make predictions...\n')
        self.probs = [(name, probability) for name, probability in zip(Y_test, self.obj.predict_proba(X_test))]
        self.crystal_ball = [(name, probability[1]) for name, probability in zip(Y_test, self.obj.predict_proba(X_test))]
        self.glass_ball = [(name, probability) for name, probability in zip(Y_test, self.obj.predict(X_test))]
        self.classes = self.obj.classes_
        return self.crystal_ball, self.glass_ball, self.probs, self.classes

    def get_recipe(self):

        importances = list()

        if self.clf_name == 'SVM':
            self.importances = self.obj.coef_
        else:
            self.importances = self.obj.feature_importances_

        indixes = np.argsort(self.importances)[::-1]
        logger.debug("Feature ranking:")

        #for f in range(10):
        #    logger.debug("%d. feature %d (%f)" % (f + 1, indixes[f], importances[indixes[f]]))

        logger.debug('IMPOTANCES '+str(self.importances))

        return self.importances

    def get_accuracy(self, path_to_ground_truth):

        self.accuracy = 0.0
        expected_values = dict()
        try:
            with open(path_to_ground_truth,'rb') as truth:

                while(True):
                    l = next(truth)
                    l = l.strip()
                    if l is None:
                        break

                    if l.startswith('#'):
                        continue

                    name, class_label = (l.split(':'))
                    expected_values[name.strip()] = 0
                    if class_label.strip().upper() == self.label:
                        expected_values[name.strip()] = 1


        except StopIteration as err:
            pass

        except Exception as err:
            logger.error('Can\'t parse "'+path_to_ground_truth+'" !')
            return self.accuracy

        if not expected_values:
            logger.error('Can\'t parse "'+path_to_ground_truth+'" !')
            return self.accuracy

        truth_vector = tuple(map(itemgetter(1), tuple(sorted(expected_values, key=itemgetter(0)))))
        predicted_vector = tuple(map(itemgetter(1), tuple(sorted(self.glass_ball, key=itemgetter(0)))))

        self.accuracy = accuracy_score(truth_vector, predicted_vector)
        return self.accuracy