#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import logging
from operator import itemgetter

import numpy as np
from sklearn.metrics import classification_report, precision_recall_curve


logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

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

        self.probs = [(name, probability) for name, probability in zip(Y_test, self.obj.predict_proba(X_test))]
        self.crystal_ball = [(name, probability[1]) for name, probability in zip(Y_test, self.obj.predict_proba(X_test))]
        self.crystal_ball = dict((name,round(p,5)) for name, p in self.crystal_ball)
        self.glass_ball = [(name, probability) for name, probability in zip(Y_test, self.obj.predict(X_test))]
        self.classes = self.obj.classes_
        return self.crystal_ball, self.glass_ball, self.probs, self.classes

    def get_recipe(self, featues_dict):

        importances = self.obj.feature_importances_
        features_indexes = np.argsort(importances)[::-1]
        ranged_features = list()

        f = lambda x: round(x,3)
        for index in features_indexes[:10]:
            #logger.debug('{0:35} {1:3} {2:5}'.format(featues_dict[index], '==>', round(importances[index],3)))
            ranged_features.append((featues_dict[index], f(importances[index])))

        return tuple(ranged_features)

    def get_accuracy_report(self, path_to_ground_truth):

        clf_report = ''
        expected_values = list()

        try:
            with open(path_to_ground_truth,'rb') as truth_lines:

                while(True):
                    l = next(truth_lines).strip()

                    if l.startswith('#') or len(l)==0:
                        continue

                    name, class_label = l.split(':')

                    if class_label.strip().upper() == self.label.upper():
                        expected_values.append((name.strip(),1.0))
                        
                    else:
                        expected_values.append((name.strip(),0.0))
                        
        except StopIteration as err:
            pass

        except Exception as err:
            logger.error('Can\'t parse "'+path_to_ground_truth+'" !')
            logger.debug(err)
            return clf_report

        if not expected_values:
            logger.debug(err)
            logger.error('Can\'t parse "'+path_to_ground_truth+'" !')
            return clf_report

        target_map = {
                        0.0 :   'NON '+self.label,
                        1.0 :    self.label
        }

        #logger.debug(self.obj.classes_)
        target_names = tuple((target_map[key]).upper() for key in tuple(self.obj.classes_))
        #logger.debug('cls: '.upper()+str(target_names))

        truth_vector = tuple(map(itemgetter(1), sorted(expected_values, key=itemgetter(0))))

        predicted_vector = tuple(map(itemgetter(1), sorted(self.glass_ball, key=itemgetter(0))))
        #logger.debug('probabilities '+str(predicted_vector))
        
        clf_report = classification_report(truth_vector, predicted_vector, target_names=target_names)
        #logger.debug(clf_report)
        self.precision, self.recall, self.thresholds = precision_recall_curve(truth_vector, predicted_vector, pos_label=self.label.upper)

        return clf_report