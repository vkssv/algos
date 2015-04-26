#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import sys, os, logging, re, argparse, stat, tempfile, math, time
import numpy as np

from email.parser import Parser
from collections import defaultdict
from operator import itemgetter

from franks_factory import MetaFrankenstein
from pattern_wrapper import BasePattern
from vectorizer import Vectorize
from clf_wrapper import ClfWrapper
from timber_exceptions import NaturesError

from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn import svm
from sklearn.grid_search import GridSearchCV

import numpy as np
import matplotlib.pyplot as plt

# define some functions

def create_report(predictions_dict, labels):

    report = dict()
    for key, decisions in predictions_dict.iteritems():
        logger.info('\t'+key+' ==> '+str(decisions)+'\n')
        decisions = tuple(sorted(decisions,key= itemgetter(2),reverse=True))[:len(classifiers)]
        logger.info('\t sort '+key+' ===> '+str(decisions)+'\n')
        final = map(itemgetter(0), decisions)
        clf_stat = tuple(clf_name+' : '+str(prob)+' % ('+label+');' for label, clf_name, prob in decisions)
        status = None
        logger.info('final '+str(final))
        if len(set(final)) == 1:
            status = set(final).pop()

        elif len(set(final)) == 2:
            status = [i for i in final if final.count(i)==2].pop()

        elif len(set(final)) == 3:
            status, cls_name, prob = decisions[0]

        report[key] = (status,  clf_stat )



    return report


if __name__ == "__main__":

    usage = 'usage: %prog [ samples_directory | file ] -c category -s score -v debug'
    parser = argparse.ArgumentParser(prog='helper')
    parser.add_argument('PATH', type=str, metavar = 'PATH',
                            help="path to dir with collections")

    parser.add_argument('-s', type = float,  action = 'store', dest = "score", default = 1.0,
                            help = "penalty score for matched feature, def = 1.0")

    #parser.add_argument('--forest-args',action = 'store', type=list, dest = "forest_args_dict", default = None,
    #                        help = "list of forest classifier arguments")

    parser.add_argument('--estimators',action = 'store', type=int, dest = "estimators", default = 20,
                            help = "number of trees in forests")

    parser.add_argument('--accuracy', type = str, action = "store", dest = "accuracy_path", default = False,
                            help = "path to file with ground truth to estimate accuracy")

    #parser.add_argument('--graph', action = "store_true", dest = "graph", default = False,
    #                        help = "plot feature impotances graph")
    parser.add_argument('--dump', action = "store_true", dest = "dump", default = False,
                            help = "dump used datasets in dir with collections (PATH argument)")

    #parser.add_argument('--report', action = "store", dest = "report", default = False,
    #                        help = "dump estimated email statuses into file")

    parser.add_argument('-v', action = "store_true", dest = "verbose", default = False,
                            help = "be verbose")

    args = parser.parse_args()

    # 1. preparations
    required_vers = '2.7'
    version = str(sys.version_info.major)+'.'+str(sys.version_info.minor)
    if version != required_vers:
        sys.stderr.write( '[%s] - Error: Your Python interpreter must be %d.%d\n' % (sys.argv[0], major, minor))
        sys.exit(-1)

    logger = logging.getLogger('')
    formatter = logging.Formatter('%(levelname)s: %(filename)s: %(funcName)s: %(message)s')
    ch = logging.StreamHandler(sys.stdout)
    fh = logging.FileHandler(os.path.join(tempfile.gettempdir(), time.strftime("%d%m%y_%H%M%S", time.gmtime())+'.log'), mode = 'w')
    logger.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(ch)

    sk_learn_verbosity = 0
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        sk_learn_verbosity = 1

    # 2. choose best parameters to initialize classifiers
    print('\n\x20 Create classifiers instances...')

    forest_params_grid = {
                            #'max_depth'         : [1,10,33,None],
                            #'max_features'      : [1,10,33,'auto','sqrt','log2',None],
                            'min_samples_split' : [1, 3, 10],
                            'min_samples_leaf'  : [1, 3, 10],
                            'bootstrap'         : [True, False],
                            'criterion'         : ['gini', 'entropy']
    }

    svm_params_grid =  {'C': [1, 10, 100, 1000]}
    add_params = list()

    classifiers = [
                    ('Random\x20Forest', RandomForestClassifier, forest_params_grid),
                    ('Extra\x20Trees', ExtraTreesClassifier, forest_params_grid),
                    ('SVM', svm.SVC, svm_params_grid)
    ]

    labels = ['spam','ham']
    #labels = ['spam']

    predicted_probs = defaultdict(list)

    # 3. vectorize emails for each label in that way
    # as we have one-class classification problem
    for label in labels :

        print('\n\x20 Try to create dataset for '+label.upper()+' class...')

        vectorizer = Vectorize(train_dir=args.PATH, label=label, score=args.score)
        X_train, Y_train, X_test, Y_test = vectorizer.load_data()

        features_dict = vectorizer.features_dict

        logger.info('\n\t\tX_train :'+str(X_train))
        logger.info('\n\t\tY_train :'+str(Y_train))
        logger.info('\n\t\tX_test :'+str(X_test)+'\n')
        logger.info('\n\t\tY_test :'+str(Y_test)+'\n')
        logger.info('\n\t\tfeatures_dict :'+str(features_dict)+'\n')
        print('\t---> train and test datasets were successfully created.')
        if args.dump:
            vectorizer.dump_dataset(to_file=True)
            print('\t---> train and test datasets were successfully exported into '+args.PATH+'.')

        # 4. train classifiers instances and perform forecasting...
        results = dict

        for clf in classifiers:
            clf_name, class_obj, params_dict = clf
            clf_instance = None

            print('\n\x20 Try to find best parameters to initialize '+clf_name.upper()+' for '+label.upper()+' class...')

            if clf_name in ['Random\x20Forest', 'Extra\x20Trees']:
                clf_instance = class_obj(n_estimators=args.estimators)
                add_params = [
                                ('n_jobs',-1),\
                                ('verbose', sk_learn_verbosity),\
                                ('max_features',None),\
                                ('max_depth',None),\
                                ('max_leaf_nodes', None)
                ]
            else:
                clf_instance = class_obj()
                add_params = [('kernel', 'linear'), ('cache_size', 200), ('max_iter',-1), ('probability',True), ('verbose', sk_learn_verbosity)]

            grid_search = GridSearchCV(clf_instance, param_grid=params_dict)
            fit_output = grid_search.fit(X_train, Y_train)
            logger.info(str(fit_output))

            params = grid_search.best_params_
            logger.info('best_params : '.upper()+str(params))

            params.update(dict(add_params))
            print('\n\t---> will use parameters set:')
            for k,value in params.iteritems():
                print('\t{0:20} {1:3} {2:5}'.format(k, '=', str(value)))

            clf_instance = class_obj(**params)
            print('\n\t --> '+clf_name.upper()+' was successfully constructed.')

            print('\n\t Fit them with '+label.upper()+' data...\n')
            clf_instance.fit(X_train, Y_train)
            wrapped_clf = ClfWrapper(clf_name, clf_instance, label)

            logger.debug(str(type(X_test)))
            logger.debug(str(type(Y_test)))
            print('\n\x20 Try to make predictions...\n')
            probs_dict, predics_vect, probs, classes = wrapped_clf.predict(X_test, Y_test)
            logger.debug('+++PROBS '+str(probs))
            logger.debug('+++CLASSES '+str(classes))

            [ predicted_probs[name].append((label.upper(), clf_name, probability)) for name, probability in probs_dict.iteritems() ]

            # 5. print results and some classifiers objects statistics
            recipe = wrapped_clf.get_recipe(features_dict)

            print('\n\x20 '+clf_name.upper()+' results for '+label.upper()+' categorizing :\n')
            print('\x20\x20 --> Probabilities for '+label.upper()+' pattern : \n')
            verdict = ''

            for email, prediction in predics_vect:

                if prediction.item() == 1.0:
                    verdict = label.upper()
                else:
                    verdict = 'NON '+label.upper()

                print('\t{0:10} {1:3} {2:9} {3:4} {4:4}'.format(email, '==>', verdict, probs_dict[email], prediction))

            print('\n\x20\x20 --> Top 10 features : \n')
            for f_name, importance in recipe:
                print('\t{0:35} {1:3} {2:5}'.format(f_name, '==>', importance))

            if args.accuracy_path:
                print('\n\x20\x20 --> Accuracy :\n')
                print('\x20\x20'+wrapped_clf.get_accuracy_report(args.accuracy_path))

            # 6. quelques photos pour bien souvenir
            #if args.graph:
            #    print(42)

    # 7. sum up final decisions

    report = create_report(predicted_probs, labels)

    print('\n\x20 statuses :\n'.upper())
    for k,v in sorted(report.iteritems(),key=itemgetter(1),reverse=True):
        status, clf_stat = v
        add_info = '\x20\x20'.join(clf_stat)
        print('\t{0:10} {1:3} {2:4} '.format(k, '==>', status)+' :\x20\x20'+add_info+'\n')










