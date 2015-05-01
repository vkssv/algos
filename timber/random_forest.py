#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import sys, os, logging, argparse

from collections import defaultdict
from operator import itemgetter

from pattern_wrapper import BasePattern
from vectorizer import Vectorize
from clf_wrapper import ClfWrapper

from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier

from sklearn.preprocessing import normalize
from sklearn import svm

CLASS_TENANCY_THRESHOLD = 0.30

# define some functions
def create_report(predictions_dict, labels):

    total = []
    for key, decisions in predictions_dict.iteritems():

        #logger.debug('\t'+key+' ===> '+str(tuple(sorted(decisions,key= itemgetter(2),reverse=True))))
        ham_probs = [(status, cls, p) for status, cls, p in decisions if p < CLASS_TENANCY_THRESHOLD ]

        if len(ham_probs) == len(decisions):

            ham_probs = tuple(sorted(ham_probs,key= itemgetter(2),reverse=True))[:len(classifiers)]
            clf_stat = tuple(clf_name+' : '+str(prob)+' % ('+label+' pattern) ;' for label, clf_name, prob in ham_probs)
            status = 'HAM'

        else:
            decisions = tuple(sorted(decisions,key= itemgetter(2),reverse=True))[:len(classifiers)]
            clf_stat = tuple(clf_name+' : '+str(prob)+' % ('+label+' pattern) ;' for label, clf_name, prob in decisions)

            final = map(itemgetter(0), decisions)
            status = None
            #logger.debug(final)
            if len(set(final)) == 1:
                status = set(final).pop()

            elif len(set(final)) > 1:
                status, cls_name, prob = decisions[0]

        total.append((key, status, '\x20\x20'.join(clf_stat)))

    logger.info('statuses : \n'.upper())
    for k, status, add_info in sorted(total, key=itemgetter(1), reverse=True):
        logger.info('\t{0:10} {1:3} {2:4} '.format(k, '==>', status)+' :'+add_info+'\n')



if __name__ == "__main__":

    usage = 'usage: %prog [ samples_directory | file ] -c category -s score -v debug'
    parser = argparse.ArgumentParser(prog='random_forest')

    parser.add_argument('PATH', type=str, metavar = 'PATH',
                            help="path to directory with samples")

    parser.add_argument('--score', type = float, metavar = ' ', action = 'store', dest = "score", default = 1.0,
                            help = "penalty score for matched feature, default = 1.0")

    parser.add_argument('--k-best', action = 'store', metavar = ' ', type=int, dest = "k", default = 0,
                            help = "number of best features, preselected by ANOVA F-value regressors set, default = 0")

    parser.add_argument('--estimators', action = 'store', metavar = ' ', type=int, dest = "estimators", default = 20,
                            help = "number of trees in classifiers, default = 20")

    parser.add_argument('--accuracy', type = str, action = "store", metavar = ' ', dest = "accuracy", default = False,
                            help = "path to file with verified statuses for checking accuracy")

    #parser.add_argument('--dump', action = "store_true", dest = "dump", default = False,
    #                        help = "dump used datasets in dir with collections (PATH argument)")

    parser.add_argument('--criterion', type = str, action = "store", metavar = ' ', dest = 'criterion', default = 'gini',
                            help = 'function to measure the quality of a split, default="gini"')

    #parser.add_argument('--dump', action = "store_true", dest = "dump", default = False,
    #                        help = "dump used datasets in dir with collections (PATH argument)")

    parser.add_argument('--report', action = "store", type = str, metavar = ' ', dest = "report", default = False,
                            help = "path to file for dumping results")

    parser.add_argument('-v', action = "store_true", dest = "verbose", default = False, help = "be verbose")

    args = parser.parse_args()

    # preparations
    required_vers = '2.7'
    version = str(sys.version_info.major)+'.'+str(sys.version_info.minor)
    if version != required_vers:
        sys.stderr.write( '[%s] - Error: Your Python interpreter must be %d.%d\n' % (sys.argv[0], major, minor))
        sys.exit(-1)

    logger = logging.getLogger('')
    formatter = logging.Formatter('%(message)s')
    logger.setLevel(logging.DEBUG)

    if args.report:
        fh = logging.FileHandler(args.report, mode = 'wb')
        fh.setFormatter(formatter)
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)

    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)

    if args.verbose:
        ch.setFormatter(formatter)
        ch.setLevel(logging.DEBUG)

    logger.addHandler(ch)

    add_params = list()
    classifiers = [
                    ('Random\x20Forest', RandomForestClassifier),\
                    ('Extra\x20Trees', ExtraTreesClassifier)
    ]

    labels = ['spam','ham','info','nets']
    predicted_probs = defaultdict(list)

    # vectorize emails from collections for each label
    try:

        for label in labels :
            results_for_label = list()
            logger.info('\n\n  Create dataset for '+label.upper()+' class...\n')

            vectorizer = Vectorize(train_dir=args.PATH, label=label, score=args.score)

            features_dict = vectorizer.features_dict

            selected_features = None
            n = None
            if args.k > len(features_dict):
                logger.warn('  k-best='+str(args.k)+' > length X_vector='+str(len(features_dict))+', will use k=\'all\'\n')
                n = 'all'

            else:
                n = args.k

            if args.k:

                logger.info('  Select '+str(n)+' features with ANOVA F-value regressors set...\n')
                X_train, Y_train, X_test, Y_test = vectorizer.transform(k_best=n)
                selected_features = vectorizer.support()

            else:
                # will use sparse matrices
                X_train, Y_train, X_test, Y_test = vectorizer.load_data()

            logger.info('\tFeatures set :\n')

            if selected_features is not None:
                for k,name in selected_features.iteritems():
                    logger.info('\t\t'+str(k)+'. '+name)
            else:
                for k,name in features_dict.iteritems():
                    logger.info('\t\t'+str(k)+'. '+name)

            #if args.dump:
            #    vectorizer.dump_dataset(to_file=True)
            #    logger.info('\t---> train and test datasets were successfully exported into '+args.PATH+'.')

            logger.info('\n  Create classifiers instances...')
            for clf in classifiers:
                clf_name, class_obj = clf

                params = {
                                'n_estimators'      : args.estimators,
                                'criterion'         : args.criterion,
                                'max_depth'         : None,
                                'max_features'      : 'auto',
                                'n_jobs'            : -1,
                                'class_weight'      :'auto',
                                'min_samples_split' : 1

                }

                logger.info('\n\twill use this parameters set:\n')
                for k,value in params.iteritems():
                    logger.info('\t\t{0:20} {1:3} {2:5}'.format(k, '=', str(value)))

                # fit classifiers and perform forecasting...
                clf_instance = class_obj(n_estimators=args.estimators, criterion=args.criterion, max_depth=None,\
                                         max_features='auto', n_jobs=-1, class_weight='auto', min_samples_split=1 )

                logger.debug('\n\t'+clf_name.upper()+' classifier was successfully constructed.')

                logger.debug('\n\tFit '+clf_name.upper()+' with '+label.upper()+' data...\n')
                X_train = normalize(X_train)
                X_test = normalize(X_test)

                clf_instance.fit(X_train, Y_train)
                wrapped_clf = ClfWrapper(clf_name, clf_instance, label)

                #logger.debug(str(type(X_test)))
                #logger.debug(str(type(Y_test)))
                logger.debug('\tMake predictions...\n')
                probs_dict, predics_vect, probs, classes = wrapped_clf.predict(X_test, Y_test)

                [ predicted_probs[name].append((label.upper(), clf_name, probability)) for name, probability in probs_dict.iteritems() ]

                # obtain features dictionary for current Pattern class and gain some classifiers statistics
                recipe = wrapped_clf.get_recipe(features_dict)

                logger.info('\n\t'+clf_name.upper()+' probabilities ('+label.upper()+' class) :\n')

                verdict = ''
                for email, prediction in predics_vect:

                    if prediction.item() == 1.0:
                        verdict = label.upper()
                    else:
                        verdict = 'NON '+label.upper()

                    report_line = '\t\t{0:10} {1:3} {2:9} {3:4} {4:4}'.format(email, '==>', verdict, probs_dict[email], prediction)
                    logger.info(report_line)

                logger.info('\n\tTop 10 features, selected by '+clf_name.upper()+' ('+label.upper()+' class) :\n')
                for f_name, importance in recipe:
                    logger.info('\t\t{0:35} {1:3} {2:5}'.format(f_name, '==>', importance))

                if args.accuracy:
                    logger.info('\n\tAccuracy :\n')
                    logger.info('  '+wrapped_clf.get_accuracy_report(args.accuracy))

        # to sum up final decisions
        create_report(predicted_probs, labels)

    except Exception as err:
        logger.error(str(err))
        sys.exit(1)











