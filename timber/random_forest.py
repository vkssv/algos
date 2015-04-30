#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import sys, os, logging, argparse

from collections import defaultdict
from operator import itemgetter

from pattern_wrapper import BasePattern
from vectorizer import Vectorize
from clf_wrapper import ClfWrapper

from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.grid_search import GridSearchCV

# define some functions
def create_report(predictions_dict, labels):

    report = dict()
    for key, decisions in predictions_dict.iteritems():

        decisions = tuple(sorted(decisions,key= itemgetter(2),reverse=True))[:len(classifiers)]
        #logger.debug('\t'+key+' ===> '+str(decisions)+'\n')
        final = map(itemgetter(0), decisions)
        clf_stat = tuple(clf_name+' : '+str(prob)+' % ('+label+');' for label, clf_name, prob in decisions)

        status = None
        if len(set(final)) == 1:
            status = set(final).pop()

        elif len(set(final)) > 1:
            status, cls_name, prob = decisions[0]

        report[key] = (status, clf_stat)

    return report

def print_report(report):

    logger.info('\n  statuses :\n'.upper())
    for k,v in sorted(report.iteritems(),key=itemgetter(1),reverse=True):
        status, clf_stat = v
        add_info = '\x20\x20'.join(clf_stat)
        logger.info('\t{0:10} {1:3} {2:4} '.format(k, '==>', status)+' :\x20\x20'+add_info+'\n')


if __name__ == "__main__":

    usage = 'usage: %prog [ samples_directory | file ] -c category -s score -v debug'
    parser = argparse.ArgumentParser(prog='helper')
    parser.add_argument('PATH', type=str, metavar = 'PATH',
                            help="path to directory with samples")

    parser.add_argument('--score', type = float, action = 'store', dest = "score", default = 1.0,
                            help = "penalty score for matched feature, def = 1.0")

    parser.add_argument('--k-best', action = 'store', type=int, dest = "k", default = 0,
                            help = "number of best features, preselected by ANOVA regressors set")

    parser.add_argument('--estimators', action = 'store', type=int, dest = "estimators", default = 30,
                            help = "number of trees in classifiers")

    parser.add_argument('--accuracy', type = str, action = "store", dest = "accuracy", default = False,
                            help = "path to file with ground truth to check accuracy")

    #parser.add_argument('--dump', action = "store_true", dest = "dump", default = False,
    #                        help = "dump used datasets in dir with collections (PATH argument)")

    parser.add_argument('--report', action = "store", type = str, dest = "report", default = False,
                            help = "write stdout to file (INFO log level)")

    parser.add_argument('-v', action = "store_true", dest = "verbose", default = False, help = "be verbose")

    args = parser.parse_args()

    # 1. preparations
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
        fh.setLevel(logging.INFO)
        logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)

    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)

    if args.verbose:
        ch.setFormatter(formatter)
        ch.setLevel(logging.DEBUG)

    logger.addHandler(ch)

    # 2. choose best parameters to initialize classifiers
    forest_params_grid = {
                            #'max_depth'         : [1,10,33,None],
                            #'max_features'      : [1,10,33,'auto','sqrt','log2',None],
                            'min_samples_split' : [1, 3, 10],
                            'min_samples_leaf'  : [1, 3, 10],
                            'bootstrap'         : [True, False],
                            'criterion'         : ['gini', 'entropy']
    }

    add_params = list()

    classifiers = [
                    ('Random\x20Forest', RandomForestClassifier, forest_params_grid),
                    ('Extra\x20Trees', ExtraTreesClassifier, forest_params_grid)
    ]

    labels = ['spam','ham','info','nets']
    predicted_probs = defaultdict(list)

    # 3. vectorize emails from collections for each label
    try:

        for label in labels :
            results_for_label = list()
            logger.info('\n\n  Create dataset for '+label.upper()+' class...\n')

            vectorizer = Vectorize(train_dir=args.PATH, label=label, score=args.score)

            features_dict = vectorizer.features_dict

            selected_features = None
            n = None
            if args.k > len(features_dict):
                logger.warn('  k-best='+str(args.k)+' > length X_vector='+str(len(features_dict))+', will use k=\'all\'\n')\

                n = 'all'

            else:
                n = args.k

            if args.k:

                logger.info('  Select '+str(n)+' features with ANOVA F-value regressors set...\n')
                X_train, Y_train, X_test, Y_test = vectorizer.transform(k_best=n)
                selected_features = vectorizer.support()

            else:
                # will use sparse matrixes
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


            # 4. tune classifiers with existing datasets by GridSearchCV
            logger.info('\n  Create classifiers instances...')
            for clf in classifiers:

                clf_name, class_obj, params_dict = clf
                clf_instance = class_obj(n_estimators=args.estimators)

                add_params = [
                                    ('n_jobs',-1),\
                                    ('max_features',None),\
                                    ('max_depth',None),\
                                    ('max_leaf_nodes', None)
                ]

                logger.info('\n\tFind best parameters to initialize '+clf_name.upper()+' ('+label.upper()+' class)...')

                grid_search = GridSearchCV(clf_instance, param_grid=params_dict)
                fit_output = grid_search.fit(X_train, Y_train)
                #logger.debug(str(fit_output))

                params = grid_search.best_params_

                params.update(dict(add_params))

                logger.info('\n\twill use this parameters set:\n')
                for k,value in params.iteritems():
                    logger.info('\t\t{0:20} {1:3} {2:5}'.format(k, '=', str(value)))

                # 5. fit classifiers and perform forecasting...
                clf_instance = class_obj(**params)
                logger.debug('\n\t'+clf_name.upper()+' classifier was successfully constructed.')

                logger.debug('\n\tFit '+clf_name.upper()+' with '+label.upper()+' data...\n')
                clf_instance.fit(X_train, Y_train)
                wrapped_clf = ClfWrapper(clf_name, clf_instance, label)

                #logger.debug(str(type(X_test)))
                #logger.debug(str(type(Y_test)))
                logger.debug('\tMake predictions...\n')
                probs_dict, predics_vect, probs, classes = wrapped_clf.predict(X_test, Y_test)

                [ predicted_probs[name].append((label.upper(), clf_name, probability)) for name, probability in probs_dict.iteritems() ]

                # 6. logger.info results and some classifiers objects statistics
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

        # 7. to sum up final decisions
        report = create_report(predicted_probs, labels)
        print_report(report)

    except Exception as err:
        logger.error(str(err))
        sys.exit(1)











