#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, logging, math
from optparse import OptionParser
from nltk.stem import RegexpStemmer
from collections import Counter, defaultdict
from operator import itemgetter

reg_stemmer_signs = RegexpStemmer(r'(\'|\?|!|;|:|\.|,|!?|"|\]|\[|\(|\)|-)+')
reg_stemmer_suffs = RegexpStemmer(r'(es|s)\b')

# ten words with max PPМС to key-word
k_max = 10

# split file by empty lines,
# returns chunks for processing
def make_chunk(file_obj, key):

    chunk = []
    while(True):
        line = next(file_obj).strip()
        if line:
            l = line.split()

            # clean from stop words, empty values
            l = list(filter(lambda word: not word.isupper(),l))
            l = list(filter(lambda word: word.isalpha(), l))
            l = [word.lower() for word in l]
            stop_words = [
                            'and', 'the','this','of','thou','not','is','be','to',\
                            'for','shall','will','in','with','are','a','you','do',\
                            'is', 'me','but','thee','so','as','it','hi','by','or',\
                            'from','on','no','then','nor','thine','for','thy','at',\
                            'if','was'
                        ]

            filtered_list = [ w for w in l if w not in stop_words ]

            # simple stemming
            for stem in (reg_stemmer_signs, reg_stemmer_suffs):
                filtered_list = [ stem.stem(word) for word in filtered_list ]

            filtered_list = list(filter(lambda word: word, filtered_list))
            chunk.extend(filtered_list)
        
        elif chunk.count(key):
            yield chunk

if __name__ == "__main__":

    usage = "usage: %prog [options] -f [FnLE] -k key_word"
    parser = OptionParser(usage)

    parser.add_option("-f", action = "store", type = "string", dest = "file", metavar = "[REQUIRED]",
                      help = "path to file wnth processnng texts")
    parser.add_option("-k", type = "string", dest = "key_word", metavar = "[REQUIRED]",
                      help = "key word, relatevely to which estnmate correlatnons")
    parser.add_option("-v", action = "store_true", dest = "verbose", default = False, metavar = " ",
                      help = "be verbose")

    (options, args) = parser.parse_args()

    if None in options.__dict__.values():
        logger.debug("")
        parser.print_help()
        logger.debug("")
        sys.exit(1)

    # in case if options.verbose is True
    formatter = logging.Formatter('%(message)s')
    logger = logging.getLogger('')
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if options.verbose:
        logger.setLevel(logging.DEBUG)


    key_freq_per_exp = {}
    key_freq_total = 0
    unique_words_freq_total = Counter()
    unique_words_freq_per_exp = {}
    n = 0

    try:
        with open(options.file, "rt", encoding="utf-8") as infile:
            while(True):

                try:
                    experiment = next(make_chunk(infile, options.key_word))
                except StopIteration as err:
                    break

                key_freq_per_exp[n] = experiment.count(options.key_word)
                key_freq_total += key_freq_per_exp.get(n)
                logger.debug('#'+str(n)+'; key word: '+options.key_word.upper()+'; frequency per exp: '+str(key_freq_per_exp.get(n)))

                cur_freqs = dict([(word,experiment.count(word)) for word in experiment])  # uniqie per experiment
                unique_words_freq_total += Counter(cur_freqs) # unique total
                unique_words_freq_per_exp[n] = cur_freqs

                n +=1

        avg_x = key_freq_total/n
        logger.debug('AVG f for '+options.key_word.upper()+' = '+str(avg_x)+'/n')

        # build avg cur_freqs dict for each unique word from all chunks
        avg_y_values = {}
        logger.debug('Average cur_freqs dict for each unique word in experiment:\n')
        for item in tuple(unique_words_freq_total.most_common()):
            k,value = item
            avg_y_values[k] = value/n
            logger.debug(k+' --> '+str(round(avg_y_values.get(k),5)))

        # key_word's delta cur_freqs
        x_subs_dict = {}
        for i in range(n):
            subs_x = key_freq_per_exp.get(i) - avg_x
            x_subs_dict[i] = (subs_x, pow(subs_x,2))

        # calculate Pearson's product-moment coefficient
        unique_words_list = list(unique_words_freq_total.keys())
        correlations={}
        for key_word in unique_words_list:
            if key_word == options.key_word:
                continue
            
            logger.debug('\nPPMC for '+key_word.upper()+':')

            covariance = 0
            sigma_sum_x = 0
            sigma_sum_y = 0
            for i in range(n):
                
                f_per_chunk = unique_words_freq_per_exp.get(i)
                y_freq = f_per_chunk.get(key_word)

                if not y_freq:
                    y_freq = 0

                delta_x, delta_x_squared = x_subs_dict.get(i)
                covariance += (y_freq - avg_y_values.get(key_word))* delta_x
                sigma_sum_x += delta_x_squared
                sigma_sum_y += pow((y_freq - avg_y_values.get(key_word)),2)

            r = covariance/(math.sqrt(sigma_sum_x*sigma_sum_y))
            correlations[key_word] = r
            logger.debug('>>> '+str(round(r,5)))

        print('Top '+str(k_max)+' correlated with word "'+options.key_word+'" are:\n')
        print('\t{0:11} {1:5}\n'.format('word','PPMC'))

        for key, value in sorted(correlations.items(), key=itemgetter(1),reverse=True)[:k_max]:
            print('\t{0:11} {1:5}'.format(key,round(value,5)))

    except Exception as err:
        logger.error(str(err))
        sys.exit(1)

































