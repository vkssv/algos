#! /usr/bin/python2.7
# -*- coding: utf-8 -*-
__author__ = 'root'

import sys, os, importlib, logging, re, binascii, math, zlib

from email import iterators
from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple

from nltk.tokenize import RegexpTokenizer
from nltk.corpus import stopwords
from nltk.stem import SnowballStemmer

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

try:
    from bs4 import BeautifulSoup, Comment
except ImportError:
    print('Can\'t find bs4 module, probably, it isn\'t installed.')
    print('try: "easy_install beautifulsoup4" or install package "python-beautifulsoup4"')



def _get_text_mime_part_(msg):

    charset_map = {'x-sjis': 'shift_jis'}
    langs_map = {
                    'ru':  ['koi8','windows-1251','cp866', 'ISO_8859-5','Latin-?5'],
                    'fr':  ['ISO_8859-[19]','Latin-?[19]','CP819', 'windows-1252']
    }

    for p in iterators.typed_subpart_iterator(msg):
        decoded_line = p.get_payload(decode=True)
        lang = ''
        # partial support of asian encodings, just to decode in UTF without exceptions


            # Python2.7 => try to decode all lines from their particular charsets to unicode,
            # add U+FFFD, 'REPLACEMENT CHARACTER' if faces with UnicodeDecodeError

        for charset in (p.get_content_charset(), p.get_charset()):
            if charset and charset.lower() != 'utf-8':
                if charset in charset_map.keys():
                    charset =  charset_map.get(charset)
                    lang = 'jis'

                break

        # so we know the charset and can decode
        decoded_line = decoded_line.decode(charset, 'replace')
        if not len(decoded_line.strip()):
            continue

        # 3. determine lang, three attempts:
        while not lang:
            for lang in langs_map.iterkeys():

                if filter(lambda ch: re.match(ch, charset, re.I), langs_map.get(lang)):
                                logger.debug('LANG from charset: '+lang)
                                break
            lang = filter(lambda lang_header: re.match(r'(Accept|Content)-Language', lang_header), map(itemgetter(0),msg.items()))[-1:]
            lang = msg.get(''.join(lang)).split('-')[:1]
            if lang:
                break


                    #logger.debug(charset)
                    decoded_line = decoded_line.decode(charset, 'replace')
                    break

            if not len(decoded_line.strip()):
                continue

            if not lang:
                lang = filter(lambda lang_header: re.match(r'(Accept|Content)-Language', lang_header), map(itemgetter(0),msg.items()))[-1:]
                lang = msg.get(''.join(lang)).split('-')[:1]

            elif not lang:
                lang = 'english'

            yield(decoded_line, part.get_content_type(), lang)

def _get_pure_text_part_(msg):

    raw_text_parts = _get_text_mime_parts_(msg)

    langs = ('english', 'french', 'russian')
    stopworders = (set(stopwords.words(lang)) for lang in langs)
    stemmers = (SnowballStemmer(lang) for lang in langs)

    nltk_obj =  namedtuple('nltk_obj','stop stem')
    nltk_obj_dict = dict(zip(langs, nltk_obj(stopworders, stemmers)))

    while(True):
        raw_line, mime_type, lang = next(raw_text_parts)
        if 'html' in mime_type:
            soup = BeautifulSoup(raw_part)
            if not soup.body:
                continue
            raw_line = ''.join(list(soup.body.strings))

        t_list = tokenizer.tokenize(raw_line)

        if lang != 'english':
            langs = list(lang)

        for i in langs:
            pure_list = [word for word in words if word not in nltk_obj_dict.get(i).stop]
            pure_list = [word for word in pure_list if word not in nltk_obj_dict.get(i).stem]


        yield pure_list


def get_text_parts_avg_entropy(msg):

    # just for fun
    total_h = 0
    all_text_parts = self._get_pure_text_part_(msg)
    n = len(all_text_parts)

    while(all_text_parts):
        tokens = next(all_text_parts)
        freqdist = FreqDist(tokens)
        probs = [freqdist.freq(l) for l in FreqDist(tokens)]
        total_h += -sum([p * math.log(p,2) for p in probs])

    return (total_h/n)

def get_text_compress_ratio(msg):

    all_text_parts = list(_get_pure_text_part_(msg))
    if all_text_parts:
        all_text = ''.join(reduce(add,all_text_parts))

    return float(len(zlib.compress(all_text)))/len(all_text)