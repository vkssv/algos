#! /usr/bin/python2.7
# -*- coding: utf-8 -*-
__author__ = 'root'

import sys, os, importlib, logging, re, binascii, math, zlib, unicodedata

from email import iterators
from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple

from nltk.tokenize import RegexpTokenizer
from nltk.corpus import stopwords
from nltk.stem import SnowballStemmer

try:
    from bs4 import BeautifulSoup
except ImportError:
    print('Can\'t find bs4 module, probably, it isn\'t installed.')
    print('try: "easy_install beautifulsoup4" or install package "python-beautifulsoup4"')

LANG = 'english'
LANGS_LIST = ('english', 'french', 'russian')


def _get_text_mime_part_(msg):

    charset_map = {'x-sjis': 'shift_jis'}
    # partial support of asian encodings, just to decode in UTF without exceptions
    # and normilize with NFC form: one unicode ch per symbol
    langs_map = {
                    'ru'    :  ['koi8','windows-1251','cp866', 'ISO_8859-5','Latin-?5'],
                    'fr'    :  ['ISO_8859-[19]','Latin-?[19]','CP819', 'windows-1252'],
                    'jis'   :  ['shift_jis']
    }

    for p in iterators.typed_subpart_iterator(msg):
        decoded_line = p.get_payload(decode=True)

        # determine charset:
        charset = 'utf-8'
        for ch in (p.get_content_charset(), p.get_charset()):
            if ch and ch.lower() != 'utf-8':
                if ch in charset_map.keys():
                    charset =  charset_map.get(ch)
                    break
                else:
                    charset = ch

        # Python2.7 => try to decode all lines from their particular charsets to unicode,
        # add U+FFFD, 'REPLACEMENT CHARACTER' if faces with UnicodeDecodeError
        decoded_line = decoded_line.decode(charset, 'replace')
        if not decoded_line.strip():
            continue
        type(decoded_line)
        decoded_line = unicodedata.normalize('NFC', decoded_line)

        # determine lang:
        # from charset attribute in Content-Type
        lang = LANG
        for l in langs_map.iterkeys():
            if filter(lambda ch: re.match(ch, charset, re.I), langs_map.get(l)):
                lang = l
                yield(decoded_line, p.get_content_type(), lang)

        # from r'(Content|Accept)-Language' headers
        l = filter(lambda lang_header: re.match(r'(Content|Accept)-Language', lang_header), map(itemgetter(0),msg.items()))[-1:]
        if l:
            lang = ''.join(msg.get(''.join(l)).split('-')[:1])

        yield(decoded_line, p.get_content_type(), lang)

def _get_stemmed_tokens_vect_(msg):
        '''
        :return: iterator with pure stemmed tokens lists, a list per text/mime part
        '''
        reg_tokenizer = RegexpTokenizer('\s+', gaps=True)

        stopwords_dict = dict([(lang, set(stopwords.words(lang))) for lang in LANGS_LIST])
        for k in stopwords_dict.iterkeys():
            print(">>>> "+str(stopwords_dict.get(k)))

        for pt in tuple(_get_text_mime_part_(msg)):
            raw_line, mime_type, lang = pt
            print('line: '+raw_line)
            print('mime: '+mime_type)
            print('lang: '+lang)
            if 'html' in mime_type:
                soup = BeautifulSoup(raw_line)
                if not soup.body:
                    continue
                raw_line = ''.join(list(soup.body.strings))

            tokens = tuple(token.lower() for token in reg_tokenizer.tokenize(raw_line))

            print("tokens: "+str(tokens))
            if lang == LANG:
                # check that it's really english

                tokens_set = set(tokens)

                lang_ratios = filter(lambda x,y: (x, len(tokens_set.intersection(y))), stopwords_dict.items())
                #max_ratio = sorted(lang_ratios, key=itemgetter(1), reverse=True)[:1]
                print(sorted(lang_ratios, key=itemgetter(1), reverse=True))
                lang, ratio = sorted(lang_ratios, key=itemgetter(1), reverse=True)[:1]
                print('determ lang: '+lang)

            tokens = tuple(word for word in tokens if word not in stopwords.words(lang))
            tokens = tuple(word for word in tokens if word not in SnowballStemmer(lang))
            yield tokens