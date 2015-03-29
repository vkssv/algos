#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-

"""
Extracting and pre-processing for basic email's bodies parts,
which can be checked by rules (features-triggers) from each pattern_class.
"""

import sys, os, importlib, logging, re, binascii, unicodedata
import pdb

from nltk.tokenize import RegexpTokenizer
from nltk.corpus import stopwords
from nltk.stem import SnowballStemmer
from nltk.probability import FreqDist, ConditionalFreqDist

from email import iterators, header, utils

from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple, OrderedDict
from itertools import islice


#from timber_exceptions import NaturesError

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(filename)s: %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#logger.addHandler(ch)

try:
    from bs4 import BeautifulSoup, UnicodeDammit
except ImportError:
    print('Can\'t find bs4 module, probably, it isn\'t installed.')
    print('try: "easy_install beautifulsoup4" or install package "python-beautifulsoup4"')


class BeautifulBody(object):
    """
    Base class for happy life with email.message objects,
    some kind of BeautifulSoup objects from bs4.

    """
    # now can't see any real reason to set default as private attributes,
    # so keep them here

    print('BEAUTIFULBODY ----------> FILL ATTRS TAB')

    __URLINTEXT_PAT = re.compile(ur'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))', re.M)

    DEFAULT_MAX_NEST_LEVEL = 30
    DEFAULT_LANG = 'english'
    DEFAULT_CHARSET = 'utf-8'
    SUPPORT_LANGS_LIST = ('english', 'french', 'russian')

    # cause inherited from object!
    __slots__ = ['msg']

    print('BEAUTIFULBODY ----------> CLASS OBJ CREATED')

    def __init__(self, msg, **kwds):

        print('IN BEAUTIFULBODY CONSTRUCTOR ----------> FILL INSTANCE TABLE')

        if msg.is_multipart():

            be_picky = [
                        (lambda y: y > self.DEFAULT_MAX_NEST_LEVEL, lambda m: len(m.get_payload()),' mime parts... I can\'t eat so much, merci!'), \
                        (lambda y: y, lambda m: m.defects,' I don\'t eat such emails, !')
            ]

            for whim, f, text in be_picky:
                y=f(msg) # cause don't want to calculate it again in exception's text
                if whim(y):
                    raise NaturesError(str(y)+text)

        self._msg = msg
        logger.debug(type(self._msg))
        logger.debug('BeautifulBody was created'.upper()+' '+str(id(self)))

        logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))
        #(self.url_list, self.netloc_list) = [list()]*2

    @classmethod
    def _get_unicoded_value(cls, raw_line, encoding=None):
        print('in get_unicoded_value')
        print(raw_line)
        print(encoding)
        dammit_obj = UnicodeDammit(raw_line, [encoding], is_html=False)
        logger.debug(dammit_obj.unicode_markup.strip())

        return dammit_obj.unicode_markup.strip()

    @classmethod
    def get_lang(cls, tokens_list, return_value=None):
        logger.debug('in get_lang')
        lang = cls.DEFAULT_LANG
        logger.debug(lang)

        stopwords_dict = dict([(lang, set(stopwords.words(lang))) for lang in cls.SUPPORT_LANGS_LIST])
        tokens_set = set(tokens_list)
        lang_ratios = [(x, len(tokens_set.intersection(stopwords_dict.get(x)))) for x in stopwords_dict.keys()]
        logger.debug(lang_ratios)
        l, ratio = sorted(lang_ratios, key=itemgetter(1), reverse=True)[0]
        if ratio > 0:
            # cause we can have here: [('russian', 0), ('french', 0), ('english', 0)]
            return l
        else:
            logger.debug('can\'t define language for this token list >> '+str(tokens_list))
            return return_value


    def get_decoded_subj(self):

        parts_list = header.decode_header(self._msg.get('Subject',''))
        logger.debug('parts >>>>>'+str(parts_list))
        subj_line = u''
        encodings_list = list()

        for pair in parts_list:
            dammit_obj = None
            line, encoding = pair
            try:
                dammit_obj = UnicodeDammit(line, [encoding], is_html=False)

            except Exception as err:
                #logger.debug(err)
                #logger.debug('>>> Please, add this to Kunstkamera')
                if dammit_obj is None:
                    continue

            subj_line += dammit_obj.unicode_markup + u' '
            if dammit_obj.original_encoding is not None:
                encodings_list.append(dammit_obj.original_encoding)

        subj_tokens = tuple(subj_line.split())
        lang = self.get_lang(subj_tokens)
        if lang in self.SUPPORT_LANGS_LIST:
            tokens = tuple(word for word in subj_tokens if word not in stopwords.words(lang))
            logger.debug('before stem: '+str(tokens))
            subj_tokens  = tuple(SnowballStemmer(lang).stem(word) for word in tokens)

        return (subj_line, subj_tokens, encodings_list)



'''''

if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)

'''''