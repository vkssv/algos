#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-

"""
Extracting and pre-processing for basic email's bodies parts,
which can be checked by rules (features-triggers) from each pattern_class.
"""

import sys, os, importlib, logging, re, binascii, unicodedata

from email import iterators
from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple

from nltk.tokenize import WordPunctTokenizer, PunktSentenceTokenizer
from nltk.corpus import stopwords
from nltk.stem import SnowballStemmer

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(filename)s: %(message)s')
ch = logging.StreamHandler(sys.stdout)
logger.addHandler(ch)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print('Can\'t find bs4 module, probably, it isn\'t installed.')
    print('try: "easy_install beautifulsoup4" or install package "python-beautifulsoup4"')


class BeautifulBody(object):
    """
    Base class for simplified work with email.message objects,
    some kind of BeautifulSoup objects from bs4.
    """
    _LANG = 'english'
    _LANGS_LIST = ('english', 'french', 'russian')
    _CHARSET = 'utf-8'

    def __init__(self, msg):
        self._msg = msg

    def _get_rcvds_(self, rcvds_num=0):
        """
        :param rcvds_num:
        :return: left parts of Received header's values, everything before ';'
        """
        # parse all RCVD headers by default if rcvds_num wasn't defined
        self.parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in self._msg.get_all('Received')])[ -1*rcvds_num : ]

        return self.parsed_rcvds

    def _get_mime_struct_(self):
        """
        :return: dict { mime_type  : [attribute : value] }
        """
        #logger.debug("in _get_mime_struct_()")
        self._mime_parts_= defaultdict(list)

        mime_heads = ['Content-Type', 'Content-Transfer-Encoding', 'Content-Id', 'Content-Disposition',\
                      'Content-Description','Content-Class']

        for part in self._msg.walk():

            part_key = 'text/plain'
            # default initialization, but expected that Content-Type always goes first in MIME-headers set for body's part?
            # so I always will have non-default value in else branch for normal emails
            # can't find any info in RFCs 2045/2046... about MIME-headers order ((
            for head in filter(lambda n: part.keys().count(n), mime_heads):

                if head == 'Content-Type':

                    part_key = part.get(head)
                    part_key = part_key.partition(';')[0].strip()
                    added_value = (re.sub(part_key+';','',part.get(head).strip(),re.M)).strip()

                    self._mime_parts_[part_key].append(added_value.lower())
                    #part_dict[head] = re.sub(part_key+';','',part.get(head),re.I)

                else:
                    self._mime_parts_[part_key].append(part.get(head).strip())
                    #part_dict[head] = part.get(head).strip()

        self._mime_parts_ = dict([(k,tuple(v)) for k,v in self._mime_parts_.items()])
        #logger.debug("mime_dict: "+str(self._mime_parts_))

        return self._mime_parts_

    def _get_nest_level_(self):

        mime_parts = self._get_mime_struct_()
        self.level = len(filter(lambda n: re.search(r'(multipart|message)\/',n,re.I),mime_parts.keys()))

        return self.level

    def _get_url_list_(self):

        self.url_list = list()

        for line, content_type, lang in list(self._get_text_mime_part_()):
            # parse by lines
            if 'html' in content_type:
                soup = BeautifulSoup(line)
                if soup.a:
                    # TODO: create deeply parsing with cool bs4 methods
                    self.url_list.extend([unicode(x) for x in soup.a])
            else:
                url_regexp= ur'(((https?|ftps?):\/\/)|www:).*'
                self.url_list.extend(filter(lambda url: re.search(url_regexp, url, re.I), [l.strip() for l in line.split()]))

        #logger.debug("URL LIST:")
        for i in self.url_list:
            if self.url_list:
                # todo: fix this shame (there is nothing more permanent, then some temporary peaces of shame in your simple code ()
                self.url_list = [ (((s.strip(']')).strip('[')).strip(')')).strip('(').strip('<').strip('>') for s in self.url_list ]

            parsed_urls = []
            for y in self.url_list:
                try:
                    parsed_urls.append(urlparse(y))
                except Exception as err:
                    logger.error(str(err))
                    continue

            self.url_list = parsed_urls

        return(self.url_list)

    def _get_text_mime_part_(self):
        """
        :return: generator of tuples ( decoded line , mime type , lang ) for each text/mime part
        """
        charset_map = {'x-sjis': 'shift_jis'} # cam meet this name for shift_jis => x-sjis
        # partial support of asian encodings, just to decode in UTF without exceptions
        # and normilize with NFC form: one unicode ch per symbol
        langs_map = {
                        'russian'   :  ['koi8','windows-1251','cp866', 'ISO_8859-5','Latin-?5'],
                        'french'    :  ['ISO_8859-[19]','Latin-?[19]','CP819', 'windows-1252'],
                        'jis'       :  ['shift_jis','ISO-2022-JP']
        }

        for p in iterators.typed_subpart_iterator(self._msg):
            decoded_line = p.get_payload(decode=True)

            # determine charset:
            charset = self._CHARSET

            for ch in tuple(ch for ch in (p.get_content_charset(), p.get_charset()) if ch):
                if (ch != self._CHARSET) and (ch in charset_map.keys()):
                    charset =  charset_map.get(ch)
                    break
                else:
                    charset = ch

            #logger.debug("charset: "+str(charset))

            # Python2.7 => try to decode all lines from their particular charsets to unicode,
            # add U+FFFD, 'REPLACEMENT CHARACTER' if faces with UnicodeDecodeError
            decoded_line = decoded_line.decode(charset, 'replace')
            if not decoded_line.strip():
                continue

            decoded_line = unicodedata.normalize('NFC', decoded_line)

            # determine lang:
            # from charset attribute in Content-Type
            lang = self._LANG
            for l in langs_map.iterkeys():
                if filter(lambda ch: re.match(r''+ch, charset, re.I), langs_map.get(l)):
                    lang = l
                    yield(decoded_line, p.get_content_type(), lang)

            # from r'(Content|Accept)-Language' headers
            l = filter(lambda lang_header: re.match(r'(Content|Accept)-Language', lang_header), map(itemgetter(0),self._msg.items()))[-1:]
            if l:
                lang = ''.join(self._msg.get(''.join(l)).split('-')[:1])

            yield(decoded_line, p.get_content_type(), lang)

    def _get_sentences_(self):
        """
        :return: sentences generator: tuple of sentences for each text/mime part
        """
        tokenizer = PunktSentenceTokenizer()
        for raw_line, mime_type, lang in tuple(self._get_text_mime_part_()):

            if 'html' in mime_type:
                soup = BeautifulSoup(raw_line)
                if not soup.body:
                    continue
                # cause exactly sentences are needed, soup.body.strings returns lines+0d0a
                lines = tuple(soup.body.strings)
                raw_line = ''.join(lines)
                #logger.debug(raw_line)

            yield tuple(tokenizer.tokenize(raw_line))

    def _get_stemmed_tokens_(self):
        """
        :return: generator of stemmed tokens for each text/mime part
        """
        tokenizer = WordPunctTokenizer()
        #punct_extractor = RegexpTokenizer("[\w']+", gaps=True)
        stopwords_dict = dict([(lang, set(stopwords.words(lang))) for lang in self._LANGS_LIST])

        for pt in tuple(self._get_sentences_()):
            tokens = tuple(tokenizer.tokenize(sent) for sent in pt)
            tokens = reduce(add,tokens)
            #logger.debug("tokens: "+str(tokens))
            if lang == self._LANG:
                # check that it's really english
                tokens_set = set(tokens)
                lang_ratios = [(x, len(tokens_set.intersection(stopwords_dict.get(x)))) for x in stopwords_dict.keys()]
                #logger.debug(lang_ratios)
                l, ratio = sorted(lang_ratios, key=itemgetter(1), reverse=True)[0]
                if ratio:
                    lang = l

                # logger.debug('lang: '+lang)

            if lang in self._LANGS_LIST:
                #todo: create stopwords list for jpn ,
                tokens = tuple(word for word in tokens if word not in stopwords.words(lang))
                #logger.debug('before stem: '+str(tokens))
                tokens = tuple(SnowballStemmer(lang).stem(word) for word in tokens)
                #logger.debug("tokens list: "+str(tokens))

            yield tokens


if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)

