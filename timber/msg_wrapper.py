# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii, unicodedata

from email import iterators
from urlparse import urlparse
from operator import add
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

# todo: implement container class,
# which will keep list of objects of any type except of None
# or empty subsequences

class BeautifulBody(object):
    """
    Base class for simplified work with email.message objects,
    something like BeautifulSoup objects from bs4.
    """
    LANG = 'en'
    LANGS_LIST = ('en', 'fr', 'ru')

    def __init__(self, msg):
        self._msg_ = msg

    def _get_mime_struct_(self):
        '''
        :return:
        '''
        logger.debug("IN get_mime_struct")
        self._mime_parts_= defaultdict(list)

        mime_heads = ['Content-Type', 'Content-Transfer-Encoding', 'Content-Id', 'Content-Disposition',\
                      'Content-Description','Content-Class']

        for part in self._msg_.walk():

            part_key = 'text/plain'
            # default initialization, but expected that Content-Type always goes first in MIME-headers set for body's part?
            # so I always will have non-default value in else branch for normal emails
            # can't find any info in RFCs 2045/2046... about MIME-headers order ((
            for head in filter(lambda n: part.keys().count(n), mime_heads):

                if head == 'Content-Type':

                    part_key = part.get(head)
                    part_key = part_key.partition(';')[0].strip()
                    added_value = (re.sub(part_key+';','',part.get(head).strip(),re.M)).strip()
                    logger.debug('VAL'+str(added_value))

                    self._mime_parts_[part_key].append(added_value.lower())
                    #part_dict[head] = re.sub(part_key+';','',part.get(head),re.I)

                else:
                    self._mime_parts_[part_key].append(part.get(head).strip())
                    #part_dict[head] = part.get(head).strip()

        #dself.mime_parts[(part_key.partition(';')[0]).strip()] = part_dict
        logger.debug("DEF_DICT"+str(self._mime_parts_))
        self._mime_parts_ = dict([(k,tuple(v)) for k,v in self._mime_parts_.items()])
        logger.debug("DICT"+str(self._mime_parts_))

        return self._mime_parts_

    def _get_text_mime_part_(self):
        '''
        :return: list of tuples with full decoded text/mime parts,
                    i.e. transport decoding + charset decoding, if lines are
                    not in utf-8
        '''
        # partial support of asian encodings, just to decode in UTF without exceptions
        # and normilize with NFC form: one unicode ch per symbol
        charset_map = {'x-sjis': 'shift_jis'}

        langs_map = {
                        'ru'    :  ['koi8','windows-1251','cp866', 'ISO_8859-5','Latin-?5'],
                        'fr'    :  ['ISO_8859-[19]','Latin-?[19]','CP819', 'windows-1252'],
                        'jis'   :  ['shift_jis']
        }

        for p in iterators.typed_subpart_iterator(self._msg_):
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

            decoded_line = unicodedata.normalize('NFC', decoded_line)

            # determine lang:
            # from charset attribute in Content-Type
            lang = self.LANG
            for l in langs_map.iterkeys():
                if filter(lambda ch: re.match(ch, charset, re.I), langs_map.get(l)):
                    lang = l
                    yield(decoded_line, p.get_content_type(), lang)

            # from r'(Content|Accept)-Language' headers
            l = filter(lambda lang_header: re.match(r'(Content|Accept)-Language', lang_header), map(itemgetter(0), self._msg_.items()))[-1:]
            if l:
                lang = ''.join(_msg_.get(''.join(l)).split('-')[:1])

            yield(decoded_line, p.get_content_type(), lang)

    def _get_text_part_ngrams_(self):
        '''
        :return: iterator with pure stemmed tokens lists, a list per text/mime part
        '''




        stopworders = (set(stopwords.words(lang)) for lang in self.LANGS_LIST)
        stemmers = (SnowballStemmer(lang) for lang in self.LANGS_LIST)

        nltk_obj =  namedtuple('nltk_obj','stop stem')
        nltk_obj_dict = dict(zip(langs, nltk_obj(stopworders, stemmers)))
        Regtokenizer = RegexpTokenizer("[a-zA-Z'éèî]+")


        for pt in self._get_text_mime_part_():
            raw_line, mime_type, lang = next(raw_text_parts)
            if 'html' in mime_type:
                soup = BeautifulSoup(raw_part)
                if not soup.body:
                    continue
                raw_line = ''.join(list(soup.body.strings))


            t_list = tokenizer.tokenize(raw_line)
            if lang != 'en':
                langs = list(lang)

            for i in langs:
                pure_list = [word for word in words if word not in nltk_obj_dict.get(i).stop]
                pure_list = [word for word in pure_list if word not in nltk_obj_dict.get(i).stem]

            yield pure_list

    def _get_rcvds_(self, rcvds_num=0):
        # parse all RCVD headers by default if rcvds_num wasn't defined
        self.parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in self._msg_.get_all('Received')])[ -1*rcvds_num : ]

        return self.parsed_rcvds

    def _get_nest_level_(self):

        mime_parts = self._get_mime_struct_()
        self.level = len(filter(lambda n: re.search(r'(multipart|message)\/',n,re.I),mime_parts.keys()))

        return self.level

    def _get_url_list_(self):

        text_parts = self._get_text_parts_()
        #logger.debug('TEXT_PARTS: '+str(text_parts))
        self.url_list = []

        for line, content_type in text_parts:
            # parse by lines
            if 'html' in content_type:
                soup = BeautifulSoup(line)
                if soup.a:
                    # TODO: create deeply parsing with cool bs4 methods
                    self.url_list.extend([unicode(x) for x in soup.a])
            else:
                url_regexp= ur'(((https?|ftps?):\/\/)|www:).*'
                self.url_list.extend(filter(lambda url: re.search(url_regexp, url, re.I), [l.strip() for l in line.split()]))

        logger.debug("URL LIST:")
        for i in self.url_list:
            logger.debug('-------------')
            logger.debug(i)
        if self.url_list:
            # to do: fix this shame (there is nothing more permanent, then some temporary peaces of shame in your simple code ()
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
