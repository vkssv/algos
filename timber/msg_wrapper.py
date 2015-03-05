#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-

"""
Extracting and pre-processing for basic email's bodies parts,
which can be checked by rules (features-triggers) from each pattern_class.
"""

import sys, os, importlib, logging, re, binascii, unicodedata
import pdb



from email import iterators, header

from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple

from nltk.tokenize import WordPunctTokenizer, PunktSentenceTokenizer
from nltk.corpus import stopwords
from nltk.stem import SnowballStemmer

from timber_exceptions import NaturesError

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


class lazyproperty:
    '''
    decorator for once-computed methods, cause for test-emails
    4 patterns will be created, all are inheritated from
    one base class
    '''

    def __init__(self, func):
        self.func = func

    def __get__(self, instance, cls):
        if instance is None:
            return self
        else:
            setattr(instance, self.func.__name__, value)

        return val


class BeautifulBody(object):
    """
    Base class for happy life with email.message objects,
    some kind of BeautifulSoup objects from bs4.

    """
    __LANG = 'english'
    __LANGS_LIST = ('english', 'french', 'russian')
    #__CHARSET = 'utf-8'
    __MAX_NEST_LEVEL = 30

    def __init__(self, msg):

        if msg.is_multipart():

            be_picky = [
                        (lambda y: y > self.__MAX_NEST_LEVEL, lambda m: len(m.get_payload()),' mime parts... I can\'t eat so much, merci!'), \
                        (lambda y: y, lambda m: m.defects,' I don\'t eat such emails, !')
                    ]

            for whim, f, text in be_picky:
                y=f(msg) # cause don't want to calculate it again in exception's text
                if whim(y):
                    raise NaturesError(str(y)+text)

        self._msg = msg

    # maybe change implementation in future
    @property
    def get_lang_(self):
        return lang

    @get_lang_.setter
    def get_lang_(self, tokens_list):
        '''
        :param tokens_list:
        :return: 42
        '''
        lang = self.__LANG

        stopwords_dict = dict([(lang, set(stopwords.words(lang))) for lang in self.__LANGS_LIST])
        tokens_set = set(tokens_list)
        lang_ratios = [(x, len(tokens_set.intersection(stopwords_dict.get(x)))) for x in stopwords_dict.keys()]
        logger.debug(lang_ratios)
        l, ratio = sorted(lang_ratios, key=itemgetter(1), reverse=True)[0]
        if ratio:
            lang = l

        return lang

    def get_rcvds(self, rcvds_num=0):
        '''
        :param rcvds_num: N curious Received headers from \CRLF\CRFL to top
        :return: left parts of Received header's values, everything before ';'
        '''
        # parse all RCVD headers by default if rcvds_num wasn't defined
        parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in self._msg.get_all('Received')])[ -1*rcvds_num : ]

        return parsed_rcvds

    def get_addr_values(self, header_value=None):
        '''
        :param header_value:
        :return:
        '''
        if header_value is None:
            header_value = self._msg.get('To')

        logger.debug('+++++>'+str(header_value))
        for_crunch = re.compile(r'[\w\.-_]{1,64}@[a-z0-9-]{1,63}(?:\.[\w]{2,4})+',re.I)

        h_value = tuple(header.decode_header(header_value))
        # don't use encoding info for translations, so don't keep it
        h_value = tuple([pair[0] for pair in h_value])
        logger.debug('+++++'+str(h_value))
        # crunch addreses and names
        addrs=[]
        names = []
        for part in h_value:
            logger.debug('part  '+str(part))
            part = re.sub(r'<|>','',part)
            logger.debug(str(part))
            addrs += for_crunch.findall(part)
            logger.debug(str(addrs))
            names.append(for_crunch.sub('',part))

        #logger.debug('names: '+str(names))

        # keep order => use tuples, + cause function should works
        # either for To/CC/Bcc headers with many senders,
        # or for From/Sender
        # names are raw encoded strings
        return tuple(names), tuple(addrs)

    #@lazyproperty
    def get_smtp_domain(self):
        '''
        :return: sender's domain from the first Received-field
        "...Ah, it is easy to deceive me!...
            I long to be deceived myself!...A. Pushkin"
        '''

        regexp = re.compile(r'(@|(?<=helo)\s?=\s?|(?<=from)\s+)?([a-z0-9-]{1,60}\.){1,3}[a-z]{2,10}', re.M)
        orig_domain = ''

        l = filter(lambda value: regexp.search(value), self._get_rcvds_())
        logger.debug(l) # check that regexp matched exactlu first
        if l:
            orig_domain = reduce(add,l)
            print('+++++++++++++++++++++++++++++++++++++++')
            print((orig_domain,))
            orig_domain = (regexp.search(orig_domain)).group(0)
            orig_domain = orig_domain.strip('.').strip('@').strip('=').strip()
            print('ORIG_DOMAINS: '+str(orig_domain))

        return orig_domain

    #@lazyproperty
    def get_decoded_subj(self):
        '''
        don't use vector-form of calculations for quick transport-decoding
        and unicoding metamorphoses, cause it could be exceptions on each
        step, so consequently cycling
        :return:
        '''

        #logger.debug('SUBJ_LINE: >'+str(subj_line)+'<')
        assert self._msg.get('Subject')
        parts_list = decode_header(self._msg.get('Subject'))
        logger.debug('parts >>>>>'+str(subj_parts))
        subj_line = u''
        encodings_list = list()

        for pair in parts_list:
            dummit_obj = None
            line, encoding = p
            try:
                dummit_obj = UnicodeDammit(line, [encoding], is_html=False)

            except Exception as err:
                #logger.debug(err)
                #logger.debug('>>> Please, add this to Kunstkamera')
                if dammit_obj is None:
                    continue

            subj_line += dummit_obj.unicode_markup + u' '
            encodings_list.append(dummit_obj.original_encoding)

        tokens = tuple(subj_line.split())
        lang = self._get_lang_(self._subj_tokens)
        if lang in self.__LANGS_LIST:
            tokens = tuple(word for word in tokens if word not in stopwords.words(lang))
            logger.debug('before stem: '+str(tokens))
            subj_tokens  = tuple(SnowballStemmer(lang).stem(word) for word in tokens)

        return subj_line, subj_tokens, encodings_list

    #@lazyproperty
    def get_mime_struct(self):
        """
        :return: dict { mime_type  : [attribute : value] }
        """
        self._mime_parts = defaultdict(list)

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

                    self._mime_parts[part_key].append(added_value.lower())
                    #part_dict[head] = re.sub(part_key+';','',part.get(head),re.I)

                else:
                    self._mime_parts[part_key].append(part.get(head).strip())
                    #part_dict[head] = part.get(head).strip()

        self._mime_parts = dict([(k,tuple(v)) for k,v in self._mime_parts.items()])
        #logger.debug("mime_dict: "+str(self._mime_parts_))

        return self._mime_parts

    #@lazyproperty
    def get_nest_level(self):
        '''
        :return: MIME-nesting level
        '''

        mime_parts = self._get_mime_struct()
        level = len(filter(lambda n: re.search(r'(multipart|message)\/',n,re.I),mime_parts.keys()))

        return level

    #@lazyproperty
    def get_url_list(self):

        url_list = list()

        for line, content_type, lang in list(self._get_text_mime_part()):
            # parse by lines
            if 'html' in content_type:
                soup = BeautifulSoup(line)
                if soup.a:
                    # TODO: create deeply parsing with cool bs4 methods
                    url_list.extend([unicode(x) for x in soup.a])
            else:
                url_regexp= ur'(((https?|ftps?):\/\/)|www:).*'
                url_list.extend(filter(lambda url: re.search(url_regexp, url, re.I), [l.strip() for l in line.split()]))

        #logger.debug("URL LIST:")
        for i in url_list:
            if url_list:
                # todo: fix this shame (there is nothing more permanent, then some temporary peaces of shame in your simple code ()
                url_list = [ (((s.strip(']')).strip('[')).strip(')')).strip('(').strip('<').strip('>') for s in self.url_list ]

            parsed_urls = list()
            for y in url_list:
                try:
                    parsed_urls.append(urlparse(y))
                except Exception as err:
                    logger.error(str(err))
                    continue

            url_list = parsed_urls

        return url_list

    def get_text_mime_part(self):
        '''
        generator of tuples with decoded text/mime part's line and metainfo
        :return: generator of tuples ( decoded line , mime type , lang ) for each text/mime part
        '''
        # partial support of asian encodings, just to decode in UTF without exceptions
        # and normilize with NFC form: one unicode ch per symbol
        langs_map = {
                        'russian'   :  ['koi8','windows-1251','cp866', 'ISO_8859-5','Latin-?5'],
                        'french'    :  ['ISO_8859-[19]','Latin-?[19]','CP819', 'windows-1252'],
                        'jis'       :  ['shift_jis','ISO-2022-JP','big5']
        }

        for p in iterators.typed_subpart_iterator(self._msg):
            (decoded_line, decode_flag, dammit_obj) = [None]*3
            if p.get('Content-Transfer-Encoding'):
                decode_flag=True
            try:
            # show must go on
                decoded_line = p.get_payload(decode=decode_flag)
                dammit_obj = UnicodeDammit(decoded_line, is_html=False)

            except Exception as err:
                #logger.debug(err)
                #logger.debug('>>> Please, add this to Kunstkamera')
                if dammit_obj is None:
                    continue

            decoded_line = dammit_obj.unicode_markup
            logger.debug(decoded_line)
            if decoded_line is None or len(decoded_line.strip()) == 0:
                continue

            lang = self.__LANG
            if dammit_obj.original_encoding:
                for l in langs_map.iterkeys():
                    if filter(lambda ch: re.match(r''+ch, dammit_obj.original_encoding, re.I), langs_map.get(l)):
                        lang = l
                        yield(decoded_line, p.get_content_type(), lang)

            # from r'(Content|Accept)-Language' headers
            l = filter(lambda lang_header: re.match(r'(Content|Accept)-Language', lang_header), map(itemgetter(0),self._msg.items()))[-1:]
            if l:
                lang = ''.join(self._msg.get(''.join(l)).split('-')[:1])

            yield(decoded_line, p.get_content_type(), lang)

    def get_sentences(self):
        '''
        sentences generator
        :return: tuple of sentences for each text/mime part
        '''
        tokenizer = PunktSentenceTokenizer()
        for raw_line, mime_type, lang in tuple(self._get_text_mime_part_()):
            print(raw_line, mime_type, lang)
            if 'html' in mime_type:
                soup = BeautifulSoup(raw_line)
                if not soup.body:
                    continue
                # cause exactly sentences are needed, soup.body.strings returns lines+0d0a
                lines = tuple(soup.body.strings)
                raw_line = ''.join(lines)
                logger.debug(raw_line)
            print(raw_line)
            print(tokenizer.tokenize(raw_line))
            try:
                sents = tuple(tokenizer.tokenize(raw_line))
            except Exception as err:
                sents = tuple(raw_line)

            yield sents

    def get_stemmed_tokens(self):
        '''
        tokens generator
        :return: stemmed tokens tuple (keeps token's order) for each text/mime part
        '''
        tokenizer = WordPunctTokenizer()
        #punct_extractor = RegexpTokenizer("[\w']+", gaps=True)

        # todo: while true ? amneisic ?
        for pt in tuple(self._get_sentences_()):
            tokens = tuple(tokenizer.tokenize(sent) for sent in pt)
            tokens = reduce(add,tokens)
            logger.debug("tokens: "+str(tokens))
            if lang == self.__LANG:
                # check that it's really english
                lang = self._get_lang_(tokens)
                logger.debug('lang: '+lang)

            if lang in self.__LANGS_LIST:
                #todo: create stopwords list for jis ,
                tokens = tuple(word for word in tokens if word not in stopwords.words(lang))
                logger.debug('before stem: '+str(tokens))
                tokens = tuple(SnowballStemmer(lang).stem(word) for word in tokens)
                logger.debug("tokens list: "+str(tokens))

            yield tokens


if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)

