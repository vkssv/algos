#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-

"""
Extracting and pre-processing for basic email's bodies parts,
which can be checked by rules (features-triggers) from each pattern_class.
"""

import sys, os, importlib, logging, re, binascii, unicodedata
import pdb



from email import iterators, header, utils

from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple
from itertools import islice

from nltk.tokenize import WordPunctTokenizer, PunktSentenceTokenizer
from nltk.corpus import stopwords
from nltk.stem import SnowballStemmer

from timber_exceptions import NaturesError

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(filename)s: %(message)s')
ch = logging.StreamHandler(sys.stdout)
logger.addHandler(ch)

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
    # now can't see any real reason to set default as private attributes,
    # so keep them here
    DEFAULT_LANG = 'english'
    DEFAULT_CHARSET = 'utf-8'
    DEFAULT_MAX_NEST_LEVEL = 30

    SUPPORT_LANGS_LIST = ['english', 'french', 'russian']

    __URLINTEXT_PAT = re.compile(ur'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))', re.M)

    __slots__ = '_msg'

    def __init__(self, msg):

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

    @staticmethod
    def _get_unicoded_value(raw_line, encoding=None ):
        print('in _get_unicoded_value')
        print(raw_line)
        print(encoding)
        dammit_obj = UnicodeDammit(raw_line, [encoding], is_html=False)
        logger.debug(dammit_obj.unicode_markup.strip())

        return dammit_obj.unicode_markup.strip()

    # maybe change implementation in future
    #@property
    #def get_lang_(self):
    #    return lang

    #@get_lang_.setter
    def get_lang_(self, tokens_list):
        '''
        :param tokens_list:
        :return: 42
        '''
        lang = self.DEFAULT_LANG

        stopwords_dict = dict([(lang, set(stopwords.words(lang))) for lang in self.SUPPORT_LANGS_LIST])
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
        parsed_rcvds = tuple(rcvd.partition(';')[0] for rcvd in self._msg.get_all('Received'))[ -1*rcvds_num : ]

        return parsed_rcvds

    def get_addr_values(self, header_value):
        '''
        :param list with destinator/originator-headers values, which could consist from realname (string, could be encoded by base64/QP)
            + email address, so these header values MUST BE obtained from email.message object by message.get_all('HEADER') method
        :return: vector (because the order of destinator/originator-addresses should be kept) of tuples :
            (unicode string with decoded realname, address without angle parentheses)
        '''

        logger.debug('+++++>'+str(header_value))

        addr_value = namedtuple('addr_value', 'realname address')

        name_addr_tuples = (addr_value(*pair) for pair in utils.getaddresses(header_value))
        # cause of such From-header values from russian spam:
        # utils.getaddresses(m.get_all('From'))
        # [('=?utf-8?B?0KDQodCl0JDQo9Cf?= "=?utf-8?B?0JHQtdC70J/QodCl0JDQk9CY?="', 'mail@belaerogis.by')]
        # need to looping
        temp = list()
        for realname, address in tuple(name_addr_tuples):
            print(address)
            if not address:
                continue
            parts = realname
            if realname.startswith('=?') and (realname.count(' ')>0 or realname.count('"')>0):
                realname = re.sub('"','',realname)

                parts = tuple(header.decode_header(p) for p in (realname).split())
                print(parts)

            temp.append((parts, address.lower()))

        print(temp)
        pairs = list()
        for t in temp:
            realname_parts, addr = t
            print(realname_parts)
            print(addr)
            
            value = u''

            for part in realname_parts:
                print(part)
                if len(part)==0:
                    continue
                value += self._get_unicoded_value(*(reduce(add,part)))

            pairs.append((value, addr))

        #name_addr_tuples = ((self._get_unicoded_value(*(t.realname)), t.address) for t in tuple((addr_value(*pair) for pair in temp)))
        # address value has always to exist in returned pair, cause in some patterns we leave only them in the list for processing
        #pairs = tuple((p.realname, p.address) for p in (addr_value(*pair) for pair in name_addr_tuples) if p.address)
        if pairs:
            pairs = tuple((p.realname, re.sub(r'<|>','',p.address)) for p in tuple(addr_value(*pair) for pair in pairs))

        print("pairs >>"+str(pairs))
        return pairs

    #@lazyproperty
    def get_smtp_domain(self):
        '''
        :return: sender's domain from the first Received-field
        "...Ah, it is easy to deceive me!...
            I long to be deceived myself!...A. Pushkin"
        '''

        regexp = re.compile(r'(@|(?<=helo)\s?=\s?|(?<=from)\s+)?([a-z0-9-]{1,60}\.){1,3}[a-z]{2,10}', re.M)
        orig_domain = ''

        l = filter(lambda value: regexp.search(value), self.get_rcvds())
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
        parts_list = header.decode_header(self._msg.get('Subject'))
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
            encodings_list.append(dammit_obj.original_encoding)

        tokens = tuple(subj_line.split())
        lang = self.get_lang_(tokens)
        if lang in self.SUPPORT_LANGS_LIST:
            tokens = tuple(word for word in tokens if word not in stopwords.words(lang))
            logger.debug('before stem: '+str(tokens))
            subj_tokens  = tuple(SnowballStemmer(lang).stem(word) for word in tokens)

        return subj_line, subj_tokens, encodings_list

    #@lazyproperty
    def get_mime_struct(self):
        """
        :return: dict { mime_type  : [attribute : value] }
        """
        mime_parts = defaultdict(list)

        needed_heads = ['content-type', 'content-transfer-encoding', 'content-id', 'content-disposition',\
                      'content-description','content-class']

        for part in self._msg.walk():

            part_key = 'text/plain'
            # default initialization, but expected that Content-Type always goes first in MIME-headers set for body's part?
            # so I always will have non-default value in else branch for normal emails
            # can't find any info in RFCs 2045/2046... about MIME-headers order ((


            mime_part_heads = tuple(k.lower() for k in part.keys())
            print('>>>'+str(mime_part_heads))
            print(tuple(head_name for head_name in needed_heads if mime_part_heads.count(head_name)))
            for head in tuple(head_name for head_name in needed_heads if mime_part_heads.count(head_name)):
            #for head in filter(lambda n: part.keys().count(n), mime_heads):

                if head == 'content-type':

                    part_key = part.get(head)
                    logger.debug(part_key)
                    part_key = part_key.partition(';')[0].strip()
                    logger.debug(part_key)
                    added_value = (re.sub(part_key+';','',part.get(head).strip(),re.M)).strip()
                    logger.debug(added_value)
                    mime_parts[part_key].append(added_value.lower())
                    logger.debug(mime_parts)
                    #part_dict[head] = re.sub(part_key+';','',part.get(head),re.I)

                else:
                    mime_parts[part_key].append(part.get(head).strip())
                    logger.debug(mime_parts)
                    #part_dict[head] = part.get(head).strip()

        mime_parts = dict((k,tuple(v)) for k,v in mime_parts.items())
        logger.debug("mime_dict: "+str(mime_parts))

        return mime_parts

    #@lazyproperty
    def get_nest_level(self):
        '''
        :return: MIME-nesting level
        '''

        mime_parts = self.get_mime_struct()
        level = len(filter(lambda n: re.search(r'(multipart|message)\/',n,re.I), mime_parts.keys()))

        return level

    #@lazyproperty
    def get_url_list(self):
        '''
        :return: list of urlparse objects for further processing,
        or empty list if body doesn't contain any links
        '''

        self.url_list = list()

        for line, content_type, lang in list(self.get_text_mime_part()):
            if 'html' in content_type:
                soup = BeautifulSoup(line)
                if soup.a:
                    self.url_list.extend([unicode(x) for x in soup.a])
            else:
                url_regexp= ur'(((https?|ftps?):\/\/)|www:).*'
                self.url_list.extend(filter(lambda url: re.search(url_regexp, url, re.I), [l.strip() for l in line.split()]))


        if self.url_list:
            self.url_list = [urlparse(i) for i in self.url_list]

        # todo: make it as lazy computing value
        return self.url_list

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
            #logger.debug(decoded_line)
            if decoded_line is None or len(decoded_line.strip()) == 0:
                continue

            lang = self.DEFAULT_LANG
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

    def get_sentences(self, remove_url=True):
        '''
        sentences generator
        :remove_url: True - replace URL from unicoded sentence with space,
        cause URLs are processing separately in BasePattern and should not
        affected other MIME part's tokens statistics
        :return: tuple of sentences for each text/mime part
        '''
        tokenizer = PunktSentenceTokenizer()


        for raw_line, mime_type, lang in tuple(self.get_text_mime_part()):
            print(raw_line, mime_type, lang)
            if 'html' in mime_type:
                soup = BeautifulSoup(raw_line)
                if not soup.body:
                    continue
                # cause exactly sentences are needed, soup.body.strings returns lines+0d0a
                lines = tuple(soup.body.strings)
                raw_line = ''.join(lines)
                logger.debug(u'raw_line_from_html >>'+raw_line)
            #print(raw_line)
            #print(tokenizer.tokenize(raw_line))
            try:
                sents = tuple(tokenizer.tokenize(raw_line))
            except Exception as err:
                sents = tuple(raw_line)

            if remove_url:
                sents = tuple(map(lambda sent: self.__URLINTEXT_PAT.sub(' ', sent, re.I), sents))

            sents = (s.strip() for s in sents)
            sents = tuple(s for s in tuple(sents) if s)
            if len(sents) == 0:
                continue

            yield sents

    def get_stemmed_tokens(self):
        '''
        tokens generator
        :return: stemmed, cleaned from stopwords tokens tuple (keeps token's order) for each text/mime part
        '''
        tokenizer = WordPunctTokenizer()
        #punct_extractor = RegexpTokenizer("[\w']+", gaps=True)

        # todo: while true ?
        for pt in tuple(self.get_sentences()):
            tokens = tuple(tokenizer.tokenize(sent) for sent in pt)
            tokens = reduce(add, tokens)
            #logger.debug("tokens: "+str(tokens))
            lang = self.get_lang_(tokens)
            logger.debug('lang: '+lang)

            if lang in self.SUPPORT_LANGS_LIST:
                #todo: create stopwords list for jis ,
                tokens = tuple(word for word in tokens if word not in stopwords.words(lang))
                #logger.debug('before stem: '+str(tokens))
                tokens = tuple(SnowballStemmer(lang).stem(word) for word in tokens)
                #logger.debug("tokens list: "+str(tokens))

            yield tokens


if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)

