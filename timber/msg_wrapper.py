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
from collections import defaultdict, namedtuple, OrderedDict
from itertools import islice

from nltk.tokenize import WordPunctTokenizer, PunktSentenceTokenizer
from nltk.corpus import stopwords
from nltk.stem import SnowballStemmer

from timber_exceptions import NaturesError

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(filename)s: >>> %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#logger.addHandler(ch)

try:
    from bs4 import BeautifulSoup, UnicodeDammit
except ImportError:
    logger.debug('Can\'t find bs4 module, probably, it isn\'t installed.')
    logger.debug('try: "easy_install beautifulsoup4" or install package "python-beautifulsoup4"')


class BeautifulBody(object):
    """
    Base class for happy life with email.message objects,
    some kind of BeautifulSoup objects from bs4.

    """

    __URLINTEXT_PAT = re.compile(ur'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))', re.M)

    DEFAULT_MAX_NEST_LEVEL = 30
    DEFAULT_LANG = 'english'
    DEFAULT_CHARSET = 'utf-8'
    SUPPORT_LANGS_LIST = ('english', 'french', 'russian')

    # BeautifulBody inherited from object! ??
    __slots__ = ['msg']

    def __init__(self, msg, **kwds):

        if msg.is_multipart():

            be_picky = [
                        (lambda y: y > self.DEFAULT_MAX_NEST_LEVEL, lambda m: len(m.get_payload()),' mime parts... I can\'t eat so much, merci!'), \
                        (lambda y: y, lambda m: m.defects,' I don\'t eat such emails, !')
            ]

            for whim, f, text in be_picky:
                y=f(msg) # cause don't want to calculate nested mime-parts count again in exception's text
                if whim(y):
                    raise NaturesError(str(y)+text)

        self.msg = msg

        #logger.debug('BeautifulBody was created'.upper()+' '+str(id(self)))
        #logger.debug("================")
        #logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))

    @classmethod
    def _get_unicoded_value(cls, raw_line, encoding=None):
        logger.debug('in get_unicoded_value')
        logger.debug(raw_line)
        logger.debug(encoding)
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

    def get_rcvds(self, rcvds_num=0):
        '''
        :param rcvds_num: N curious Received headers from \CRLF\CRFL to top
        :return: left parts of Received header's values, everything before ';'
        '''
        # parse all Received: headers by default if rcvds_num wasn't defined
        parsed_rcvds = tuple(rcvd.partition(';')[0] for rcvd in self.msg.get_all('Received'))[ -1*rcvds_num : ]
        logger.debug('parsed_rcvds : '+str(parsed_rcvds))
        return parsed_rcvds

    def get_addr_values(self, header_value):
        '''
        :header_value - value of particular header, which can store < mailbox name > + < address >
        returnes tuple (< mail box name (utf-8)>, < address (without angle braces) >)
        '''

        logger.debug('value for crunching addresses : '+str(header_value))

        addr_value = namedtuple('addr_value', 'realname address')
        name_addr_tuples = (addr_value(*pair) for pair in utils.getaddresses(header_value))
        # and we can meet here tricky stuff like this:
        # ('=?utf-8?B?0KDQodCl0JDQo9Cf?= "=?utf-8?B?0JHQtdC70J/QodCl0JDQk9CY?="', 'mail@belaerogis.by')
        temp = list()
        for realname, address in tuple(name_addr_tuples):
            if not address:
                continue
            realname = re.sub('"','',realname)
            parts = tuple(header.decode_header(p) for p in realname.split())
            temp.append((parts, address.lower()))

        logger.debug(temp)
        pairs = list()
        for t in temp:
            realname_parts, addr = t
            logger.debug(realname_parts)
            logger.debug(addr)
            
            value = u''
            for part in realname_parts:
                logger.debug(part)
                if len(part)==0:
                    continue
                value += self._get_unicoded_value(*(reduce(add,part)))

            pairs.append((value, addr))

        pairs = tuple((p.realname, re.sub(r'<|>','',p.address)) for p in tuple(addr_value(*pair) for pair in pairs))
        logger.debug("results : "+str(pairs))
        return pairs

    #@lazyproperty
    def get_smtp_originator_domain(self):

        regexp = re.compile(r'(@|(?<=helo)\s?=\s?|(?<=from)\s+)?([a-z0-9-]{1,60}\.){1,3}[a-z]{2,10}', re.M)
        orig_domain = ''

        l = filter(lambda value: regexp.search(value), self.get_rcvds())
        logger.debug(l) # check that regexp matched exactly first
        if l:
            orig_domain = reduce(add,l)
            logger.debug('+++++++++++++++++++++++++++++++++++++++')
            logger.debug((orig_domain,))
            orig_domain = (regexp.search(orig_domain)).group(0)
            orig_domain = orig_domain.strip('.').strip('@').strip('=').strip()
            logger.debug(type(orig_domain))
            logger.debug('ORIG_DOMAINS: '+str(orig_domain))

        return orig_domain

    def get_dkim_domains(self):
        '''
        returns list of domains, which names were used in DKIM signatures
        '''
        # if msg has not these headers one space char will be returned, in case of escaping exceptions
        values = [ el.split(';') for el in [self.msg.get(dkim_head,'\x20') for dkim_head in ['DKIM-Signature','DomainKey-Signature']]]
        values = reduce(add,values)
        values = [i.strip() for i in values if i.strip().startswith('d=')]
        return [i.strip('d=') for i in values]


    #@lazyproperty
    def get_decoded_subj(self):

        parts_list = header.decode_header(self.msg.get('Subject'))
        logger.debug('subject parts >>>>>'+str(parts_list))
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
            subj_tokens = tuple(word for word in subj_tokens if word not in stopwords.words(lang))
            #logger.debug('before stem: '+str(tokens))
            #subj_tokens  = tuple(SnowballStemmer(lang).stem(word) for word in tokens)

        return (subj_line, subj_tokens, encodings_list)

    def get_mime_struct(self):
        """
        try to parse
        :return: dict { mime_type  : [attribute : value] }
        """
        mime_parts = defaultdict(list)

        needed_heads = ['content-type', 'content-transfer-encoding', 'content-id', 'content-disposition',\
                      'content-description','content-class']

        for part in self.msg.walk():

            part_key = 'text/plain'
            # default initialization, but expected that Content-Type always goes first in MIME-headers set for body's part?
            # so I always will have non-default value in else branch for normal emails
            # can't find any info in RFCs 2045/2046... about MIME-headers order ((


            mime_part_heads = tuple(k.lower() for k in part.keys())
            logger.debug('>>>'+str(mime_part_heads))
            logger.debug(tuple(head_name for head_name in needed_heads if mime_part_heads.count(head_name)))
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

    def get_text_mime_part(self):

        # partial support of asian encodings, just to decode in UTF without exceptions
        # and normilize with NFC form: one unicode ch per symbol
        langs_map = {
                        'russian'   :  ['koi8','windows-1251','cp866', 'ISO_8859-5','Latin-?5'],
                        'french'    :  ['ISO_8859-[19]','Latin-?[19]','CP819', 'windows-1252'],
                        'jis'       :  ['shift_jis','ISO-2022-JP','big5']
        }

        for p in iterators.typed_subpart_iterator(self.msg):
            (decoded_line, decode_flag, dammit_obj) = [None]*3
            if p.get('Content-Transfer-Encoding'):
                decode_flag=True
            try:
            # show must go on
                decoded_line = p.get_payload(decode=decode_flag)
                dammit_obj = UnicodeDammit(decoded_line, is_html=False)

            except Exception as err:
                #logger.debug(err)
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
            l = filter(lambda lang_header: re.match(r'(Content|Accept)-Language', lang_header), map(itemgetter(0),self.msg.items()))[-1:]
            if l:
                lang = ''.join(self.msg.get(''.join(l)).split('-')[:1])

            yield (decoded_line, p.get_content_type(), lang)

    def get_url_obj_list(self):

        url_list = list()
        for line, content_type, lang in list(self.get_text_mime_part()):
            if 'html' in content_type:
                soup = BeautifulSoup(line)
                if soup.a:
                    url_list.extend([unicode(x) for x in soup.a])
            else:
                url_regexp= ur'(((https?|ftps?):\/\/)|www:).*'
                url_list.extend(filter(lambda url: re.search(url_regexp, url, re.I), [l.strip() for l in line.split()]))


        if url_list:
            url_list = [urlparse(i) for i in url_list]

        # todo: make it as lazy computing value
        return url_list

    def get_net_location_list(self, url_list=None):

        netloc_list = list()
        if url_list is None:
            url_list = self.get_url_obj_list()

        for url in url_list:
            if url.netloc:
                netloc_list.append(url.netloc)
                continue
            elif url.path:
                netloc_list.append(url.path.strip('www.'))
                continue

        netlocations = [ domain for domain in  netloc_list if domain ]

        only_str_obj = [ i for i in netloc_list if type(i) is str ]

        if only_str_obj:
            only_str_obj  = [i.decode('utf8') for i in only_str_obj]
            netloc_list = only_str_obj + [ i for i in netlocations if type(i) is unicode ]

            logger.debug("NETLOC: >>>>>"+str(netloc_list))

        return netloc_list

    def get_sentences(self, remove_url=True):

        tokenizer = PunktSentenceTokenizer()


        for raw_line, mime_type, lang in tuple(self.get_text_mime_part()):
            logger.debug('raw_line :'+raw_line)
            logger.debug('mime_type :'+mime_type)
            logger.debug('lang :'+lang)

            if 'html' in mime_type:
                soup = BeautifulSoup(raw_line)
                if not soup.body:
                    continue
                # cause exactly sentences are needed, soup.body.strings returns lines+0d0a
                lines = tuple(soup.body.strings)
                raw_line = ''.join(lines)
                logger.debug(u'raw_line_from_html >>'+raw_line)
            #logger.debug(raw_line)
            #logger.debug(tokenizer.tokenize(raw_line))
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

        tokenizer = WordPunctTokenizer()
        #punct_extractor = RegexpTokenizer("[\w']+", gaps=True)

        # todo: while true ?
        for pt in tuple(self.get_sentences()):
            tokens = tuple(tokenizer.tokenize(sent) for sent in pt)
            tokens = reduce(add, tokens)
            #logger.debug("tokens: "+str(tokens))
            lang = self.get_lang(tokens)
            logger.debug(lang)

            if lang in self.SUPPORT_LANGS_LIST:
                #todo: create stopwords list for jis ,
                tokens = tuple(word for word in tokens if word not in stopwords.words(lang))
                #logger.debug('before stem: '+str(tokens))
                tokens = tuple(SnowballStemmer(lang).stem(word) for word in tokens)
                #logger.debug("tokens list: "+str(tokens))

            yield tokens

    def get_html_parts(self, mime_parts_list=None):

        if mime_parts_list is None:
            mime_parts_list = self.get_text_mime_part()

        while(True):
            mime_text_part, content_type, lang = next(mime_parts_list)
            if 'html' in content_type:
                soup = BeautifulSoup(mime_text_part)
                if not soup.body:
                    continue

                yield soup

'''''

if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)

'''''