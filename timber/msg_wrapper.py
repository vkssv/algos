#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-

"""
Extracting and pre-processing for basic email's bodies parts,
which can be checked by rules (features-triggers) from each pattern_class.
"""

import sys, os, importlib, logging, re, binascii, unicodedata
import pdb
from email import iterators
from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple

from nltk.tokenize import WordPunctTokenizer, PunktSentenceTokenizer
from nltk.corpus import stopwords
from nltk.stem import SnowballStemmer

from timber_exceptions import NaturesError

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(filename)s: %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#logger.addHandler(ch)

try:
    from bs4 import BeautifulSoup, UnicodeDammit
except ImportError:
    print('Can\'t find bs4 module, probably, it isn\'t installed.')
    print('try: "easy_install beautifulsoup4" or install package "python-beautifulsoup4"')


class BeautifulBody(object):
    """
    Base class for simple life with email.message objects,
    some kind of BeautifulSoup objects from bs4.
    """
    _LANG = 'english'
    _LANGS_LIST = ('english', 'french', 'russian')
    _CHARSET = 'utf-8'
    _MAX_NEST_LEVEL = 30

    def __init__(self, msg):

        if msg.is_multipart():

            be_picky = [
                        (lambda y: y > self._MAX_NEST_LEVEL, lambda m: len(m.get_payload()),' mime parts... I can\'t eat so much, merci!'), \
                        (lambda y: y, lambda m: m.defects,' I don\'t eat such emails, !')
                    ]

            for whim, f, text in be_picky:
                y=f(msg) # cause don't want to calculate it again in exception's text
                if whim(y):
                    raise NaturesError(str(y)+text)

        self._msg = msg

    def _get_rcvds_(self, rcvds_num=0):
        """
        :param rcvds_num:
        :return: left parts of Received header's values, everything before ';'
        """
        # parse all RCVD headers by default if rcvds_num wasn't defined
        self.parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in self._msg.get_all('Received')])[ -1*rcvds_num : ]

        return self.parsed_rcvds

    def _get_trace_crc_(rcvds_vect):

        logger.debug('rcvds_vect:'+str(rcvds_vect))
        traces_dict = {}

        for rcvd_line, n in zip(rcvds_vect, range(len(rcvds_vect))):
            logger.debug(rcvd_line)
            trace = map(lambda x: rcvd_line.replace(x,''),['from','by',' '])[2]
            trace = trace.strip().lower()
            trace = binascii.crc32(trace)

            traces_dict['rcvd_'+str(n)] = trace

        return traces_dict

    # excluded_list=['Received', 'From', 'Date', 'X-.*']
    # header_value_list = [(header1,value1),...(headerN, valueN)] = msg.items() - save the order of heads
    def _get_all_heads_crc_(header_value_list, excluded_list = None):

        vect = dict.fromkeys(['heads_crc','values_crc'])
        logger.debug("header_value_list >>"+str(header_value_list))

        # just to play with itemgetter ))
        heads_vector = tuple(map(itemgetter(0), header_value_list))
        heads_dict = dict(header_value_list)

        if excluded_list:
            for ex_head in excluded_list:
                # can use match - no new lines in r_name
                heads_vector = tuple(filter(lambda h_name: not re.match(ex_head, h_name, re.I), heads_vector[:]))

        values_vector = tuple([heads_dict.get(k) for k in heads_vector])
        #logger.debug('values_vector'+str(values_vector))
        # save the last word
        values_vector = tuple([value.split()[-1:] for value in values_vector[:]])
        #logger.debug('values_vector --->'+str(values_vector))

        vect['heads_crc'] = binascii.crc32(''.join(heads_vector))
        vect['values_crc'] = binascii.crc32(''.join(reduce(add,values_vector)))

        return (vect)

    def _get_addr_values_(head_value=''):
        logger.debug('+++++>'+str(head_value))
        for_crunch = re.compile(r'[\w\.-_]{1,64}@[a-z0-9-]{1,63}(?:\.[\w]{2,4})+',re.I)

        h_value = tuple(decode_header(head_value))
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
        return(tuple(names),tuple(addrs))

    def _get_smtp_domain_(rcvds):
    # get sender domain from the first (by trace) RCVD-field, e.g. SMTP MAIL FROM: value

        regexp = re.compile(r'(@|(?<=helo)\s?=\s?|(?<=from)\s+)?([a-z0-9-]{1,60}\.){1,3}[a-z]{2,10}', re.M)
        orig_domain = ''

        l = filter(lambda value: regexp.search(value), rcvds)
        if l:
            orig_domain = reduce(add,l)
            print('+++++++++++++++++++++++++++++++++++++++')
            print((orig_domain,))
            orig_domain = (regexp.search(orig_domain)).group(0)
            orig_domain = orig_domain.strip('.').strip('@').strip('=').strip()
            print('ORIG_DOMAINS: '+str(orig_domain))

        return(orig_domain)


    def _get_subject_(subj_line, token_len = MIN_TOKEN_LEN):

        logger.debug('SUBJ_LINE: >'+str(subj_line)+'<')
        subj_parts = decode_header(subj_line)
        logger.debug('parts >>>>>'+str(subj_parts))
        subj = u''
        encodings_list = []
        for p in subj_parts:
            logger.debug(p)
            line, encoding = p
            logger.debug('enc:'+str(encoding))
            logger.debug(line)
            if encoding:
                line = line.decode(encoding,'replace')
                encodings_list.append(encoding)
            else:
                try:
                    line = line.decode('utf-8')
                    encodings_list.append('utf-8')
                except UnicodeDecodeError as err:
                    logger.warning('Can\'t decode Subject\'s part: "'+line+'", it will be skipped.')
                    continue

            subj+=line
        # force decode to utf

        words_list = tuple(subj.split())
        # remove short tockens
        words_list = filter(lambda s: len(s)>token_len, words_list[:])
        if not encodings_list:
            encodings_list = ['ascii']

        return(unicodedata.normalize('NFC',subj), words_list, encodings_list)

    def _get_mime_crc_(mime_skeleton_dict, excluded_args_list=['boundary=','charset=']):

        checksum = 0
        logger.debug('EXL:'+str(excluded_args_list))

        items = mime_skeleton_dict.items()

        for prefix in excluded_args_list:
            items = [[k, list(ifilterfalse(lambda x: x.startswith(prefix),v))] for k,v in items]

        if items:
            items = reduce(add,items)
            checksum = binascii.crc32(''.join([''.join(i) for i in items]))

        return checksum

    def _get_mime_struct_(self):
        """
        :return: dict { mime_type  : [attribute : value] }
        """
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

    def  _get_text_mime_part_(self):
        """
        generator of tuples with decoded text/mime part's line and metainfo
        :return: generator of tuples ( decoded line , mime type , lang ) for each text/mime part
        """
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

            lang = self._LANG
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

    def _get_sentences_(self):
        """
        sentences generator
        :return: tuple of sentences for each text/mime part
        """
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

    def _get_stemmed_tokens_(self):
        """
        tokens generator
        :return: stemmed tokens tuple (keeps token's order) for each text/mime part
        """
        tokenizer = WordPunctTokenizer()
        #punct_extractor = RegexpTokenizer("[\w']+", gaps=True)
        stopwords_dict = dict([(lang, set(stopwords.words(lang))) for lang in self._LANGS_LIST])

        for pt in tuple(self._get_sentences_()):
            tokens = tuple(tokenizer.tokenize(sent) for sent in pt)
            tokens = reduce(add,tokens)
            logger.debug("tokens: "+str(tokens))
            if lang == self._LANG:
                # check that it's really english
                tokens_set = set(tokens)
                lang_ratios = [(x, len(tokens_set.intersection(stopwords_dict.get(x)))) for x in stopwords_dict.keys()]
                logger.debug(lang_ratios)
                l, ratio = sorted(lang_ratios, key=itemgetter(1), reverse=True)[0]
                if ratio:
                    lang = l

                logger.debug('lang: '+lang)

            if lang in self._LANGS_LIST:
                #todo: create stopwords list for jis ,
                tokens = tuple(word for word in tokens if word not in stopwords.words(lang))
                logger.debug('before stem: '+str(tokens))
                tokens = tuple(SnowballStemmer(lang).stem(word) for word in tokens)
                logger.debug("tokens list: "+str(tokens))

            yield tokens


if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)

