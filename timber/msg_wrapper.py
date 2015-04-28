#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-

"""
    Extract and parse email's headers and mime-parts
"""

import sys, logging, re

from email import iterators, header, utils
from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple

try:
    from bs4 import BeautifulSoup, UnicodeDammit
    from nltk.tokenize import WordPunctTokenizer, PunktSentenceTokenizer
    from nltk.corpus import stopwords
    from nltk.stem import SnowballStemmer
except ImportError as err:
    logger.error(str(err))
    sys.exit(1)

from timber_exceptions import NaturesError

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(levelname)s %(funcName)s: %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#ch.setLevel(logging.DEBUG)
#ch.setFormatter(formatter)
#logger.addHandler(ch)

#from email import parser
#parser = parser.Parser()
#with open('/home/calypso/debug/spam/0000000175_1422266129_bc57f700.eml','rb') as f:
#    M = parser.parse(f)


class BeautifulBody(object):
    """
    Base class for happy life with email.message objects,
    some kind of great BeautifulSoup class from bs4.
    """

    __URLINTEXT_PAT = re.compile(ur'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))'.lower(), re.M)

    DEFAULT_MAX_NEST_LEVEL = 30
    DEFAULT_LANG = 'english'
    DEFAULT_CHARSET = 'utf-8'
    SUPPORT_LANGS_LIST = ('english', 'french', 'russian')

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

    @classmethod
    def _get_unicoded_value(cls, raw_line, encoding=None):

        dammit_obj = UnicodeDammit(raw_line, [encoding], is_html=False)
        #logger.debug(dammit_obj.unicode_markup.strip())

        return dammit_obj.unicode_markup.strip()

    @classmethod
    def get_lang(cls, tokens_list, return_value=None):

        lang = cls.DEFAULT_LANG

        stopwords_dict = dict([(lang, set(stopwords.words(lang))) for lang in cls.SUPPORT_LANGS_LIST])
        tokens_set = set(tokens_list)
        lang_ratios = [(x, len(tokens_set.intersection(stopwords_dict.get(x)))) for x in stopwords_dict.keys()]
        #logger.debug(lang_ratios)
        l, ratio = sorted(lang_ratios, key=itemgetter(1), reverse=True)[0]
        if ratio > 0:
            # cause we can have here: [('russian', 0), ('french', 0), ('english', 0)]
            return l
        else:
            logger.info('can\'t define language for this token list >> '+str(tokens_list))
            return return_value

    def get_rcvds(self, rcvds_num=0):
        '''
        :param rcvds_num: N curious Received headers from \CRLF\CRFL to top,
                            N defined in each Pattern ;
        :return: left parts of Received header's values, everything before ';'
        '''
        # parse all Received: headers by default if rcvds_num wasn't defined
        parsed_rcvds = tuple(rcvd.partition(';')[0] for rcvd in self.msg.get_all('Received',' '))[ -1*rcvds_num : ]
        logger.debug(str(parsed_rcvds))
        return parsed_rcvds

    def get_addr_values(self, header_value):
        '''
        :header_value - value of particular header, which can store < mailbox name > + < address >
        :return: tuple of tuples (< mail box name (utf-8)>, < address (without angle braces) >)
        '''
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

        pairs = list()
        for t in temp:
            realname_parts, addr = t
            
            value = u''
            for part in realname_parts:
                if len(part)==0:
                    continue
                logger.warn(part)
                value += self._get_unicoded_value(*(reduce(add,part)))

            pairs.append((value, addr))

        pairs = tuple((p.realname, re.sub(r'<|>','',p.address)) for p in tuple(addr_value(*pair) for pair in pairs))
        logger.debug(str(pairs))
        return pairs

    def get_smtp_originator_domain(self):
        '''
        :return: originator domain from 'Received:' headers values
        (MAIL FROM: SMTP header)
        '''

        regexp = re.compile(r'(@|(?<=helo)\s?=\s?|(?<=from)\s+)?([a-z0-9-]{1,60}\.){1,3}[a-z]{2,10}', re.M)
        smtp_sender_domain = ''

        l = filter(lambda value: regexp.search(value), self.get_rcvds())
        logger.debug(l) # check that regexp matched exactly first
        if l:
            orig_domain = reduce(add,l)

            logger.debug((orig_domain,))
            orig_domain = (regexp.search(orig_domain)).group(0)
            smtp_sender_domain = orig_domain.strip('.').strip('@').strip('=').strip()

            logger.debug('smtp originator domain : '+str(smtp_sender_domain))

        return smtp_sender_domain

    def get_dkim_domains(self):
        '''
        :return: list of domains, which names were used in DKIM signing
        '''
        # if msg has not these headers one space char will be returned, in case of escaping exceptions
        values = [ el.split(';') for el in [self.msg.get(dkim_head,'\x20') for dkim_head in ['DKIM-Signature','DomainKey-Signature']]]
        values = reduce(add,values)
        values = [i.strip() for i in values if i.strip().startswith('d=')]
        return [i.strip('d=') for i in values]

    def get_decoded_subj(self):
        '''
        parses and decodes 'Subject' header value,
        :return:
                < raw subject line in utf8 >,
                < tuple of subject tokens without stopwords in utf8 >,
                < list of encodings >
        '''

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
        parses and keeps into dict values of MIME-part headers
        :return: dict { mime_type  : [attribute : value] }
        """
        mime_parts = defaultdict(list)

        needed_heads = ['content-type', 'content-transfer-encoding', 'content-id', 'content-disposition',\
                            'content-description','content-class']

        for part in self.msg.walk():

            part_key = 'text/plain'
            mime_part_heads = tuple(k.lower() for k in part.keys())
            for head in tuple(head_name for head_name in needed_heads if mime_part_heads.count(head_name)):

                if head == 'content-type':
                    part_key = part.get(head)
                    #logger.debug(part_key)
                    part_key = part_key.partition(';')[0].strip()
                    added_value = (re.sub(part_key+';','',part.get(head).strip(),re.M)).strip()
                    mime_parts[part_key].append(added_value.lower())
                    #logger.debug(mime_parts)

                else:
                    mime_parts[part_key].append(part.get(head).strip())
                    #logger.debug(mime_parts)
                    #part_dict[head] = part.get(head).strip()

        mime_parts = dict((k,tuple(v)) for k,v in mime_parts.items())
        logger.debug(str(mime_parts))

        return mime_parts

    def get_text_mime_part(self):
        '''
        generator
        :return: < line with text from mime-part in utf8 > ,
                 < Content-Type value >,
                 < lang value >
        '''

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

            l = filter(lambda lang_header: re.match(r'(Content|Accept)-Language', lang_header), map(itemgetter(0),self.msg.items()))[-1:]
            if l:
                lang = ''.join(self.msg.get(''.join(l)).split('-')[:1])

            yield(decoded_line, p.get_content_type(), lang)

    def get_url_obj_list(self):
        '''
        parses, keeps and transforms all
        URL-objects from bodies to urlparse objects
        :return: list of urlparse-objects
        '''

        url_list = list()
        for line, content_type, lang in list(self.get_text_mime_part()):
            if 'html' in content_type:
                soup = BeautifulSoup(line)
                if soup.a:
                    url_list.extend([unicode(x) for x in soup.a])
            else:
                url_regexp= ur'(((https?|ftps?):\/\/)|www:).*'
                url_list.extend(filter(lambda url: re.search(url_regexp, url.lower()), [l.strip() for l in line.split()]))


        if url_list:
            url_list = [urlparse(i) for i in url_list]

        return url_list

    def get_net_location_list(self, url_list=None):
        '''

        :param url_list --> list of urlparse objects
        :return: list of domains from crunched URLs
        '''

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

            #logger.debug(str(netloc_list))

        return netloc_list

    def get_sentences(self, remove_url=True):
        '''
        generator
        :param remove_url --> replace URLs in sentences with one space char ;
        :return: tuple of sentences for each mime-part ;
        '''

        tokenizer = PunktSentenceTokenizer()

        for raw_line, mime_type, lang in tuple(self.get_text_mime_part()):

            if 'html' in mime_type:
                soup = BeautifulSoup(raw_line)
                if not soup.body:
                    continue
                # cause exactly sentences are needed, soup.body.strings returns lines+0d0a
                lines = tuple(soup.body.strings)
                raw_line = ''.join(lines)

            try:
                sents = tuple(tokenizer.tokenize(raw_line))
            except Exception as err:
                sents = tuple(raw_line)

            if remove_url:
                sents = tuple(map(lambda sent: self.__URLINTEXT_PAT.sub(' ', sent.lower()), sents))

            sents = (s.strip().lower() for s in sents)
            sents = tuple(s for s in tuple(sents) if s)
            if len(sents) == 0:
                continue

            yield sents

    def get_stemmed_tokens(self):
        '''
        generator
        :return list of tokens, does not keep its order as in sentence
        '''
        tokenizer = WordPunctTokenizer()
        #punct_extractor = RegexpTokenizer("[\w']+", gaps=True)

        for pt in tuple(self.get_sentences()):
            tokens = tuple(tokenizer.tokenize(sent) for sent in pt)
            tokens = reduce(add, tokens)
            # reduce returns list not tuple
            #logger.warn("tokens: "+str(type(tokens)))
            lang = self.get_lang(tokens)
            #logger.debug(lang)

            if lang in self.SUPPORT_LANGS_LIST:
                # todo: create stopwords list for jis ,
                tokens = [word for word in tokens if word not in stopwords.words(lang)]
                tokens = [SnowballStemmer(lang).stem(word) for word in tokens]
                #logger.warn("tokens list: "+str(type(tokens)))

            yield tokens

    def get_html_parts(self, mime_parts_list=None):
        '''
        generator
        wrap up all text/html parts with BeautifulSoup class

        :param mime_parts_list --> list with preparced mime-parts
        :return: BeautifulSoup instance
        '''

        if mime_parts_list is None:
            mime_parts_list = self.get_text_mime_part()

        while(True):
            mime_text_part, content_type, lang = next(mime_parts_list)
            if 'html' in content_type:
                soup = BeautifulSoup(mime_text_part)
                if not soup.body:
                    continue

                yield soup

