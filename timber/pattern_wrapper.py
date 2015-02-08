# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii

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

class BasePattern(object):
    """
    Base parent class for created all other four pattern classes.
    Provides access to some pre-parsed attributes of msg.
    """

    INIT_SCORE = 0
    MIN_TOKEN_LEN = 3
    NEST_LEVEL_THRESHOLD = 2
    LANG = 'english'
 
    def __init__(self, msg):
        self.msg = msg

    # just for debugging new regexp on the fly
    @staticmethod
    def _get_regexp_(regexp_list, compilation_flag=None):
        '''
        @param regexp_list: list of scary regexes
        @param compilation_flag: re.U, etc
        :return: list of compiled RE.objects, faster and easy for checking this trash
        '''
        # todo: also make it as iterator
        compiled_list = []

        for exp in regexp_list:
            #logger.debug(exp)
            if compilation_flag:
                exp = re.compile(exp, compilation_flag)
            else:
                exp = re.compile(exp)

            compiled_list.append(exp)

        return compiled_list

    def _get_mime_struct_(self):
        '''
        :return:
        '''
        logger.debug("IN get_mime_struct")
        self.mime_parts= defaultdict(list)

        mime_heads = ['Content-Type', 'Content-Transfer-Encoding', 'Content-Id', 'Content-Disposition',\
                      'Content-Description','Content-Class']

        for part in self.msg.walk():

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

                    self.mime_parts[part_key].append(added_value.lower())
                    #part_dict[head] = re.sub(part_key+';','',part.get(head),re.I)

                else:
                    self.mime_parts[part_key].append(part.get(head).strip())
                    #part_dict[head] = part.get(head).strip()

        #dself.mime_parts[(part_key.partition(';')[0]).strip()] = part_dict
        logger.debug("DEF_DICT"+str(self.mime_parts))
        self.mime_parts = dict([(k,tuple(v)) for k,v in self.mime_parts.items()])
        logger.debug("DICT"+str(self.mime_parts))

        return self.mime_parts

    def _get_text_mime_part_(self):
        '''
        :return: list of tuples with full decoded text/mime parts,
                    i.e. transport decoding + charset decoding, if lines are
                    not in utf-8
        '''
        lang = self.LANG
        parts_iterator = iterators.typed_subpart_iterator(self.msg)
        while(True):
            try:
                part = next(parts_iterator)
                #logger.debug('TEXT PART:')
                #logger.debug(part)
            except StopIteration as err:
                break

            if part:
                # can't use assert here, cause it can return empty lines
                decoded_line = part.get_payload(decode=True)
                #logger.debug(part.get_content_charset())

                # partial support of asian encodings, just to decode in UTF without exceptions
                charset_map = {'x-sjis': 'shift_jis'}
                langs_map = {
                                'russian':  ['koi8','windows-1251','cp866', 'ISO_8859-5','Latin(-)?5'],
                                'french' :  ['ISO_8859-([19]','Latin(-)?[19]','CP819', 'windows-1252']
                }

                # Python2.7 => try to decode all lines from their particular charsets to unicode,
                # add U+FFFD, 'REPLACEMENT CHARACTER' if faces with UnicodeDecodeError

                for charset in (part.get_content_charset(), part.get_charset()):
                    if charset and charset.lower() != 'utf-8':
                        if charset in charset_map.keys():
                            charset =  charset_map.get(charset)
                            lang = 'asian'

                        else:
                            for lang in langs_map.iterkeys():
                                if filter(lambda ch: re.match(ch, charset, re.I), langs_map.get(lang))
                                    break

                        #logger.debug(charset)
                        decoded_line = decoded_line.decode(charset, 'replace')
                        break

                if not len(decoded_line.strip()):
                    continue

                yield(decoded_line, part.get_content_type(), lang)

    def _get_pure_text_part_(self, stemmer, lines_generator=list()):
        '''
        @param stemmer: StemmerClass from nltk
        @param lines_generator: iterator object with tuples(fully_decoded_line, text/mime_type),
                a line per text/mime part
        :return: iterator with pure stemmed tokens lists, a list per text/mime part
        '''

        raw_text_parts = self._get_text_mime_parts_()

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
            pure_list = [word for word in words if word not in nltk_obj_dict.get(lang).stop]
            pure_list = [word for word in pure_list if word not in nltk_obj_dict.get(self.LANG).stem]

            yield pure_list

    def get_rcvds(self, rcvds_num=0):
        # parse all RCVD headers by default if rcvds_num wasn't defined
        self.parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in self.msg.get_all('Received')])[ -1*rcvds_num : ]

        return self.parsed_rcvds

    def get_nest_level(self):

        mime_parts = self._get_mime_struct_()
        self.level = len(filter(lambda n: re.search(r'(multipart|message)\/',n,re.I),mime_parts.keys()))

        return self.level

    def get_url_list(self):

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

    def get_text_parts_metrics(self, score, regs_list, lines_generator=list()):

        text_score = self.INIT_SCORE
        lines = []
        if not lines_generator:
            all_text_parts = self._get_pure_text_part_()
            if not all_text_parts:
                return text_score

            compiled_regs_list = self._get_regexp_(regs_list, re.U)
            for mime_text_part, content_type in all_text_parts:
                if 'plain' in content_type and mime_text_part.strip():
                    for regexp_obj in compiled_regs_list:
                        text_score += len(filter(lambda line: regexp_obj.search(line,re.I), mime_text_part.split('\r\n')))

        return text_score

    def get_html_parts_metrics(self, score, regs_list, tags_map):

        (html_score, html_checksum) = [self.INIT_SCORE]*3
        attr_value_pair = namedtuple('attr_value_pair','name value')

        all_mime_parts = self._get_text_mime_part_()
        if not all_mime_parts:
            return html_score, html_checksum

        logger.debug('TEXT_PARTS: '+str(all_text_parts))
        html_skeleton = list()
        for mime_text_part, content_type, lang in all_text_parts:
            if 'html' in content_type:
                soup = BeautifulSoup(mime_text_part)
                if not soup.body.table:
                    continue

                # get table checksum
                comments = soup.body.table.findAll( text=lambda text: isinstance(text, Comment) )
                [comment.extract() for comment in comments]
                # leave only closing tags struct
                reg = re.compile(ur'<[a-z]*/[a-z]*>',re.I)
                # todo: investigate the order of elems within included generators
                html_skeleton.extend(t.encode('utf-8', errors='replace') for t in tuple(reg.findall(soup.body.table.prettify(), re.M)))

                soup_attrs_list = filter(lambda t: t, [soup.body.table.find_all(tag) for tag in tags_map.iterkeys()])
                logger.debug('soup_attrs_list: '+str(soup_attrs_list))

                if not soup_attrs_list:
                    continue

                # analyze tags and their attributes
                soup_attrs_list = filter(lambda y: y, [ x.attrs.items() for x in soup.body.table.findAll(tag) ])

                logger.debug('soup_attrs_list '+str(soup_attrs_list))
                if not soup_attrs_list:
                    continue

                soup_attrs_list = [ attr_value_pair(*obj) for obj in reduce(add, soup_attrs_list) ]
                compiled_regexp_list = self._get_regexp_(tags_map.get(tag), re.U)

                pairs = list()
                for key_attr in compiled_regexp_list: #expected_attrs_dict:
                    pairs = filter(lambda pair: key_attr.match(pair.name, re.I), soup_attrs_list)
                    check_values = list()
                    if pairs:
                        check_values = filter(lambda pair: re.search(ur''+expected_attrs_dict.get(key_attr), pair.value, re.I), soup_attrs_list)
                        html_score += score*len(check_values)

        # logger.debug('HTML CLOSED:'+str(list(html_skeleton)))
        table_checksum = binascii.crc32(''.join(html_skeleton))

        return html_score, text_score, html_checksum

    def get_body_compress_ratio():
        all_text_parts = self._get_pure_text_part_()

        return compress_ratio=42


class PatternFactory(object):
    """ Factory for creating on the fly set of rules for desired pattern class, terrible """

    def New(self, msg, label):
        #logger.debug(label)
        try:

            pattern = importlib.import_module(label + '_pattern')
            # logger.debug ((check.title()).replace('_',''))
            current_obj = getattr(pattern, (label.title() + 'Pattern'))

        except Exception as details:
            raise

        return (current_obj(msg))


MetaPattern = PatternFactory()


