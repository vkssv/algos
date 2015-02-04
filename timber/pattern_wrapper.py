# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii
from email import iterators, base64mime, quoprimime
from urlparse import urlparse
from bs4 import BeautifulSoup, Comment, ResultSet
from operator import add
from collections import defaultdict, namedtuple

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)


class dream_bag(list):
    """just tired to perfom filter(lambda x: x, list)"""
    def sweep(self):
        for obj in self:
            if obj:
                yield(obj)


class BasePattern(object):
    """Base parent class for created all other pattern classes.
    Provides access to some pre-parsed attributes of msg"""
    INIT_SCORE = 0
    MIN_TOKEN_LEN = 3
    NEST_LEVEL_THRESHOLD = 2
 
    def __init__(self, msg):
        self.msg = msg

    # just for debugging new regexp on the fly
    def _get_regexp_(self, regexp_list, compilation_flag=0):
        compiled_list = []

        for exp in regexp_list:
            logger.debug(exp)
            if compilation_flag:
                exp = re.compile(exp, compilation_flag)
            else:
                exp = re.compile(exp)

            compiled_list.append(exp)

        return(compiled_list)

    def _get_text_parts_(self):
    # todo: make this as normal people do with yield, ужас просто
    # returns list of text body's parts: each in one unicode line
        #encodings = {
        #                'quoted-printable'  : lambda payload: quoprimime.body_decode(payload),
        #                'base64'            : lambda payload: base64mime.body_decode(payload)
        #            }

        self.text_parts = []

        decoded_line = ''
        parts_iterator = iterators.typed_subpart_iterator(self.msg)

        while(True):
            try:
                part = next(parts_iterator)
                #logger.debug('TEXT PART:')
                #logger.debug(part)

            except StopIteration as err:
                break

            if part:
                decoded_line = part.get_payload(decode=True)
                #logger.debug(part.get_content_charset())


                #if part.get('Content-Transfer-Encoding') in encodings.keys():
                #    f = encodings.get(part.get('Content-Transfer-Encoding'))
                #    decoded_line = f(decoded_line)

                #logger.debug('decoded_line: >'.upper()+str((decoded_line,))+'<')
                #logger.debug('Type of line >>>>>>>>>'+str(type(decoded_line)))

                charset_map = {'x-sjis': 'shift_jis'}
                # Python2.7 => try to decode all lines from their particular charsets to unicode,
                # add U+FFFD, 'REPLACEMENT CHARACTER' if faces with UnicodeDecodeError
                for charset in (part.get_content_charset(), part.get_charset()):
                    if charset:
                        if charset in charset_map.keys():
                            charset =  charset_map.get(charset)

                        #logger.debug(charset)
                        decoded_line = decoded_line.decode(charset, 'replace')
                        break

                if not len(decoded_line.strip()):
                    continue

                self.text_parts.append((decoded_line, part.get_content_type()))

        return (self.text_parts)

    def _get_mime_struct_(self):
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

        return(self.mime_parts)

    def get_rcvds(self, rcvds_num=0):
        # parse all RCVD headers by default if rcvds_num wasn't defined
        self.parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in self.msg.get_all('Received')])[ -1*rcvds_num : ]
        return (self.parsed_rcvds)

    def get_nest_level(self):

        mime_parts = self._get_mime_struct_()
        self.level = len(filter(lambda n: re.search(r'(multipart|message)\/',n,re.I),mime_parts.keys()))

        return(self.level)

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
            all_text_parts = self._get_text_parts_()
            if not all_text_parts:
                return text_score

            compiled_regs_list = self._get_regexp_(regs_list, re.U)
            for mime_text_part, content_type in all_text_parts:
                if 'plain' in content_type and mime_text_part.strip():
                    for regexp_obj in compiled_regs_list:
                        text_score += len(filter(lambda line: regexp_obj.search(line,re.I), mime_text_part.split('\r\n')))

        return text_score

    def get_html_parts_metrics(self, score, regs_list, tags_map):

        (html_score, text_score, html_checksum) = [self.INIT_SCORE]*3
        attr_value_pair = namedtuple('attr_value_pair','name value')

        all_text_parts = self._get_text_parts_()
        if not all_text_parts:
            return html_score, text_score, html_checksum

        logger.debug('TEXT_PARTS: '+str(all_text_parts))
        html_skeleton = list()
        for mime_text_part, content_type in all_text_parts:
            if 'html' in content_type:
                soup = BeautifulSoup(mime_text_part)
                if not soup.body:
                    continue

                # analyze pure text content within tags
                text_score += self.get_text_parts_metrics(score, regs_list, soup.body.stripped_string)

                if not soup.body.table:
                    continue

                # get table checksum
                comments = soup.body.table.findAll( text=lambda text: isinstance(text, Comment) )
                [comment.extract() for comment in comments]
                # leave only closing tags struct
                reg = re.compile(ur'<[a-z]*/[a-z]*>',re.I)
                # todo: investigate the order of elems within included generators
                html_skeleton.append(t.encode('utf-8', errors='replace') for t in tuple(reg.findall(soup.body.table.prettify(),re.M)))

                soup_attrs_list = list(dream_bag([soup.body.table.find_all(tag) for tag in tags_map.iterkeys()]).sweep())
                print('type of obj'+str(type(soup_attrs_list)))
                print('>>>>>>>>>>>>>>>>'+str([type(o) for o in soup_attrs_list]))
                #soup_attrs_list = filter(lambda t: t, [soup.body.table.find_all(tag) for tag in tags_map.iterkeys()])
                logger.debug('soup_attrs_list: '+str(soup_attrs_list))

                if not soup_attrs_list:
                    continue

                # analyze tags and their attributes
                # convert soup_attrs_list to list, cause type(soup.body.findAll('p') = <class 'bs4.element.ResultSet'>,
                if ResultSet in [type(x) for x in soup_attrs_list]:
                    soup_attrs_list = list(soup_attrs_list)

                #soup_attrs_list = filter(lambda t: t, [ t.attrs.items() for t in soup_attrs_list ])
                soup_attrs_list = list(dream_bag(filter(lambda t: t, [ t.attrs.items() for t in soup_attrs_list ])).sweep())
                logger.debug('soup_attrs_list '+str(soup_attrs_list))
                if not soup_attrs_list:
                    continue

                soup_attrs_list = filter(lambda t: t,[ attr_value_pair(*obj) for obj in reduce(add, soup_attrs_list) ])
                    #expected_attrs_dict = tags_map.get(tag)
                compiled_regexp_list = self._get_regexp_(tags_map.get(tag), re.U)
                pairs = list()

                for key_attr in compiled_regexp_list: #expected_attrs_dict:
                    pairs = filter(lambda pair: key_attr.match(pair.name, re.I), soup_attrs_list)
                    check_values = list()
                    if pairs:
                        check_values = filter(lambda pair: re.search(ur''+expected_attrs_dict.get(key_attr), pair.value, re.I), soup_attrs_list)
                        html_score += score*len(check_values)

        table_checksum = binascii.crc32(''.join(html_skeleton))

        return html_score, text_score, html_checksum

    def get_body_entropy_metrics():
        metrics = (parts_compress_ratio, max_part_entropy)
        metrics = [INIT_SCORE]*len(metrics)
        # PARTS_COMPRESS_RATIO ? (compress only pure text lines):
        # probably will be very high for infos and nets, cause they all have in bodies:
        # ...
        #   multipart/alternative
        #       text/plain
        #       text/html
        # ...
        # for bodies with one or more parts - will be some expected values in expected boundaries
        # (high for hams, not so high - for spams)
        # parts, which contain absolutely the same text => high redunduncy => low entropy => good compression
        # investigate more about the efficiancy of compression algos on short text pieces, LZW 12bit ?
        # http://www.pal-blog.de/entwicklung/perl/compressing-test-for-short-strings.html
        #
        # MAX_PART_ENTROPY ? (maybe... calculate on fly for each line into the current text part and each time keep the max,
        # it has to have some distribution of peak values for different classes)

        return(metrics)


class PatternFactory(object):
    """Factory for creating on the fly set of rules for desired class"""

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


