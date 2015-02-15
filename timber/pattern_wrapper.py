# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii, zlib

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

from msg_wrapper import BeautifulBody



class BasePattern(BeautifulBody):
    """
    Base parent class for created all other four pattern classes.
    Provides some basic chekcs for email's bodies.
    """

    INIT_SCORE = 0
    MIN_TOKEN_LEN = 3
    NEST_LEVEL_THRESHOLD = 2

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

    def get_text_parts_metrics(self, score, regs_list, sent_list=list()):

        text_score = self.INIT_SCORE

        if not sent_list and not self._get_sent_vect_():
            return text_score
        elif not sent_list:
            sent_lists = list(self._get_sent_vect_())

        compiled_regs_list = self._get_regexp_(regs_list, re.U)
        for reg_obj in compiled_regs_list:
            text_score += len(filter(lambda : reg_obj.search(sentence,re.I), sent_lists))

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

        return html_score, html_checksum

    def get_text_parts_avg_entropy(self):

        # just for fun
        total_h = self.INIT_SCORE
        all_text_parts = self._get_stemmed_tokens_vect_()
        n = len(list(all_text_parts))

        while(all_text_parts):
            tokens = next(all_text_parts)
            freqdist = FreqDist(tokens)
            probs = [freqdist.freq(l) for l in FreqDist(tokens)]
            total_h += -sum([p * math.log(p,2) for p in probs])

        return (total_h/n)

    def get_text_compress_ratio(self):

        all_text_parts = list(self._get_stemmed_tokens_vect_())
        if all_text_parts:
            all_text = ''.join(reduce(add,all_text_parts))
            return float(len(zlib.compress(all_text)))/len(all_text)


class PatternFactory(object):
    """ Factory for creating Frankenstines on the fly """

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


