# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii, zlib, math

from urlparse import urlparse
from operator import add
from collections import defaultdict, namedtuple

from nltk.tokenize import RegexpTokenizer
from nltk.corpus import stopwords
from nltk.stem import SnowballStemmer
from nltk.probability import FreqDist, ConditionalFreqDist

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(filename)s: %(message)s')
ch = logging.StreamHandler(sys.stdout)
logger.addHandler(ch)

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
    Keeps Frankenstain's DNAs.
    """

    INIT_SCORE = 0
    MIN_TOKEN_LEN = 3
    NEST_LEVEL_THRESHOLD = 2

    # just for debugging new regexps
    @staticmethod
    def _get_regexp_(regexp_list, compilation_flag=None):
        '''
        :param regexp_list: list of scary regexes
        :param compilation_flag: re.U, re.M, etc
        :return: list of compiled RE.objects, for check this trash faster and easier
        '''
        # todo: also make it as iterator
        compiled_list = []

        for exp in regexp_list:
            #logger.debug(exp)
            if compilation_flag is not None:
                exp = re.compile(exp, compilation_flag)
            else:
                exp = re.compile(exp)

            compiled_list.append(exp)

        return compiled_list

    def get_text_parts_metrics(self, score, regs_list, sent_list=None):
        '''
        Maps input regexp list to each sentence one by one
        :return: penalising score, gained by sentenses
        '''
        print("score "+str(score))
        print("regs_list "+str(regs_list))
        text_score = self.INIT_SCORE

        if sent_list is None:
            sents_generator = self._get_sentences_()
            print("sent_lists >>"+str(self._get_sentences_()))

        while(True):
            try:
                for reg_obj in regs_list:
                    text_score += len(filter(lambda s: reg_obj.search(s,re.I), next(sents_generator)))*score
                    print("text_score: "+str(text_score))
            except StopIteration as err:
                break

        return text_score

    def get_html_parts_metrics(self, score, tags_map, mime_parts_list=None):
        '''
        1. from the last text/html part creates HTML-body skeleton from end-tags,
            takes checksum from it, cause spammer's and info's/net's HTML patterns
            are mostly the same;
        2. if HTML-body includes table - analyze tags and values inside, cause
            info's and net's HTML-patterns mostly made up with pretty same <tables>;

        :param tags_map: expected <tags attribute="value">, described by regexes;
        :return: penalizing score and checksum for body;
        '''

        (html_score, html_checksum) = [self.INIT_SCORE]*2
        attr_value_pair = namedtuple('attr_value_pair','name value')
        html_skeleton = list()

        print("tags_map: "+str(tags_map))
        if mime_parts_list is None:
            mime_parts_list = self._get_text_mime_part_()

        while(True):
            try:
                mime_text_part, content_type, lang = next(mime_parts_list)
            except StopIteration as err:
                break

            print(type(mime_text_part))
            print(">>>>"+str(content_type))
            print(">>>"+str(lang))
            if 'html' in content_type:
                soup = BeautifulSoup(mime_text_part)
                if not soup.body:
                    continue

                # get table checksum
                comments = soup.body.findAll( text=lambda text: isinstance(text, Comment) )
                [comment.extract() for comment in comments]
                # leave only closing tags struct
                reg = re.compile(ur'<[a-z]*/[a-z]*>',re.I)
                # todo: investigate the order of elems within included generators
                html_skeleton.extend(t.encode('utf-8', errors='replace') for t in tuple(reg.findall(soup.body.prettify(), re.M)))

                soup_attrs_list = filter(lambda t: t, [soup.body.find_all(tag) for tag in tags_map.iterkeys()])
                logger.debug('soup_attrs_list: '+str(soup_attrs_list))

                if not soup.body.table:
                    continue

                # analyze tags and their attributes
                soup_attrs_list = filter(lambda y: y, [ x.attrs.items() for x in soup.body.table.findAll(tag) ])
                print(soup_attrs_list)
                logger.debug('soup_attrs_list '+str(soup_attrs_list))
                if not soup_attrs_list:
                    continue

                soup_attrs_list = [ attr_value_pair(*obj) for obj in reduce(add, soup_attrs_list) ]
                print(soup_attrs_list)
                print('type of parsing line in reg_obj: '+str(type(tags_map.get(tag))))
                compiled_regexp_list = self._get_regexp_(tags_map.get(tag), re.U)

                pairs = list()
                for key_attr in compiled_regexp_list: # expected_attrs_dict:
                    print(key_attr)
                    pairs = filter(lambda pair: key_attr.match(pair.name, re.I), soup_attrs_list)
                    print(pairs)

                    check_values = list()
                    if pairs:
                        check_values = filter(lambda pair: re.search(ur''+expected_attrs_dict.get(key_attr), pair.value, re.I), soup_attrs_list)
                        html_score += score*len(check_values)

        #logger.debug('HTML CLOSED:'+str(list(html_skeleton)))
        html_checksum = binascii.crc32(''.join(html_skeleton))
        print(html_checksum)
        return html_score, html_checksum

    def get_text_parts_avg_entropy(self):

        # just for fun
        (total_h, n) = [self.INIT_SCORE]*2

        for tokens in self._get_stemmed_tokens_():
            n +=1
            freqdist = FreqDist(tokens)
            probs = [freqdist.freq(l) for l in FreqDist(tokens)]
            print('P >>> '+str(probs))
            total_h += -sum([p * math.log(p,2) for p in probs])
            total_h = total_h/n

        return total_h

    def get_text_compress_ratio(self):

        all_text_parts = list(self._get_stemmed_tokens_())
        print(all_text_parts)
        if all_text_parts:
            all_text = ''.join(reduce(add,all_text_parts))
            print(type(all_text))
            return float(len(zlib.compressobj(all_text)))/len(all_text)


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


if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)
