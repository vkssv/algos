# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii, zlib, math

from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple, Counter, OrderedDict
from itertools import ifilterfalse

from nltk.tokenize import RegexpTokenizer
from nltk.corpus import stopwords
from nltk.stem import SnowballStemmer
from nltk.probability import FreqDist, ConditionalFreqDist

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(filename)s: %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#logger.addHandler(ch)

try:
    from bs4 import BeautifulSoup, Comment
except ImportError:
    print('Can\'t find bs4 module, probably, it isn\'t installed.')
    print('try: "easy_install beautifulsoup4" or install package "python-beautifulsoup4"')

from msg_wrapper import BeautifulBody

class BasePattern(BeautifulBody):
    '''
    Base parent class for created all other four pattern classes.
    Provides some basic checks and metrics for email's headers and bodies.
    Keeps Frankenstein's DNAs.
    '''

    INIT_SCORE = 0 # can redifine for particular set of instanses, => use cls./self._INIT_SCORE in code

    EX_MIME_ATTRS_LIST=['boundary=','charset=']

    # BASE_FEATURES = ('rcvd_traces_num','rcpt_smtp_to', 'rcpt_body_to', 'list', 'avg_entropy')

    def __init__(self, score, **kwds):

        self._penalty_score = score

        super(BasePattern, self).__init__(**kwds)
        base_features = ['from_checksum', 'list_score', 'all_heads_checksum', 'subj_score', 'rcvd_num']

        features_dict = {
                            'rcpt'    :   ['smtp_to','body_to'],
                            'dmarc'   :   ['spf','score'],
                            'url'     :   ['count','distinct_count','sender_count','score', 'avg_len'],
                            'mime'    :   ['nest_level','checksum'],
                            'html'    :   ['checksum','score'],
                            'txt'     :   ['avg_ent','compressed_ratio','score'],
                            'attach'  :   ['count','in_score','score']
        }

        total = list()
        [ total.extend([k+'_'+name for name in features_dict.get(k)]) for k in features_dict.keys() ]

        [ self.__setattr__(f, self.INIT_SCORE) for f in (base_features + total) ]
        print('initialized: '+str(self.__dict__))

        self.get_all_heads_checksum()

        self.rcvd_num = self._msg.keys().count('Received')
        self.__dict__.update(self.get_rcvd_checksum())


        self.get_subj_score()

        logger.debug('BasePattern was created'.upper()+': '+str(id(self)))
        #logger.debug(self.__dict__)
        for (k,v) in self.__dict__.iteritems():
            logger.debug(str(k).upper()+' ==> '+str(v).upper())
        logger.debug("================")
        #logger.debug(BasePattern.__dict__)
        for (k,v) in self.__dict__.iteritems():
            logger.debug(str(k).upper()+' ==> '+str(v).upper())
        logger.debug('size in bytes: '.upper()+str(sys.getsizeof(self, 'not implemented')))


    @staticmethod
    # use it only here for dirty particular needs
    def __unpack_arguments(*args, **kwargs):
        '''
        :todo: + common value validator
        '''
        print(args)
        print(type(args))
        attrs_to_set = [name for name in args if kwargs.has_key(name)]
        print('__unpack_arguments: '+str(attrs_to_set))
        if len(attrs_to_set) == 0:
            return

        attrs_to_set = [(n.upper(), kwargs.get(n)) for n in attrs_to_set]
        [self.__setattr__(key,value) for key,value in attrs_to_set]

        return

    @staticmethod
    def _get_regexp(regexp_list, compilation_flag=None):
        '''
        :param regexp_list: list of scary regexes
        :param compilation_flag: re.U, re.M, etc
        :return: list of compiled RE.objects, check this trash faster and easier
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

    @classmethod
    def excluded_for_hams(cls, *args):
        if cls.__name__ == 'HamPattern':
            return


    # call from each particular pattern
    @excluded_for_hams
    def get_subj_score(self, **kwargs):

        logger.debug('3. >>> SUBJ_CHECKS')

        if self._msg.get("Subject") is None:
            return self.subj_score

        self.__unpack_arguments('subj_rules', **kwargs)
        #:param subj_regs:
        #:param score:
        #:return: <penalizing score for Subj>, <count of tokens in upper-case and in Title>
        #cause russian unconditional spam is more complicated than abusix )

        line, tokens, encodings = self.get_decoded_subj()
        logger.debug('line : '+line)

        compiled_regs = self._get_regexp(self.SUBJ_RULES, re.U)
        # check by regexp rules
        matched = filter(lambda r: r.search(line, re.I), compiled_regs)
        self.subj_score = self._penalty_score*len(matched)

        return self.subj_score

    def get_url_base_features(self):

        # URL_COUNT: url count for infos and nets maybe lies in certain boundaries, \
        # cause they are generated by certain patterns  ));
        # DISTINCT_COUNT: count of different domains from netlocation parts of URLs;
        # SENDER_COUNT: count of domains/subdomains from netlocation parts of URLs,
        # which are the same with sender domain from RCVD-headers.

        # url_count
        url_list = self.get_url_obj_list()
        self.url_count = len(url_list)

        if self.url_count > 0:
            net_location_list = self.get_net_location_list()

            if net_location_list:
                self.url_distinct_count += len(set([d.strip() for d in net_location_list]))
                sender_domain = False
                while not (sender_domain):
                    sender_domain = self.get_smtp_originator_domain()
                    originator = self.get_addr_values(self._msg.get_all('From'))
                    if not originator:
                        return (self.url_count, self.url_distinct_count, self.url_sender_count)

                    orig_name, orig_addr = reduce(add, originator)
                    sender_domain = (orig_addr.split('@')[1]).strip()


                pattern = ur'\.?'+sender_domain.decode('utf-8')+u'(\.\w{2,10}){0,2}'
                self.url_sender_count += len(filter(lambda d: re.search(pattern, d, re.I), net_location_list))

                l = [ len(url) for url in [ obj.geturl() for obj in urls_list ]]
                self.url_avg_len = math.ceil(float(sum(l))/float(len(urls_list)))

        logger.debug((self.url_count, self.url_distinct_count, self.url_sender_count, self.url_avg_len))

        return (self.url_count, self.url_distinct_count, self.url_sender_count, self.url_avg_len)

    def get_url_score(self, **kwargs):

        #:param fqdn_regs:
        #:param txt_regs:
        #:return:

        self.__unpack_arguments('url_fqdn_regexp','url_txt_regexp', **kwargs)

        reg = namedtuple('reg', 'fqdn_regs txt_regs')
        compiled = reg(*(self._get_regexp(l, re.I) for l in (self.URL_FQDN_REGEXP, self.URL_TXT_REGEXP)))

        for reg in compiled.fqdn_regs:
            self.url_score += len(filter(lambda netloc: reg.search(netloc), self.get_net_location_list()))*self._penalty_score

        # url_score
        metainfo_list = list()
        for attr in ['path', 'query', 'fragment']:
            metainfo_list.extend([i.__getattribute__(attr) for i in self.get_url_obj_list()])

        if metainfo_list:
            for reg in compiled.txt_regs:
                self.url_score += len(filter(lambda metainfo: reg.search(metainfo), metainfo_list))*self._penalty_score

        return self.url_score

    def get_mime_nest_level(self):

        mime_parts = self.get_mime_struct()
        level = len(filter(lambda n: re.search(r'(multipart|message)\/',n,re.I), mime_parts.keys()))

        logger.debug('mime_nest_level: '.upper()+str(self.mime_nest_level))
        return self.mime_nest_level

    def get_mime_checksum(self, **kwargs):

        #:param excluded_atrs_list: values of uninteresting mime-attrs
        #:return: 42


        self.__unpack_arguments('ex_mime_attrs_list', **kwargs)
        logger.debug('EXL:'+str(self.EX_MIME_ATTRS_LIST))

        for prefix in self.EX_MIME_ATTRS_LIST:
            items = [[k, list(ifilterfalse(lambda x: x.startswith(prefix),v))] for k,v in self.get_mime_struct().items()]

            if items:
                items = reduce(add, items)

            self.checksum = binascii.crc32(''.join([''.join(i) for i in items]))

        logger.debug('mime_checksum: '.upper()+str(self.mime_nest_level))
        return self.mime_checksum

    def get_text_score(self, **kwargs):

        #Maps input regexp list to each sentence one by one
        #:return: penalising score, gained by sentenses

        self.__unpack_arguments('text_regexp_list', **kwargs)

        # precise flag for re.compile ?
        regs_list = self._get_regexp(self.TEXT_REGEXP_LIST, re.M)

        sents_generator = self.get_sentences()
        print("sent_lists >>"+str(self.get_sentences()))

        while(True):
            try:
                for reg_obj in regs_list:
                    self.txt_score += len(filter(lambda s: reg_obj.search(s,re.I), next(sents_generator)))*self._penalty_score
                    print("text_score: "+str(self.txt_score))
            except StopIteration as err:
                break

        logger.debug('text_score: '.upper()+str(self.txt_score))
        return self.txt_score

    def get_html_score(self, **kwargs):

        #1. from the last text/html part creates HTML-body skeleton from end-tags,
        #    takes checksum from it, cause spammer's and info's/net's HTML patterns
        #    are mostly the same ;
        #2. if HTML-body includes table - analyze tags and values inside, cause
        #    info's and net's HTML-patterns mostly made up with pretty same <tables> ;

        #:param tags_map: expected <tags attribute="value">, described by regexes ;
        #:return: <penalizing score> and <checksum for body> ;

        self.__unpack_arguments('html_tags_map', **kwargs)
        attr_value_pair = namedtuple('attr_value_pair', 'name value')

        print("tags_map: "+str(self.HTML_TAGS_MAP))

        soups_list = self.get_html_parts()

        while(True):
            try:
                soup = next(soups_list)
            except StopIteration as err:
                return self.html_score

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
                print('type of parsing line in reg_obj: '+str(type(self.HTML_TAGS_MAP[tag])))
                compiled_regexp_list = self._get_regexp(self.HTML_TAGS_MAP.get[tag], re.U)

                pairs = list()
                for key_attr in compiled_regexp_list: # expected_attrs_dict:
                    print(key_attr)
                    pairs = filter(lambda pair: key_attr.match(pair.name, re.I), soup_attrs_list)
                    print(pairs)

                    check_values = list()
                    if pairs:
                        check_values = filter(lambda pair: re.search(ur''+expected_attrs_dict.get(key_attr), pair.value, re.I), soup_attrs_list)
                        self.html_score += self._penalty_score*len(check_values)

        return self.html_score

    def get_html_checksum(self):

        html_skeleton = list()
        soups_list = self.get_html_parts()

        for s in tuple(soups_list):
            # get table checksum
            comments = s.body.findAll( text=lambda text: isinstance(text, Comment) )
            [comment.extract() for comment in comments]
            # leave only closing tags struct
            reg = re.compile(ur'<[a-z]*/[a-z]*>',re.I)
            # todo: investigate the order of elems within included generators
            html_skeleton.extend(t.encode('utf-8', errors='replace') for t in tuple(reg.findall(s.body.prettify(), re.M)))

        self.html_checksum = binascii.crc32(''.join(html_skeleton))

        return self.html_checksum

    def get_text_parts_avg_entropy(self):

        #for fun
        #:return:

        n = 0
        txt_avg_ent = 0
        # todo: make n-grams
        for tokens in self.get_stemmed_tokens():
            n +=1
            freqdist = FreqDist(tokens)
            probs = [freqdist.freq(l) for l in FreqDist(tokens)]
            print('P >>> '+str(probs))
            txt_avg_ent += -sum([p * math.log(p,2) for p in probs])

        self.txt_avg_ent = txt_avg_ent/n
        logger.debug('avg_ent'.upper()+': '+str(self.txt_avg_ent))

        return self.txt_avg_ent

    def get_text_compress_ratio(self):

        #maybe
        #:return: compress ratio of stemmed text-strings from
        #all text/mime-parts

        all_text_parts = list(self.get_stemmed_tokens())
        for x in all_text_parts:
            logger.debug('>>>> '+str(x))
        if all_text_parts:
            all_text = ''.join(reduce(add, all_text_parts))
            print(type(all_text))
            self.txt_compressed_ratio = float(len(zlib.compress(all_text.encode(self.DEFAULT_CHARSET))))/len(all_text)

        return self.txt_compressed_ratio

    def get_attach_features(self, **kwargs):

        #:param mime_parts_list:
        #:param reg_list: scary regexes for attach attribute value from Content-Type header
        #:param score:
        #:return: attach_count, score, <score gained by inline attachements>

        self.__unpack_arguments('attaches_rules', **kwargs)
        logger.debug('MIME STRUCT >>>>>'+str(self.get_mime_struct())+'/n')

        mime_values_list = reduce(add, self.get_mime_struct())
        attach_attrs = filter(lambda name: re.search(r'(file)?name([\*[:word:]]{1,2})?=.*',name), mime_values_list)
        attach_attrs = [( x.partition(';')[2]).strip('\r\n\x20') for x in attach_attrs ]
        self.attach_count = len(attach_attrs)

        self.attach_in_score = self._penalty_score*len(filter(lambda value: re.search(r'inline\s*;', value, re.I), mime_values_list))

        for exp in [re.compile(r,re.I) for r in self.ATTACHES_RULES]:
            x = filter(lambda value: exp.search(value,re.M), attach_attrs)
            self.attach_score += self._penalty_score*len(x)

        self.attach_score += self._penalty_score*len(filter(lambda name: re.search(r'(file)?name(\*[0-9]{1,2}\*)=.*',name), attach_attrs))

        return (self.attach_count, self.attach_in_score, self.attach_score)

if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)
