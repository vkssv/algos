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

    _INIT_SCORE = 0 # can redifine for particular set of instanses, => use cls./self._INIT_SCORE in code

    # BASE_FEATURES = ('rcvd_traces_num','rcpt_smtp_to', 'rcpt_body_to', 'list', 'avg_entropy')

    def __init__(self, score, **kwds):

        self._penalty_score = score

        super(BasePattern, self).__init__(**kwds)

        base_features = [
                            'rcvd_num',
                            'from_checksum',
                            'list',
                            'mime_checksum'

        ]

        rcpt_features = ['rcpt_'+f for f in ['smtp_to','body_to']]
        dmarc_features = ['dmarc+'+f for f in ['Received-SPF','(DKIM|DomainKey)-Signature']]
        url_base_features =

        [ self.__setattr__(f, BasePattern._INIT_SCORE) for f in base_features + rcpt_features + dmarc_features ]

        self.rcvd_num = self._msg.keys().count('Received')
        self.get_rcpts_metrics()
        self.get_from_checksum()
        self.get_list_metrics()
        self.get_dmarc_metrics()
        self.get_base_url_metrics()


        '''''
        self.msg_vector.update(self.get_attach_metrics())
        self.msg_vector['html_checksum'] = self.get_html_crc()
        self.msg_vector['avg_entropy'] = self.get_text_parts_avg_entropy()
        self.msg_vector['compression_ratio'] = self.get_text_compress_ratio()
        '''''
        logger.debug('BasePattern was created')

    @staticmethod
    def get_regexp(regexp_list, compilation_flag=None):
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


    def get_features_dict(self, features_list):
        '''

        :param features_list: list of private attributes of particular PatternClass,
        which we need to return when exit from PatternClass.method scope,
        don't want to return None
        :return:
        '''
        for f in features:
            keys.extend(filter(lambda k: re.search(r'_.*'+f,k), self.__dict__.keys()))

        return dict((k, self.__dict__[k]) for k in keys)


    # can be called from each particular pattern with particular excluded_list
    def get_all_heads_checksum(self, excluded_list=None):
        '''
        :param excluded_list: uninteresting headers like ['Received', 'From', 'Date', 'X-.*']
        :return: <CRC32 from headers names>
        '''
        logger.debug(self._msg.items())

        heads_vector = tuple(map(itemgetter(0), self._msg.items()))
        heads_dict = dict(self._msg.items())

        if excluded_list:
            for ex_head in excluded_list:
                # can use match - no new lines in r_name
                heads_vector = tuple(filter(lambda h_name: not re.match(ex_head, h_name, re.I), heads_vector[:]))

        all_heads_checksum = binascii.crc32(''.join(heads_vector))

        return all_heads_checksum

    # can be called from each particular pattern with particular rcvds_num
    def get_rcvd_checksum(self, rcvds_num=0):
        '''
        :param rcvds_num: N curious Received headers from \CRLF\CRFL to top
        :return: dict {'rcvd_N': CRC32 } from line, formed by parsed values,
                 parser is interested only in servers IPs-literals, domains, etc
        '''
        rcvds_vect = self.get_rcvds(rcvds_num)
        logger.debug('rcvds_vect:'+str(rcvds_vect))
        rcvd_checksum = {}

        for rcvd_line, n in zip(rcvds_vect, range(len(rcvds_vect))):
            logger.debug(rcvd_line)
            trace = map(lambda x: rcvd_line.replace(x,''),['from','by',' '])[2]
            trace = trace.strip().lower()
            trace = binascii.crc32(trace)

            rcvd_checksum['rcvd_'+str(n)] = trace

        # don't assign to BasePattern attribute, cause it returns slice of Pattern's Class attributes dictionary,
        # (for different Patterns calculates checksum from different count of parced RCVD headers values)
        # will call it in Pattern's Class constructor and update it's attribute dictionary by rcvd_checksum dict
        return rcvd_checksum


    '''''
    def get_emarket_metrics(self, head_pattern, known_mailers, score):

        #:param head_pattern: one more regexp list with SN-header's names (X-FACEBOOK-PRIORITY, etc)
        #:param known_mailers: X-Mailer header with value like "ZuckMail"
        #:param score:
        #:return: <penalizing score>, <flag of known mailer presence>


        emarket_features = ('emarket_score', 'known_mailer_flag')
        emarket_dict = dict(zip(emarket_features, [self.INIT_SCORE]*len(emarket_features)))

        emarket_heads = set(filter(lambda header: re.match(head_pattern, header, re.I), self._msg.keys()))
        emarket_dict['emarket_score'] = len(emarket_heads)*score

        mailer_header = ''.join(filter(lambda h: re.match(r'^x-mailer$', h, re.I), self._msg.keys()))

        if self._msg.get(mailer_header) and filter(lambda reg: re.search(reg, self._msg.get(mailer_header), re.I), known_mailers):
            emarket_dict['known_mailer_flag'] = score

        return emarket_dict
    '''''

    def get_dmarc_metrics(self):

        #:param score:
        #:param dmarc_heads: list of headers, described in RFC 6376, RFC 7208
        #:return: <DMARC metrics dict>

        dmarc_heads = ['Received-SPF','(DKIM|DomainKey)-Signature']



        logger.debug(str(dmarc_features_dict))

        # RFC 7001, this header has always to be included

        if not (cls._msg.keys()).count('Authentication-Results'):
            return dmarc_features_dict, dkim_domain

        found_heads = list()
        for h in dmarc_heads:
            found_heads.extend(filter(lambda z: re.match(h, z, re.I), cls._msg.keys()))

        logger.debug('TOTAL:'+str(found_heads))

        # (len(required_heads_list)+1, cause we can find DKIM-Signature and DomainKey-Signature in one doc
        logger.debug('req_head:'+str(len(dmarc_heads)))
        #logger.debug('req_head:'+str(len(required_heads_list)+1))
        #logger.debug('found:'+str(len(set(total))*score))

        # todo: in a results look how it will probably correlate with last two metrics below
        dmarc_features_dict['dmarc_score'] = (len(dmarc_heads) - len(set(found_heads)))*cls.score

        # simple checks for Received-SPF and DKIM/DomainKey-Signature
        if cls._msg.keys().count('Received-SPF') and re.match(r'^\s*pass\s+', cls._msg.get('Received-SPF'), re.I):
            dmarc_features_dict['dmarc_Received-SPF'] += cls.score

        # check domain names in From and DKIM-headers (but now it's probably redundant)
        from_domain = (cls._msg.get('From')).partition('@')[2]
        from_domain = from_domain.strip('>').strip()

        logger.debug('dkims'+str(found_heads))
        valid_lines = filter(lambda f: re.search(from_domain, f), [ cls._msg.get(h) for h in found_heads ])
        if len(valid_lines) == len(found_heads):
            dmarc_features_dict['(DKIM|DomainKey)-Signature'] += cls.score
            dkim_domain = from_domain
            logger.debug('dkim_domain '+str(dkim_domain))

        return dmarc_features_dict

    def get_dkim_domain(self):
        pass

    def get_from_checksum(self):
        logger.debug('>>> ORIGINATOR_CHECKS:')

        if self._msg.get('From'):
            name_addr_tuples = self.get_addr_values(self._msg.get_all('From'))[:1]
            logger.debug('\tFROM:----->'+str(name_addr_tuples))
            print(name_addr_tuples)

            if len(name_addr_tuples) != 1:
                logger.warning('\t----->'+str(name_addr_tuples))

            if name_addr_tuples:
                from_value, from_addr = reduce(add, name_addr_tuples)
                self.from_checksum = binascii.crc32(from_value.encode(self._DEFAULT_CHARSET))
                logger.debug('\t----->'+str(self.from_checksum))

        return self.from_checksum

    def get_rcpts_metrics(self):

        #:param score:
        #:return: tuple with penalizing scores for To-header value from body,
        #and RCPT TO value from Received headers

        #for debut works only with To-header values

        name_addr_tuples = self.get_addr_values(self._msg.get_all('To'))
        only_addr_list = map(itemgetter(1), name_addr_tuples)
        logger.debug(only_addr_list)

        parsed_rcvds = [ rcvd.partition(';')[0] for rcvd in self.get_rcvds() ]
        print('parsed_rcvds >>'+str(parsed_rcvds))
        smtp_to_list = [ x for x in ( r.partition('for')[2].strip() for r in parsed_rcvds ) if x ]
        smtp_to_addr = re.findall(r'<(.*@.*)?>', ''.join(smtp_to_list))

        if not (smtp_to_list or only_addr_list):
            # can't check without data => leave zeros
            return (self.rcpt_smtp_to, self.rcpt_body_to)

        for key, l in zip((self.rcpt_smtp_to, self.rcpt_body_to), (smtp_to_list, only_addr_list)):
            if filter(lambda x: re.search(r'undisclosed-recipients', x, re.I), l):
                print(key)
                print(l)
                key += self._penalty_score

        if len(only_addr_list) == 1 and ''.join(smtp_to_addr) != ''.join(only_addr_list):
            self.rcpt_body_to += self._penalty_score
            logger.debug('\t----->'+str(self.rcpt_body_to))

        elif len(only_addr_list) > 2 and smtp_to_addr != '<multiple recipients>':
            self.rcpt_body_to += self._penalty_score
            logger.debug('\t----->'+str(self.rcpt_body_to))

        return (self.rcpt_body_to, self.rcpt_smtp_to)


    def get_list_metrics(self):

        #:return: penalizing score for List-* headers

        # very weak for spam cause all url from 'List-Unsubscribe','Errors-To','Reply-To'
        # have to be checked with antiphishing service

        if not filter(lambda list_field: re.search('(List|Errors)(-.*)?', list_field), self._msg.keys()):
            body_from = re.compile(r'@.*[a-z0-9]{1,63}\.[a-z]{2,4}')

        #logger.debug('\t=====>'+str(header_value_list))


        # try to get sender domain from RCVD headers,
        # use header_value_list to obtain
        # exactly the first rcvd header,
        # order makes sense here

        sender_domain = self.get_smtp_domain()
        if not sender_domain:
            body_from.search(cls._msg.get('From'))
            # try to get it from From: header value
            sender_domain = (for_body_from.search(cls._msg.get('From'))).group(0)
            sender_domain = sender_domain.strip('@')

        patterns = [
                        r'https?:\/\/.*'+sender_domain+'\/.*(listinfo|unsub|email=).*', \
                        r'mailto:.*@.*\.'+sender_domain+'.*'
        ]

        # check Reply-To only with infos, very controversial, here are only pure RFC 2369 checks
        # leave Errors-To cause all russian authorized email market players
        # rather put exactly Errors-To in their infos instead of List-Unsubscribe
        rfc_heads = ['List-Unsubscribe', 'Errors-To', 'Sender']

        presented = filter(lambda h: (cls._msg.keys()).count(h), rfc_heads)
        # doesn't support RFC 2369 in a proper way
        unsubscribe_score += (len(rfc_heads)-len(presented))*cls.score

        if not presented:
            return unsubscribe_score

        for uri in [heads_dict.get(head) for head in presented]:
            if not filter(lambda reg: re.search(reg, uri, re.M), patterns):
                unsubscribe_score += cls.score

        return unsubscribe_score


    # call from each particular pattern
    def get_base_subj_metrics(self, subj_regs):

        #:param subj_regs:
        #:param score:
        #:return: <penalizing score for Subj>, <count of tokens in upper-case and in Title>
        #cause russian unconditional spam is more complicated than abusix )

        line, tokens, encodings = self.get_decoded_subj()
        logger.debug('line : '+line)

        regs = self.get_regexp(subj_regs, re.U)
        # check by regexp rules
        matched = filter(lambda r: r.search(line, re.I), regs)
        subj_score = self._penalty_score*len(matched)

        upper_words_count = len([w for w in tokens if w.isupper()])
        title_words_count = len([w for w in tokens if w.istitle()])

        return (subj_score, upper_words_count, title_words_count)


    def get_url_features(self):

        # URL_COUNT: url count for infos and nets maybe lies in certain boundaries, \
        # cause they are generated by certain patterns  ));
        # DISTINCT_COUNT: count of different domains from netlocation parts of URLs;
        # SENDER_COUNT: count of domains/subdomains from netlocation parts of URLs,
        # which are the same with sender domain from RCVD-headers.

        # url_count
        self.url_count = len(self.get_urlparse_obj_list())

        if self.url_count > 0:
            net_location_list = self.get_netlocation_list()

            if net_location_list:
                self.distinct_count += len(set([d.strip() for d in net_location_list]))
                pattern = ur'\.?'+sender_domain.decode('utf-8')+u'(\.\w{2,10}){0,2}'
                self.sender_count += len(filter(lambda d: re.search(pattern, d, re.I), net_location_list))

        return (self.url_count, self.distinct_count, self.sender_count)

    def get_url_score(self, fqdn_regs, txt_regs):

        #:param fqdn_regs:
        #:param txt_regs:
        #:return:

        reg = namedtuple('reg', 'fqdn_regs txt_regs')
        compiled = reg(*(self.get_regexp(l, re.I) for l in (fqdn_regs, txt_regs)))

        for reg in compiled.fqdn_regs:
            url_score += len(filter(lambda netloc: reg.search(netloc), self.netloc_list))*self.score

        # url_score
        metainfo_list = list()
        for attr in ['path', 'query', 'fragment']:
            metainfo_list.extend([i.__getattribute__(attr) for i in self.url_list])

        if metainfo_list:
            for reg in compiled.txt_regs:
                url_score += len(filter(lambda metainfo: reg.search(metainfo), metainfo_list))*self.score

        return url_score

    def get_mime_checksum(self, excluded_attrs_list=['boundary=','charset=']):

        #:param excluded_atrs_list: values of uninteresting mime-attrs
        #:return: 42

        logger.debug('EXL:'+str(excluded_attrs_list))

        for prefix in excluded_attrs_list:
            items = [[k, list(ifilterfalse(lambda x: x.startswith(prefix),v))] for k,v in self.get_mime_struct().items()]

            if items:
                items = reduce(add, items)

            self.checksum = binascii.crc32(''.join([''.join(i) for i in items]))

        return self.mime_checksum

    '''''
    def get_text_parts_metrics(self, regs_list, sent_list=None):

        #Maps input regexp list to each sentence one by one
        #:return: penalising score, gained by sentenses

        print("score "+str(self.score))
        print("regs_list "+str(regs_list))
        text_score = cls.INIT_SCORE

        # precise flag for re.compile ?
        regs_list = cls.get_regexp_(regs_list, re.M)

        if sent_list is None:
            sents_generator = cls.get_sentences()
            print("sent_lists >>"+str(self.get_sentences()))

        while(True):
            try:
                for reg_obj in regs_list:
                    text_score += len(filter(lambda s: reg_obj.search(s,re.I), next(sents_generator)))*self.score
                    print("text_score: "+str(text_score))
            except StopIteration as err:
                break

        return text_score

    def get_html_score(self, tags_map, soups_list=None):

        #1. from the last text/html part creates HTML-body skeleton from end-tags,
        #    takes checksum from it, cause spammer's and info's/net's HTML patterns
        #    are mostly the same ;
        #2. if HTML-body includes table - analyze tags and values inside, cause
        #    info's and net's HTML-patterns mostly made up with pretty same <tables> ;

        #:param tags_map: expected <tags attribute="value">, described by regexes ;
        #:return: <penalizing score> and <checksum for body> ;


        html_score = self.INIT_SCORE
        attr_value_pair = namedtuple('attr_value_pair', 'name value')


        print("tags_map: "+str(tags_map))
        if soups_list is None:
            soups_list = self.get_html_parts()

        while(True):
            try:
                soup = next(soups_list)
            except StopIteration as err:
                return html_score

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
                compiled_regexp_list = self.get_regexp_(tags_map.get(tag), re.U)

                pairs = list()
                for key_attr in compiled_regexp_list: # expected_attrs_dict:
                    print(key_attr)
                    pairs = filter(lambda pair: key_attr.match(pair.name, re.I), soup_attrs_list)
                    print(pairs)

                    check_values = list()
                    if pairs:
                        check_values = filter(lambda pair: re.search(ur''+expected_attrs_dict.get(key_attr), pair.value, re.I), soup_attrs_list)
                        html_score += self.score*len(check_values)


        return html_score

    @classmethod
    def get_html_crc(cls):
        html_skeleton = list()
        soups_list = cls.get_html_parts()
        html_checksum = cls.INIT_SCORE

        for s in tuple(soups_list):
            # get table checksum
            comments = s.body.findAll( text=lambda text: isinstance(text, Comment) )
            [comment.extract() for comment in comments]
            # leave only closing tags struct
            reg = re.compile(ur'<[a-z]*/[a-z]*>',re.I)
            # todo: investigate the order of elems within included generators
            html_skeleton.extend(t.encode('utf-8', errors='replace') for t in tuple(reg.findall(s.body.prettify(), re.M)))

        html_checksum = binascii.crc32(''.join(html_skeleton))

        return html_checksum

    @classmethod
    def get_text_parts_avg_entropy(cls):

        #for fun
        #:return:


        (avg_ent, n) = [cls.INIT_SCORE]*2
        # todo: make n-grams
        for tokens in cls.get_stemmed_tokens():
            n +=1
            freqdist = FreqDist(tokens)
            probs = [freqdist.freq(l) for l in FreqDist(tokens)]
            print('P >>> '+str(probs))
            avg_ent += -sum([p * math.log(p,2) for p in probs])
            avg_ent = avg_ent/n

        return avg_ent

    @classmethod
    def get_text_compress_ratio(cls):

        #maybe
        #:return: compress ratio of stemmed text-strings from
        #all text/mime-parts

        compressed_ratio = cls.INIT_SCORE
        all_text_parts = list(cls.get_stemmed_tokens())
        for x in all_text_parts:
            print('>>>> '+str(x))
        if all_text_parts:
            all_text = ''.join(reduce(add, all_text_parts))
            print(type(all_text))
            compressed_ratio = float(len(zlib.compress(all_text.encode(cls.DEFAULT_CHARSET))))/len(all_text)

        return compressed_ratio

    @classmethod
    def get_attach_metrics(cls):

        #:param mime_parts_list:
        #:param reg_list: scary regexes for attach attribute value from Content-Type header
        #:param score:
        #:return: attach_count, score, <score gained by inline attachements>



        mime_skeleton = cls.get_mime_struct()
        logger.debug('MIME STRUCT >>>>>'+str(mime_skeleton)+'/n')

        mime_dict['att_count'] = count
            mime_dict['att_score'] = att_score
            # defines by count of inline attachements
            mime_dict['in_score'] = in_score

            mime_dict['nest_level'] = cls.get_nest_level()
            mime_dict['checksum'] = binascii.crc32(''.join(mime_skeleton.keys()))


        attach_score = cls.INIT_SCORE

        mime_values_list = reduce(add, mime_parts_list)
        attach_attrs = filter(lambda name: re.search(r'(file)?name([\*[:word:]]{1,2})?=.*',name), mime_values_list)
        attach_attrs = [(x.partition(';')[2]).strip('\r\n\x20') for x in attach_attrs]
        attach_count = len(attach_attrs)

        attach_score += score*len(filter(lambda name: re.search(r'(file)?name(\*[0-9]{1,2}\*)=.*',name), attach_attrs))

        inline_score = score*len(filter(lambda value: re.search(r'inline\s*;', value, re.I), mime_values_list))
        return attach_features_dict

    def get_attach_score(self, reg_list, score):

        for exp in [re.compile(r,re.I) for r in reg_list]:
            x = filter(lambda value: exp.search(value,re.M), attach_attrs)
            score += score*len(x)


        return attach_score


if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)
'''''