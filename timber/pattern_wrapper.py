# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii, zlib, math

from urlparse import urlparse
from operator import add, itemgetter
from collections import defaultdict, namedtuple, Counter, OrderedDict

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

from msg_wrapper import BeautifulBody, lazyproperty

class BasePattern(BeautifulBody):
    """
    Base parent class for created all other four pattern classes.
    Provides some basic checks and metrics for email's headers and bodies.
    Keeps Frankenstein's DNAs.
    """

    INIT_SCORE = 0

    # just for debugging new regexps
    @staticmethod
    def get_regexp_(regexp_list, compilation_flag=None):
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

    def get_trace_crc(self, rcvds_num=0):
        '''
        :param rcvds_num: N curious Received headers from \CRLF\CRFL to top
        :return: dict {'rcvd_N': CRC32 } from line, formed by parsed values,
                 parser is interested only in servers IPs-literals, domains, etc
        '''
        rcvds_vect = self.get_rcvds(rcvds_num)
        logger.debug('rcvds_vect:'+str(rcvds_vect))
        traces_dict = {}

        for rcvd_line, n in zip(rcvds_vect, range(len(rcvds_vect))):
            logger.debug(rcvd_line)
            trace = map(lambda x: rcvd_line.replace(x,''),['from','by',' '])[2]
            trace = trace.strip().lower()
            trace = binascii.crc32(trace)

            traces_dict['rcvd_'+str(n)] = trace

        return traces_dict

    def get_all_heads_crc(self, excluded_list = None):
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

        heads_crc = binascii.crc32(''.join(heads_vector))

        return heads_crc

    def get_headers_metrics(self, head_pattern, known_mailers, score):
        '''
        :param head_pattern: one more regexp list with SN-headers names (X-FACEBOOK-PRIORITY, etc)
        :param known_mailers: X-Mailer: ZuckMail
        :param score:
        :return: <penalizing score>, <Zuck-IsHere-Flag>
        '''

        typical_heads_score = self.INIT_SCORE
        known_mailer_flag = self.INIT_SCORE
        header = namedtuple('header','name value')

        header_value_list = [header(*pair) for pair in header_value_list]
        headers_list = [i.name for i in header_value_list]

        emarket_heads = set(filter(lambda header: re.match(head_pattern, header, re.I), headers_list))
        emarket_heads_score += len(emarket_heads)*score

        mailer_header = ''.join(filter(lambda h: re.match(r'^x-mailer$', h, re.I), headers_list))

        if dict(self._msg_items()).get(mailer_header):
            x_mailer =  dict(self._msg_items()).get(mailer_header)
            if filter(lambda reg: re.search(reg, x_mailer, re.I), known_mailers):
                known_mailer_flag = score

        return emarket_heads_score, known_mailer_flag

    def get_dmarc_metrics(self, score, dmarc_heads=None):
        '''
        :param score:
        :param dmarc_heads: list of headers, described in RFC 6376, RFC 7208
        :return: <dmarc_score (score, which is gained, if some of DMARC-standard's headers are absent)>
                    <DMARC metrics dict>, <sender's domain from DKIM>
        '''

        if dmarc_heads is None:
            dmarc_heads = ['Received-SPF','(DKIM|DomainKey)-Signature']

        dmarc_dict = dict(zip(dmarc_heads, [self.INIT_SCORE]*len(dmarc_heads)))
        logger.debug(str(dmarc_dict))
        dmarc_score = self.INIT_SCORE
        dkim_domain = ''

        # RFC 7001, this header has always to be included
        dmarc_heads.append('Authentication-Results')
        if not (self._msg.keys()).count('Authentication-Results'):
            return dmarc_score, dmarc_dict, dkim_domain

        total = list()
        for h in dmarc_dict.iterkeys():
            dkims = filter(lambda z: re.match(h, z, re.I), self._msg.keys())
            total.extend(dkims)

        logger.debug('TOTAL:'+str(total))

        # (len(required_heads_list)+1, cause we can find DKIM-Signature and DomainKey-Signature in one doc
        logger.debug('req_head:'+str(len(dmarc_heads)))
        #logger.debug('req_head:'+str(len(required_heads_list)+1))
        logger.debug('found:'+str(len(set(total))*score))

        # todo: in a results look how it will probably correlate with last two metrics below
        dmarc_score = len(dmarc_heads) - len(set(total))*score

        # simple checks for Received-SPF and DKIM/DomainKey-Signature
        if self._msg.keys().count('Received-SPF') and re.match(r'^\s*pass\s+', self._msg.get('Received-SPF'), re.I):
            dmarc_dict['Received-SPF'] += score

        # check domain names in From and DKIM-headers (but now it's probably redundant)
        from_domain = (self._msg.get('From')).partition('@')[2]
        from_domain = from_domain.strip('>').strip()

        dkim_domain=''
        logger.debug('dkims'+str(dkims))
        valid_lines = filter(lambda f: re.search(from_domain,f), [ self._msg.get(h) for h in dkims ])
        if len(valid_lines) == len(dkims):
            dmarc_dict['(DKIM|DomainKey)-Signature'] += score
            dkim_domain = from_domain
            logger.debug('dkim_domain '+str(dkim_domain))

        return dmarc_score, dmarc_dict, dkim_domain

    def get_rcpts_metrics(self, score):
        '''
        :param score:
        :return: tuple with penalizing scores for To-header value from body,
        and RCPT TO value from Received headers

        for debut works only with To-header values
        '''
        (smtp_to, body_to) = [self.INIT_SCORE]*2

        name_addr_tuples = self.get_addr_values(self._msg.get_all('To'))
        only_addr_list = map(itemgetter(1), name_addr_tuples)
        logger.debug(only_addr_list)

        parsed_rcvds = [ rcvd.partition(';')[0] for rcvd in self.get_rcvds() ]
        print('parsed_rcvds >>'+str(parsed_rcvds))
        smtp_to_list = [ x for x in ( r.partition('for')[2].strip() for r in parsed_rcvds ) if x ]
        smtp_to_addr = re.findall(r'<(.*@.*)?>', ''.join(smtp_to_list))

        if not (smtp_to_list or only_addr_list):
            # can't check without data => leave zeros
            return smtp_to, body_to

        for key, l in zip((smtp_to, body_to),(smtp_to_list, only_addr_list)):
            if filter(lambda x: re.search(r'undisclosed-recipients', x, re.I), l):
                print(key)
                print(l)
                key += score

        if len(only_addr_list) == 1 and ''.join(smtp_to_addr) != ''.join(only_addr_list):
            body_to += score
            logger.debug('\t----->'+str(body_to))

        elif len(only_addr_list) > 2 and smtp_to_addr != '<multiple recipients>':
            body_to += score
            logger.debug('\t----->'+str(body_to))

        return smtp_to, body_to

    def get_list_metrics(self, score):
        '''
        :param score:
        :return: penalizing score for List-* headers
        '''
        # very weak for spam cause all url from 'List-Unsubscribe','Errors-To','Reply-To'
        # have to be checked with antiphishing service
        unsubscribe_score = self.INIT_SCORE
        body_from = re.compile(r'@.*[a-z0-9]{1,63}\.[a-z]{2,4}')

        #logger.debug('\t=====>'+str(header_value_list))
        heads_dict = dict(self._msg.items())

        # try to get sender domain from RCVD headers,
        # use header_value_list to obtain
        # exactly the first rcvd header,
        # order makes sense here

        sender_domain = self.get_smtp_domain()
        if not sender_domain:
            body_from.search(heads_dict.get('From'))
            # try to get it from From: header value
            sender_domain = (for_body_from.search(heads_dict.get('From'))).group(0)
            sender_domain = sender_domain.strip('@')

        patterns = [
                        r'https?:\/\/.*'+sender_domain+'\/.*(listinfo|unsub|email=).*', \
                        r'mailto:.*@.*\.'+sender_domain+'.*'
        ]

        # check Reply-To only with infos, very controversial, here are only pure RFC 2369 checks
        # leave Errors-To cause all russian authorized email market players
        # rather put exactly Errors-To in their infos instead of List-Unsubscribe
        rfc_heads = ['List-Unsubscribe', 'Errors-To', 'Sender']

        presented = filter(lambda h: (heads_dict.keys()).count(h), rfc_heads)
        # doesn't support RFC 2369 in a proper way
        unsubscribe_score += (len(rfc_heads)-len(presented))*score

        if not presented:
            return unsubscribe_score

        for uri in [heads_dict.get(head) for head in presented]:
            if not filter(lambda reg: re.search(reg, uri, re.M), patterns):
                unsubscribe_score += score

        return unsubscribe_score

    def get_subject_metrics(self, subj_regs, score):
        '''
        :param subj_regs:
        :param score:
        :return: <penalizing score for Subj>, <count of tokens in upper-case and in Title>
        cause russian unconditional spam is more complicated than abusix )
        '''

        # check by regexp rules
        total_score = self.INIT_SCORE
        line, tokens, encodings = self.get_decoded_subj()
        #line = re.sub(ur'[\\\|\/\*]', '', line)
        logger.debug('line : '+line)

        regs = self.get_regexp_(subj_regs, re.U)
        matched = filter(lambda r: r.search(line, re.I), regs)

        total_score += score*len(matched)
        upper_words_count = len(filter(lambda w: w.isupper(),tokens))
        title_words_count = len(filter(lambda w: w.istitle(),tokens))

        return total_score, upper_words_count, title_words_count

    def get_url_metrics(self, domain_regs, text_regs, score):
        '''
        :param domain_regs: regexp list for URL's domains
        :param text_regs: regexp list for text and tags around URL
        :param score:
        :return: <dict with metrics>, <list of domains from URL's>
        '''
        # domain_regs, regs - lists of compiled RE objects
        logger.debug('our list: '+str())

        basics = ['url_count', 'url_score', 'distinct_count', 'sender_count']
        basic_features = Counter(zip(basics, [self.INIT_SCORE]*len(basics)))
        # URL_COUNT: url count for infos and nets maybe lies in certain boundaries, \
        # cause they are generated by certain patterns  ));
        # URL_SCORE: score, which will be earned during regexp-checks for different parts of parsed URLs;
        # DISTINCT_COUNT: count of different domains from netlocation parts of URLs;
        # SENDER_COUNT: count of domains/subdomains from netlocation parts of URLs,
        # which are the same with sender domain from RCVD-headers.

        # url_count
        basic_features['url_count'] = len(self.url_list)

        netloc_list = []
        for url in self.url_list:
            if url.netloc:
                netloc_list.append(url.netloc)
                continue
            elif url.path:
                netloc_list.append(url.path.strip('www.'))
                continue

        netloc_list = filter(lambda d: d, netloc_list)
        only_str_obj = filter(lambda i: type(i) is str, netloc_list)

        if only_str_obj:
            only_str_obj  = [i.decode('utf8') for i in only_str_obj]
            netloc_list = only_str_obj + filter(lambda i: type(i) is unicode, netloc_list)

        #print("NETLOC: >>>>>"+str(netloc_list))

        sender_domain = self.get_smtp_domain()
        pattern = ur'\.?'+sender_domain.decode('utf-8')+u'(\.\w{2,10}){0,2}'

        # url_score, distinct_count, sender_count
        reg = namedtuple('reg', 'for_dom_pt for_txt_pt')
        compiled = reg(*(self.get_regexp_(l, re.I) for l in (domain_regs, text_regs)))

        if netloc_list:

            for reg in compiled.for_dom_pt:
                basic_features['url_score'] += len(filter(lambda netloc: reg.search(netloc), netloc_list))*score

            basic_features['distinct_count'] += len(set([d.strip() for d in netloc_list]))
            basic_features['sender_count'] += len(filter(lambda d: re.search(pattern, d, re.I), netloc_list))

        # url_score
        metainfo_list = []
        for attr in ['path', 'query', 'fragment']:
            metainfo_list.extend([i.__getattribute__(attr) for i in self.url_list])

        if metainfo_list:
            for reg in compiled.for_txt_pt:
                basic_features['url_score'] += len(filter(lambda metainfo: reg.search(metainfo), metainfo_list))*score

        return dict(basic_features), netloc_list

    def get_mime_crc(self, excluded_atrs_list=['boundary=','charset=']):
        '''
        :param excluded_atrs_list: values of uninteresting mime-attrs
        :return: 42
        '''

        checksum = self.INIT_SCORE
        logger.debug('EXL:'+str(excluded_atrs_list))

        items = self.get_mime_struct.items()

        for prefix in excluded_args_list:
            items = [[k, list(ifilterfalse(lambda x: x.startswith(prefix),v))] for k,v in items]

        if items:
            items = reduce(add,items)
            checksum = binascii.crc32(''.join([''.join(i) for i in items]))

        return checksum

    def get_text_parts_metrics(self, score, regs_list, sent_list=None):
        '''
        Maps input regexp list to each sentence one by one
        :return: penalising score, gained by sentenses
        '''
        print("score "+str(score))
        print("regs_list "+str(regs_list))
        text_score = self.INIT_SCORE

        # precise le flag pour re.compile ?
        regs_list = self.get_regexp_(regs_list, re.M)

        if sent_list is None:
            sents_generator = self.get_sentences()
            print("sent_lists >>"+str(self.get_sentences()))

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
            are mostly the same ;
        2. if HTML-body includes table - analyze tags and values inside, cause
            info's and net's HTML-patterns mostly made up with pretty same <tables> ;

        :param tags_map: expected <tags attribute="value">, described by regexes ;
        :return: <penalizing score> and <checksum for body> ;
        '''

        (html_score, html_checksum) = [self.INIT_SCORE]*2
        attr_value_pair = namedtuple('attr_value_pair', 'name value')
        html_skeleton = list()

        print("tags_map: "+str(tags_map))
        if mime_parts_list is None:
            mime_parts_list = self.get_text_mime_part()

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

                print(type(tags_map))
                soup_attrs_list = [ t for t in [soup.body.find_all(tag) for tag in tags_map.iterkeys()] if t ]
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
                compiled_regexp_list = self.get_regexp_(tags_map.get(tag), re.U)

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
        #print(html_checksum)

        return html_score, html_checksum

    #@lazyproperty
    def get_text_parts_avg_entropy(self):
        '''
        for fun
        :return:
        '''

        (avg_ent, n) = [self.INIT_SCORE]*2
        # todo: make n-grams
        for tokens in self.get_stemmed_tokens():
            n +=1
            freqdist = FreqDist(tokens)
            probs = [freqdist.freq(l) for l in FreqDist(tokens)]
            print('P >>> '+str(probs))
            avg_ent += -sum([p * math.log(p,2) for p in probs])
            avg_ent = avg_ent/n

        return avg_ent

    #@lazyproperty
    def get_text_compress_ratio(self):
        '''
        maybe
        :return: compress ratio of stemmed text-strings from
        all text/mime-parts
        '''
        compressed_ratio = self.INIT_SCORE
        all_text_parts = list(self.get_stemmed_tokens())
        for x in all_text_parts:
            print('>>>> '+str(x))
        if all_text_parts:
            all_text = ''.join(reduce(add,all_text_parts))
            print(type(all_text))
            compressed_ratio = float(len(zlib.compress(all_text.encode(self.DEFAULT_CHARSET))))/len(all_text)

        return compressed_ratio

    #def get_text_parts_jaccard():
        # return nltk.jaccard_distance()

    def get_attach_metrics(self, mime_parts_list, reg_list, score):
        '''
        :param mime_parts_list:
        :param reg_list: scary regexes for attach attribute value from Content-Type header
        :param score:
        :return: attach_count, score, <score gained by inline attachements>
        '''

        attach_score = self.INIT_SCORE

        mime_values_list = reduce(add, mime_parts_list)
        attach_attrs = filter(lambda name: re.search(r'(file)?name([\*[:word:]]{1,2})?=.*',name), mime_values_list)
        attach_attrs = [(x.partition(';')[2]).strip('\r\n\x20') for x in attach_attrs]
        attach_count = len(attach_attrs)

        attach_score += score*len(filter(lambda name: re.search(r'(file)?name(\*[0-9]{1,2}\*)=.*',name), attach_attrs))


        for exp in [re.compile(r,re.I) for r in reg_list]:
            x = filter(lambda value: exp.search(value,re.M), attach_attrs)
            score += score*len(x)

        inline_score = score*len(filter(lambda value: re.search(r'inline\s*;', value, re.I), mime_values_list))

        return attach_count, score, inline_score


if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.NORMALIZE_WHITESPACE)
