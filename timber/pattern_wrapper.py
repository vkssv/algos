import sys, os, importlib, logging, re
from email import iterators, base64mime, quoprimime
from bs4 import BeautifulSoup
from collections import OrderedDict

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)

class BasePattern(object):
    """Base parent class for created all other pattern classes.
    Provides access to some pre-parsed attributes of msg"""
    INIT_SCORE = 0
    MIN_TOKEN_LEN = 3

    def __init__(self, msg):
        self.msg = msg

    def get_text_parts(self):

        self.text_parts = []
        encodings = {
                            'quoted-printable'  : lambda payload: quoprimime.body_decode(payload),
                            'base64'            : lambda payload: base64mime.body_decode(payload)
                    }

        decoded_line = ''
        parts_iterator = iterators.typed_subpart_iterator(self.msg)
        while(True):
            try:
                part = next(parts_iterator)
                #logger.debug("next text part: "+str(part))
            except StopIteration as err:
                break

            if part:
                decoded_line = part.get_payload()
                #logger.debug("decoded_line "+str(decoded_line))
                #logger.debug("part.keys() "+str(part.keys()))

                if part.get('Content-Transfer-Encoding') in encodings.keys():
                    f = encodings.get(part.get('Content-Transfer-Encoding'))
                    decoded_line = f(decoded_line)

                self.text_parts.append((decoded_line, part.get_content_charset(), part.get_content_type()))

        return (self.text_parts)

    def get_rcvds(self, rcvds_num=0):

        self.parsed_rcvds = tuple([rcvd.partition(';')[0] for rcvd in self.msg.get_all('Received')])[-1*rcvds_num:]

        return (self.parsed_rcvds)

    def get_mime_struct(self):

        self.mime_heads = ['content-type', 'content-transfer-encoding', 'content-id', 'content-disposition']
        self.mime_parts= OrderedDict()

        for part in self.msg.walk():
            all_heads = [name.lower() for name in part.keys()]
            #print(all_heads)

            part_dict = {}
            part_key = 'text/plain'
            for head in filter(lambda n: all_heads.count(n), self.mime_heads):
                part_dict[head] = part.get_all(head)
                if head == 'content-type':
                    part_key = part.get(head)

            if len(part_dict) == 0:
                continue

            self.mime_parts[(part_key.partition(';')[0]).strip()] = part_dict

        return(self.mime_parts)

    def get_nest_level(self):

        mime_parts = self.get_mime_struct()
        self.level = len(filter(lambda n: re.search(r'(multipart|message)\/',n,re.I),mime_parts.keys()))

        return(self.level)

    def get_url_list(self):

        text_parts = self.get_text_parts()
        logger.debug("TEXT PARTS "+str(text_parts))
        self.url_list = []
        url_regexp= ur'(https?|mailto|ftps?):'
        for obj in text_parts:
            line, encoding, content_type = obj
            #logger.debug("part content type: "+content_type.upper())
            #logger.debug("LINE '"+line+"'")
            if 'html' in content_type:

                soup = BeautifulSoup(line)
                if soup.a:
                    self.url_list.extend(soup.a)
            else:
                self.url_list.extend(filter(lambda url: re.search(url_regexp, url, re.I), [l.strip() for l in line.split('\r\n')]))

        logger.debug('URL LIST >>>> '+str(self.url_list))
        return(self.url_list)

class PatternFactory(object):
    """Factory for creating on the fly set of rules for desired class"""

    def New(self, msg, label):
        #print(label)
        try:

            pattern = importlib.import_module(label + '_pattern')
            # logger.debug ((check.title()).replace('_',''))
            current_obj = getattr(pattern, (label.title() + 'Pattern'))

        except Exception as details:
            raise

        return (current_obj(msg))

MetaPattern = PatternFactory()
