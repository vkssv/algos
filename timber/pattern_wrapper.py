# -*- coding: utf-8 -*-

import sys, logging, re, binascii

from operator import add, itemgetter
from itertools import izip_longest

from msg_wrapper import BeautifulBody

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(levelname)s %(funcName)s: %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#ch.setLevel(logging.DEBUG)
#ch.setFormatter(formatter)
#logger.addHandler(ch)

class BasePattern(BeautifulBody):
    '''
    Base parent class for created pattern classes.
    Provides some basic features for email's headers and bodies :

    ALL_HEADS_CHECKSUM --> crc32-checksum from all headers,
        except of the set of obligatory and very frequent,
        which is defined as class-attribute in each Pattern class ;

    RCVD_CHECKSUM --> crc32-checksum from N first 'Received' headers
        values, N is defined as class-attribute in each Pattern class ;

    RCPT_SCORE --> gained by comparing value from 'To' header and recepients,
        mentioned in 'Received' headers ;
    '''

    INIT_SCORE = 0.0
    PENALTY_SCORE = 1.0

    EX_MIME_ATTRS_LIST = ['boundary=','charset=']
    BASE_FEATURES = ['all_heads_checksum','rcpt_score']

    def __init__(self, score, **kwds):

        self.PENALTY_SCORE = score

        super(BasePattern, self).__init__(**kwds)

        methods_names = ['get_'+name for name in self.BASE_FEATURES]
        methods = [ (name.lstrip('get_'), getattr(self, name, lambda x: self.INIT_SCORE)) for name in methods_names ]
        # default "lambda x" here in getattr() just intercepts unexisted any method from self.BASE_FEATURES,
        # to avoid AttributeError exception

        for n, pair in enumerate(methods, start=1):
            name, f = pair
            value = self.INIT_SCORE
            # if attribute-method was found in BasePattern, setup it's default value before call, because
            # if later we will have an exception => anyway vector will have defined set of features
            try:
                value = f()
            except Exception as err:
                logger.error(f.func_name+' : '+str(err))
                pass

            #logger.debug((name+' ==> '+str(value)).upper())
            self.__setattr__(name, value)

        self.rcvd_num = self.msg.keys().count('Received')
        self.get_rcvd_checksum()

        #for (k,v) in self.__dict__.iteritems():
        #    logger.debug(str(k).upper()+' ==> '+str(v).upper())

    
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
            #logger.debug(u'get_regexp : for compiling => '+exp)
            # cause mostly use unicoded lines and unicoded regexps
            # => re doesn't support re.I flag for them
            #logger.debug(exp)
            if compilation_flag is not None:
                exp = re.compile(exp, compilation_flag)
            else:
                exp = re.compile(exp)

            compiled_list.append(exp)

        return compiled_list

    def get_smtp_sender_domain(self):

        sender_domain = False
        while not (sender_domain):
            sender_domain = self.get_smtp_originator_domain()
            originator = self.get_addr_values(self.msg.get_all('From'))
            if not originator:
                return self.list_score

            orig_name, orig_addr = reduce(add, originator)
            sender_domain = (orig_addr.split('@')[1]).strip()

    def get_all_heads_checksum(self):

        '''
        :param excluded_list: uninteresting headers like ['Received', 'From', 'Date', 'X-.*']
        :return: < CRC32 from headers names >
        '''

        heads_vector = tuple(map(itemgetter(0), self.msg.items()))
        #logger.debug(heads_vector)
        heads_dict = dict(self.msg.items())


        for ex_head in self.EXCLUDED_HEADS:
            heads_vector = tuple(filter(lambda h_name: not re.match(ex_head, h_name, re.I), heads_vector[:]))

        all_heads_checksum = binascii.crc32(''.join(heads_vector))
        #logger.debug('all_heads_checksum ==> '.upper()+str(self.all_heads_checksum))
        return all_heads_checksum

    def get_rcvd_checksum(self):
        '''
        :param rcvds_num: N curious Received headers from \CRLF\CRFL to top
        :return: dict {'rcvd_N': CRC32 } from line, formed by parsed values,
                 parser is interested only in servers IPs-literals, domains, etc
        '''

        logger.debug('rcvds num from '+str(self.__class__)+' : '+str(self.RCVDS_NUM))
        rcvds_vect = self.get_rcvds(self.RCVDS_NUM)
        logger.debug('rcvds_vect :'+str(rcvds_vect))
        rcvd_checksum = {}

        for rcvd_line, n in izip_longest(rcvds_vect, range(self.RCVDS_NUM),fillvalue=''):
            self.__dict__['rcvd_'+str(n)] = self.INIT_SCORE
            logger.debug('rcvd_line : '+rcvd_line)
            trace = map(lambda x: rcvd_line.replace(x,''),['from','by',''])[2]
            trace = trace.strip().lower()
            trace = binascii.crc32(trace)

            self.__dict__['rcvd_'+str(n)] = trace
            rcvd_checksum['rcvd_'+str(n)] = trace

        #logger.debug('rcvd_checksum ==> '.upper()+str(rcvd_checksum))
        return rcvd_checksum

    def get_rcpt_score(self):
        '''
        :return: tuple with penalizing scores for To-header value from body,
        for debut works only with To-header values
        '''

        name_addr_tuples = self.get_addr_values(self.msg.get_all('To'))

        only_addr_list = map(itemgetter(1), name_addr_tuples)
        parsed_rcvds = [ rcvd.partition(';')[0] for rcvd in self.get_rcvds() ]

        smtp_to_list = [ x for x in ( r.partition('for')[2].strip() for r in parsed_rcvds ) if x ]
        smtp_to_addr = re.findall(r'<(.*@.*)?>', ''.join(smtp_to_list))

        if not (smtp_to_list or only_addr_list):
            return self.INIT_SCORE

        rcpt_score = len([value for value in smtp_to_list + only_addr_list if re.search(r'undisclosed-recipients', value, re.I)])*self.PENALTY_SCORE
        #logger.debug(str(type(only_addr_list)))
        #logger.debug(str(type(smtp_to_addr)))
        if len(only_addr_list) == 1 and ''.join(smtp_to_addr) != ''.join(only_addr_list):
            rcpt_score += self.PENALTY_SCORE

        elif len(only_addr_list) > 2 and smtp_to_addr != '<multiple recipients>':
            rcpt_score += self.PENALTY_SCORE

        #logger.debug('rcpt_score ==> '.upper()+str(self.INIT_SCORE))
        return rcpt_score


