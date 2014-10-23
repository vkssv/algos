#!/usr/bin/env python

import sys, os, logging, re, math
from optparse import OptionParser
# import matplotlib.pyplot as plt
SCORE=1.0

# define needed functions
def cut_header_from_body(email):
    doc = open(email, "rb")
    doc_content = ''.join(doc.readlines())
    doc.close()

    # cut headers from body
    headers_str = re.split('\r\n\r\n', doc_content)[0]
    corp_lines = re.split('\r\n\r\n', doc_content)[1:]

    # normilize lines in body
    b_list = sum([b.split('\r\n') for b in corp_lines], [])
    corp_lines_list = [l.strip() for l in b_list]
    corp_lines_list = filter(lambda x: len(x) != 0, corp_lines_list)

    return (headers_str, corp_lines_list)

def headers_parser(head_string):
    logger.debug("Parsing email's headers:")
    headers_dict = {}
    cur_header = None
    for h in head_string.split('\r\n'):
        h = h.rstrip()
        # match the start of header
        if re.match('^[\S]+:.*$', h):
            header_name, value = h.split(':', 1)
            headers_dict[header_name] = value
            cur_header = header_name
        # match the start of folded value of the header
        elif re.match('^(\t|\x20)+.*$', h):
            headers_dict[cur_header] = headers_dict.get(cur_header)+' '+h.strip()
        else:
            # just skip unmached headers
            continue

    for h_key in headers_dict.iterkeys():
        logger.debug('HEADER: '+h_key+" --> "+headers_dict.get(h_key))

    return (headers_dict)

def check_features_headers(head_value, head_name):
    res = 0
    if head_name in ['To', 'Cc', 'Bcc']:

        res = len(re.findall('<.*>', head_value))

    elif head_name in ['Subject', 'Received']:

        if head_name == 'Subject':
            # remove noise in cases of "my tasty V I A G R A \S\I\A\L\I\S /D/R/U/G"
            head_value = re.sub('[\\\/\s]', '', head_value)

        headers_dict = {

            'Subject' : r'(viagra|cialis|discount|pill|med|free|click|Best\s+Deal\s+Ever|babe)+',
            'Received': r'((public|airnet|wi-?fi|a?dsl|dynamic|pppoe|static|account)+|(\(|\s+)(([a-z]+?)-){0,2}(\d{1,3}-){1,3}\d{1,3}([\.a-z]{1,63})+\.(ru|in|id|ua|ch))'
        }

        m = re.search(headers_dict.get(head_name), head_value, re.I)
        if m:
            res = SCORE
            logger.debug('SUSPECT_'+head_name.upper()+': '+(m.group(0)).strip())

    logger.debug(head_name.upper()+' = '+str(res))

    return(res)

def check_headers(headers_list):
    # attempt to create some useless heuristic rules
    # if header is present in email keep zero in doc_vector, if absent put 1 or 1*coefficient
    # ( apply all coefficients below in create_doc_vector() func)
    typically_for_ham = (
        'Authentication-Results',
        'List-Unsubscribe',
        'DKIM-.*',
        'Domain-Key',
        'Received-SPF',
        'Sender',
        'List-Unsubscribe',
        'X-.*',
        'Errors-To',
        'X-Mailer',
        'User-Agent',
        'Content-Type',
        'Mime-Version',
        'Reply-To',
        'Content-Language'
    )

    headers_spamness_vector = []
    for h in typically_for_ham:
        n = 0
        if headers_list.count(h) == 0:
            n = SCORE

        headers_spamness_vector.append(n)
        logger.debug(h+' = '+str(n))

    return (tuple(headers_spamness_vector))

def check_url(body_lines_set, url_regex = '(https?|ftp):\\/\\/.*\\.(ru|in|cn|tld|su|kz|cz)(\/|\x20)?'):
    url_flag = 0
    urls_dict = {}
    for line in body_lines_set:
        match_url = re.search(url_regex, line, re.I)
        if match_url:
            url_flag = 1
            urls_dict[match_url.group(0).strip()] = 1

    if url_flag:
        logger.debug('SUSPECT_URL: '+' '.join(urls_dict.keys()))

    logger.debug('SUSPECT_URL: '+str(url_flag))

    return (url_flag)

# rules for bodies
def check_body(body_lines):
    score = 0

    spam_patterns = [

        # just to add some more features, very greedy aggressive regexes were inherited from last
        # SpamAssasin rule updates
        '(viagra|ciali([sz])?|(pills?).*(doctors?)*.*(discount)*.*(free))',
        '(free.*(pills?)*.*(every?)*.*(order)*|online.*&.*(save)*|tablet.*(split?ed?)*.*has?le)',
        '(cheap([est])?.*(satisf[ied]?)*.*(U[SK])*.*(CANADIAN)*.*customer|To.*Be.*Remov([ed])?.*(Please?)*)',
        '(100%\s+GUARANTE?D|free.{0,12}(?:(?:instant|express|online|no.?obligation).{0,4})+.{0,32})',
        '(dear.*(?:IT\W|Internet|candidate|sirs?|madam|investor|travell?er|car\sshopper|web))',
        'prestigi?ous\b.{0,20}\bnon-accredited\b.{0,20}\buniversities',
        '(FONT-WEIGHT:.*bold | style.*=.*VISIBILITY.*hidden |face.*=.*Dotum)',
        'Content-Type:\s+application\/.*(-excel|x-ms-dos-.*|compressed|xml|gzip|rar|xz)',
        'Content-Disposition:\s*attachment;(\r\n)?.*(file)?name=.*\.(com|exe|xlsx?|ppt|doc|js|bat)'
    ]

    spam_patterns_compiled = [re.compile(pp, re.I) for pp in spam_patterns]

    if len(body_lines) <= 2:
        score += SCORE

    for l in body_lines:

        # try to normilize line somehow
        l = re.sub('[\+-{2,}]\\]?', ' ', l)

        if filter(lambda y: y.match(l), spam_patterns_compiled):
            # logger.debug ('bl >> '+l)
            score += SCORE

    body_score = []
    body_score.append(score)
    logger.debug('Check body with regexp patterns: '+str(score)+'\n\n')

    return (tuple(body_score))

def create_doc_vector(doc_path):
    logger.debug("Start processing: "+doc_path)
    headers_string, body_lines = cut_header_from_body(doc_path)
    vect = []

    # check mandatory features
    logger.debug("Checking basic features: ")

    if float(os.stat(doc_path).st_size)/1024 < 4.0:
        vect.append(1)
        logger.debug('SMALL_SIZE: '+str(math.floor(float(os.stat(doc_path).st_size)/1024))+' kb')

    else:
        vect.append(0)

    h_dict = headers_parser(headers_string)
    for head_name in ('Subject', 'Received', 'From', 'To', 'Cc', 'Bcc'):
        if head_name not in h_dict.keys():
            vect.append(0.0)
        else:
            vect.append(check_features_headers(h_dict.get(head_name), head_name))
            if head_name == 'Subject':
                vect.append(len(h_dict.get('Subject')))

    vect.append(check_url(body_lines))

    doc_vector = tuple(vect)
    doc_vector += check_headers(h_dict.keys())
    doc_vector += check_body(body_lines)

    # coefficients for axes strething
    # features values in doc_vector have such positions:
    # (size|SUS_subj|SUS_Rcpt|From|To|Cc|Bcc|Subj_len|SUS_url|Auth-Res|DMARC|DKIM|SPF|Sender|X.*|Err|X-Mailer|User-Agent|Content-Type|Mime-Version|Reply-To|Content-Language|body_score
    # (1   | 5      | 2      |1.0 |1 |1 | 1 |        |5      | 1.5    |0.5  |0.3 |0.3|0.5   |0.5|0.5|  0.5   | 0.5      |    0.5     |     0.05   |   0.2  |   0.2          | 0.5
    axis_stretching = (2.0, 5.0, 3.0, 1.0, 1.0, 1.0, 1.0, 5.0, 1.5, 0.1, 0.1, 0.3, 0.3, 0.2, 0.2, 0.1, 0.1, 0.1, 0.05, 0.2, 0.1, 0.5)
    result_vector = [k*x for k, x in zip(axis_stretching, doc_vector)]

    # put the class of doc from collection
    result_vector.append(''.join(os.path.dirname(doc_path).split('/')[-1:]))
    result_vector = tuple(result_vector)

    return (result_vector)


# using for weighted vote
def get_total_sum(neigh_list):
    total_sum = 0.0
    for j in neigh_list:
        if j[0] == 0.0:
            # find a neighbor with zero coordinates ))
            return (sys.maxint, j[1])
        else:
            total_sum += 1.0/math.pow(j[0], 2)

    return (total_sum, j[1])


if __name__ == "__main__":

    usage = "usage: %prog [options] -t training_directory -f file -k k"
    parser = OptionParser(usage)

    parser.add_option("-t", action = "store", type = "string", dest = "train_dir", metavar = "[REQUIRED]",
                      help = "path to dir with spam/ham collections")
    parser.add_option("-f", action = "store", type = "string", dest = "new_doc", metavar = "[REQUIRED]",
                      help = "path to checking email")
    parser.add_option("-k", type = "int", dest = "k", default = 3, metavar = " ",
                      help = "count of nearest neighbors, default k=3")
    parser.add_option("-v", action = "store_true", dest = "verbose", default = False, metavar = " ",
                      help = "be verbose")

    (options, args) = parser.parse_args()

    if options.__dict__.values().count(None) > 0:
        print("")
        parser.print_help()
        print("")
        sys.exit(1)

    # in case if options.verbose is True
    formatter = logging.Formatter('%(message)s')
    logger = logging.getLogger('')
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if options.verbose:
        logger.setLevel(logging.DEBUG)

    # 1. create train dataset
    try:
        train_dataset = []

        for path, subdirs, docs in os.walk(options.train_dir):

            for d in docs:
                sample_path = os.path.join(path, d)
                vector = create_doc_vector(sample_path)
                train_dataset.append(vector)

        # 2. create vector model for processing email
        email_coordinates = (create_doc_vector(options.new_doc))

        # 3. search nearest neighbors
        dist_list = []

        logger.debug("Calculate distances to each document from collection:\n")
        for vec in train_dataset:

            logger.debug('size|Subj|Rcpt|From|To|Cc|Bcc|SUS_url|Auth-Res|DMARC|DKIM|Received-SPF|Sender|X.*|Err|X-Mailer|UA|CType|MV|Reply|CL|b_score')
            logger.debug(str(vec))
            logger.debug(str(email_coordinates))

            vect_coords = vec[:-1]
            sum = 0.0
            for x, y in zip(vect_coords, email_coordinates):
                sum += math.pow((x-y), 2)

            distance = math.sqrt(sum)
            logger.debug("distance = "+str(distance)+'\n')
            dist_list.append((distance, ''.join(vec[-1:])))

        dist_list.sort()

        # 4. take neighbors
        neighbors = dist_list[:options.k]
        logger.debug('\tClosest neighbors list :\n\n'+str(neighbors)+'\n')

        # 5. weighted voting
        results_dict = {}
        spam_neighbors = []
        ham_neighbors = []
        for el in neighbors:
            if el[1] == 'spam':
                spam_neighbors.append(el)
            else:
                ham_neighbors.append(el)

        if not spam_neighbors:
            logger.info('>> HAM')
            sys.exit(0)
        elif not ham_neighbors:
            logger.info('>> SPAM')
            sys.exit(0)

        logger.debug('\tSpam neighbors list :\n')
        logger.debug(spam_neighbors)
        logger.debug('\n\tHam neighbors list :\n')
        logger.debug(ham_neighbors)

        sum1, sum2 = [get_total_sum(s) for s in [spam_neighbors, ham_neighbors]]

        #logger.debug(sum1)
        #logger.debug(sum2)

        if sum1[0] > sum2[0]:
            logger.info('>> '+sum1[1].upper())

        elif abs(sum2[0]-sum1[0]) < 0.1:
            if (sum2[0]-sum1[0]) > 0:
                logger.info('>> PROBABLY '+sum2[1].upper())
            else:
                logger.info('>> PROBABLY '+sum1[1].upper())

        else:
            logger.info('>> '+sum2[1].upper())

    except Exception, details:
        logger.error(str(details))
        sys.exit(1)





