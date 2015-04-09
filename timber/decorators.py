# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii, zlib, math




logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(filename)s: %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#logger.addHandler(ch)


#from m_wrapper import BeautifulBody

class HamDecorator(object):
    pass



def validator(F):
    print('in val')
    def wrapper(*args):
        print('in wrap')

        print(args)
        # from this scope return a func() call
        print(args[0])
        return F(*args)

    # from this scope return a reference to wrapped func
    return wrapper


class A(object):
    def __init__(self, m, *args):
        self.m = m


class B(A):
    def __init__(self, *args):
        super(B, self).__init__(*args)
        self.map = {}

    @validator
    def meth(self):
        x = self.m.get('kjkj')
        print(x)
        print(type(x))
        return x







