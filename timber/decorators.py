# -*- coding: utf-8 -*-

import sys, os, importlib, logging, re, binascii, zlib, math
from pattern_wrapper import BasePattern

INIT_SCORE = BasePattern.INIT_SCORE



logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(filename)s: %(message)s')
#ch = logging.StreamHandler(sys.stdout)
#logger.addHandler(ch)


#from m_wrapper import BeautifulBody

class HamDecorator(object):
    pass


class DummyChecker(object):

    def __getattr__(self, name):
    # On attribute fetch
        self.__dict__[name] = INIT_SCORE
        return self.name


def validator(cls):

    class Wrapper(object):

        print('create attr table of Wrapper')

        def __init__(self, pattern_instance):
            self.checker_cls = DummyChecker()

            try:
                self.checker_cls = cls(pattern_instance)
                print('successfully init')
                print(self.checker_cls.__dict__)

            except Exception as err:
                logger.warn('Can\'t initialize '+cls.__name__+' class for processing msg!')
                logger.warn(err)
                pass

        def __getattr__(self, name):
            print(name)
            try:
                x = getattr(self.checker_cls, name)
            except Exception as err:
                logger.warn('Can\'t initialize '+cls.__name__+' class for processing msg!')
                logger.warn(err)
                self.checker_cls.__dict__[name] = INIT_SCORE

            return getattr(self.checker_cls, name)

    # from this scope return a reference to wrapped func
    return Wrapper

'''''
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


'''''




