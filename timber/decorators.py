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


def dummy_method(*args,**kwargs):
    return INIT_SCORE

class DummyChecker(object):
    def __getattribute__(self, attr_name):
        return object.__getattribute__(self, dummy_method)


class Validator(object):

    def __init__(self, checker_obj):

        self.checker = checker_obj

    def __call__(self, checker_obj):

        try:
            print('try to init checker')
            self.checker_inst = self.checker(*args, **kwargs)

        except Exception as err:
            logger.warn('Can\'t initialize '+self.checker.__name__+' class for processing msg!')
            logger.warn(err)
            self.checker_inst = DummyChecker()

        return self.checker_inst

    def __getattr__(self, attr_name):
        print('>>> in Validator get_attr')

        try:
            return getattr(self.checker_inst, attr_name)

        except Exception, err:
            print('in Validator exception')
            self.checker_inst.__dict__[attr_name] = INIT_SCORE
            if callable(getattr(self.checker_inst, attr_name)):
                self.checker_inst.__dict__[attr_name] = dummy_method

            return getattr(self.checker_inst, attr_name)



'''''
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
                return getattr(self.checker_cls, name)

            except Exception as err:
                logger.warn('Can\'t initialize '+cls.__name__+' class for processing msg!')
                logger.warn(err)
                self.checker_cls.__dict__[name] = INIT_SCORE
                #return getattr(self.checker_cls, name)
                return self.checker_cls[name]

    # from this scope return a reference to wrapped func
    return Wrapper
'''''


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




