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


class Wrapper(object):
    '''
    Wrap up classes from checkers.py :

    1. if exception happens on Checker-initialisation stage
    - returns self instead of wrapped Checker's class ;

    2. if exception happens, when Checker's method-attribute/attribute
    is called - returns INIT_SCORE instead of attribute and dummy_method
    instead of attribute-method ;

    3. doesn't handle AttributeError if Checkers class was successfully
    initialised, cause this is serious lack of implementation ;
    '''

    def __init__(self, checker_obj):

        self.checker = checker_obj

    def __call__(self, *args):

        try:
            print('try to init checker')
            self.checker_inst = self.checker(*args)

        except Exception as err:
            logger.warn('Can\'t initialize '+self.checker.__name__+' class for processing msg!')
            logger.warn('>>>'+str(err))
            self.checker_inst = self
            print(self.checker.__name__)
            print(str(self.checker_inst.__module__))
            #print(str(self.checker_inst.__class__))

        return self.checker_inst
'''''

    def __getattr__(self, attr_name):

        print('>>> in Validator get_attr')
        self.checker_inst.__dict__[attr_name] = INIT_SCORE
        if callable(getattr(self.checker_inst, attr_name)):
            self.checker_inst.__dict__[attr_name] = (lambda x: INIT_SCORE)

        return getattr(self.checker_inst, attr_name)

        

        print(str(self.checker.__name__))
        print(str(self.checker_inst.__module__))

        return getattr(self.checker_inst, attr_name, INIT_SCORE)


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





