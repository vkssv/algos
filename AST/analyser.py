#!/usr/bin/env python2
# coding: utf-8

import ast, logging, argparse, sys, re
from operator import itemgetter

logger = logging.getLogger('')
formatter = logging.Formatter('%(message)s')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)

MODIFIED_METH = 'baz'
OPTIMIZED_METH = 'bar'
CLASS_NAME='Foo'
attribute_keys = (OPTIMIZED_METH, 'M_attr', 'blot')

# some multistring constants and functions
opt_bar_meth = """
@staticmethod
def bar(e=None):

    a = 20

    if isinstance(e, int):

        d = a+e%10
        if d == 100:
            return -1
        elif d > 100:
            return d

        return a+2*(e%10)

    return a+6
"""

M_class_attr = 'M = {0:0, 1:1}'

fib_decorator = """
def blot(cls):

    def fib(x):

        if x in cls.M:
            return cls.M[x]
        else:
            cls.M[x] = (fib(x-2) + fib(x-1))
            return cls.M[x]

    cls.fib = lambda cls, x: fib(x)

    return cls
"""

values = tuple(ast.parse(i, '<string>', mode='exec') for i in (opt_bar_meth, M_class_attr, fib_decorator))
attributes = dict(zip(attribute_keys, map(itemgetter(0),tuple(l.body for l in values))))

def get_fib_index(num):
    """
    :param num: number from fibonacci sequence
    :return: index of this number from series
    """

    a,b = 0,1
    i = 1
    while(True):
        i +=1
        a, b = b, a + b
        if b>=num:
            return i

def make_assert_node(expression_node, source_line):
    """
    using to generate instance of ast.Assert subclass
    from ast.Expr node with print() call :
      -- takes function names and arguments from
         print() expression;
      -- takes expecting results from commented
         line above each print expression:
         pls, see TestingChallenge.py for any details

    :param expression_node: instance of ast.Expr with print() call
    :param source_line: string with content of TestingChallenge.py
    :return: node with assert call to verify returned results
             or node with print expression if can't parse commented line
    """

    method = expression_node.value.args[0]

    regexpr = r'#\s?Will\s+be\s+printed\s?:\s+.*\n\tprint\(.*\..*\(.*\)\).*\n'
    test_data = re.findall(regexpr, source_line)

    values_line = ''.join([line for line in test_data if method.func.attr in line])
    if len(values_line.strip()) == 0:
        logger.warn('Couldn\'t find expected values for '+str(method.func.attr)+'() call,')
        logger.warn('So skip this test.')
        return expression_node

    values_line = values_line.split(':')[1]

    expected_values = re.search(r'(\[?\d{2,4}(,\s)?)+\]?', values_line)
    if expected_values is None:
        logger.warn('Couldn\'t find expected values for '+str(method.func.attr)+' call,')
        logger.warn('So skip this test.')
        return expression_node

    expected_values = expected_values.group(0)
    expected_values = ast.parse(str(expected_values), '<string>', mode='eval')
    expected_values = expected_values.body

    params = {
                'left': method,
                'ops' : [ast.Eq()],
                'comparators' : [expected_values]
    }

    if method.func.attr == 'baz':
        params['ctx'] = ast.Load()

    return ast.Assert(test=ast.Compare(**params), msg=None)

def test_node(node):
    """
    -- tries to compile and exec modified part as a separate module,
    -- writes error message to stdout if it has failed
    :param node: modified node instance to verify
    """

    tree_part = ast.Module(body=[node])
    tree_part = ast.fix_missing_locations(tree_part)
    try:
        compiled_node = compile(tree_part, '<string>', 'exec')
        exec(compiled_node)

    except (SyntaxError, TypeError) as err:
        logger.error('Following ERROR during compiling this node :\n')
        logger.error(ast.dump(tree_part)+'\n')
        logger.error(str(err))
        pass

    except Exception as err:
        logger.error(str(err))
        pass


class CustomTransformer(ast.NodeTransformer):
    """
    -- replaces values from ast.Num instances to ast.Call,
       where Foo.fib is a static method called with indexes
       from Fibonacci series

    -- obtained Fibonacci numbers should be relative to
       replaced values
    """

    def visit_Num(self, node):

        node = ast.Call(
                            func=ast.Attribute(value=ast.Name(id='self', ctx=ast.Load()), attr='fib', ctx=ast.Load()),
                            args=[ast.Num(n=get_fib_index(node.n))],
                            keywords=[],
                            starargs=None,
                            kwargs=None
        )

        return node


if __name__ == '__main__':

    usage = 'usage: %prog [ file ] -c class_name -v debug'
    parser = argparse.ArgumentParser(prog='analyser')

    parser.add_argument('PATH', type=str, metavar = 'PATH', help='path to file with source code')

    parser.add_argument('-v', action = 'store_true', dest = 'verbose', default = False,
                        help = 'be verbose')

    args = parser.parse_args()


    if args.verbose:
        ch.setLevel(logging.DEBUG)

    try:

        with open(args.PATH, 'rb') as f:
            source_line = f.read()

        # 1. generate AST tree
        tree = ast.parse(source_line, '<string>', mode='exec')

        # 2. obtain class decorator name to add fib method as static method to processed class node
        class_obj = [obj for obj in tree.body if (isinstance(obj, ast.ClassDef) and obj.name == CLASS_NAME)][0]
        decorator = class_obj.decorator_list[0].id

        # 3. modify bar(), baz() methods and class-decorator function
        for stmt in ast.walk(tree):

            if isinstance(stmt, ast.ClassDef) and stmt.name == CLASS_NAME:
                stmt.body.insert(1, attributes.get('M_attr'))

                logger.debug('\nRaw class tree:\n'.upper())
                logger.debug(ast.dump(stmt)+'\n')

                for obj in stmt.body:

                    if isinstance(obj, ast.FunctionDef):
                        i = stmt.body.index(obj)

                        if obj.name == OPTIMIZED_METH:
                            obj = ast.copy_location(attributes.get(OPTIMIZED_METH), obj)

                        elif obj.name == MODIFIED_METH:
                            obj = CustomTransformer().visit(obj)

                        test_node(obj)
                        stmt.body[i] = obj

            elif isinstance(stmt, ast.FunctionDef) and stmt.name == decorator:
                node = attributes.get(decorator)
                test_node(node)
                tree.body[tree.body.index(stmt)] = ast.copy_location(node, stmt)


            # add assert calls before expressions with print() to verify returning values
            elif isinstance(stmt, ast.FunctionDef) and stmt.name == 'main':
                for obj in stmt.body[:]:
                    if isinstance(obj, ast.Expr):
                        i = stmt.body.index(obj)
                        stmt.body.insert(i, make_assert_node(obj, source_line))


        fixed = ast.fix_missing_locations(tree)
        logger.debug('\nModified tree:\n'.upper())
        logger.debug(ast.dump(fixed)+'\n')

        # 4. generate code object from modified tree and execute it
        codeobj = compile(fixed, '<string>', 'exec', flags=65536)
        logger.info('==> try to execute modified codeobject:\n')
        exec codeobj

    except Exception as err:
        logger.error('ERROR: '+str(err))
        pass






