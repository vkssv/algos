#!/usr/bin/env python2
# coding: utf-8


import ast, logging, argparse, sys

from operator import add
from itertools import dropwhile

logger = logging.getLogger('')
formatter = logging.Formatter('%(levelname)s %(message)s')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
logger.addHandler(ch)

MODIFIED_METH = 'baz'
OPTIMIZED_METH = 'bar'


def get_fib_index(num):

    a,b = 0,1
    i = 1
    while(True):
        i +=1
        a, b = b, a + b
        if b>=num:
            return i


def new_bar(e=None):
    a = 20

    if isinstance(e,int):

        d = a+e%10
        if d == 100:
            return -1
        elif d > 100:
            return d

        return a+2*(e%10)

    return a+6


class AssertCmpTransformer(ast.NodeTransformer):

    def visit_Assert(self, node):
        if isinstance(node.test, ast.Compare) and \
                len(node.test.ops) == 1 and \
                isinstance(node.test.ops[0], ast.Eq):
            call = ast.Call(func=ast.Name(id='assert_equal', ctx=ast.Load()),
                            args=[node.test.left, node.test.comparators[0]],
                            keywords=[])
            # Wrap the call in an Expr node, because the return value isn't used.
            newnode = ast.Expr(value=call)
            ast.copy_location(newnode, node)
            ast.fix_missing_locations(newnode)
            return newnode

        # Remember to return the original node if we don't want to change it.
        return node


class UnitTest(method_node):

    test_namespace = {}
    wrapper = ast.Module(body=[method_node])

    try:
        co = compile(wrapper, "<ast>", 'exec')
        exec(co, test_namespace)
    except AssertionError:
        print("Assertion failed on line", method_node.lineno, ":")
        print(method_node.lineno])
        # If the error has a message, show it.
        if e.args:
            print(e)
        print()


class NodeEditor(ast.NodeTransformer):
    """Wraps all integers in a call to Integer()"""

    def visit_Assign(self, node):

        logger.debug('ASSIGN NODE: '+str(ast.dump(node)))
        logger.debug('elts: '+str(node.value.elts))
        needed_num_nodes = tuple(el for el in dropwhile(lambda x: isinstance(x, ast.Num),tuple(node.value.elts)))
        logger.debug('>>>>'+str(needed_num_nodes))
        logger.debug('>>>>'+str(needed_num_nodes[0].orelse.n))

        needed_nums  = (needed_num_nodes[0].orelse.n,)+tuple(i.n for i in needed_num_nodes[1:])
        logger.debug('>>>>'+str(needed_nums))
        args_nums = tuple(get_fib_index(n) for n in needed_nums)
        logger.debug("args_nums "+str(args_nums))

        return ast.copy_location(ast.parse(str(args_nums), mode='eval'), node)


    def visit_FunctionDef(self, node):
        logger.debug('FUNC NODE: '+str(ast.dump(node)))
        new_meth = ast.FunctionDef(
                        name='bar',
                        args=ast.arguments(
                            args=[ast.Name(id='e', ctx=ast.Param())],
                            vararg=None,
                            kwarg=None,
                            defaults=[ast.Name(id='None', ctx=ast.Load())]
                        ),
                        body=[
                                ast.Assign(targets=[ast.Name(id='a', ctx=ast.Store())], value=ast.Num(n=20)),
                                ast.If(
                                        test=ast.Call(func=ast.Name(id='isinstance', ctx=ast.Load()), args=[ast.Name(id='e', ctx=ast.Load()), ast.Name(id='int', ctx=ast.Load())], keywords=[], starargs=None, kwargs=None),
                                        body=[
                                                ast.Assign(
                                                            targets=[ast.Name(id='d', ctx=ast.Store())],
                                                            value=ast.BinOp(
                                                                                left=ast.Name(id='a', ctx=ast.Load()), op=ast.Add(),
                                                                                right=ast.BinOp(
                                                                                                    left=ast.Name(id='e', ctx=ast.Load()), op=ast.Mod(),
                                                                                                    right=ast.Num(n=10)
                                                                            )
                                                            )
                                                ),
                                                ast.If(
                                                        test=ast.Compare(
                                                                            left=ast.Name(id='d', ctx=ast.Load()),
                                                                            ops=[ast.Eq()],
                                                                            comparators=[ast.Num(n=100)]
                                                        ),
                                                        body=[ast.Return(value=ast.Num(n=-1))],
                                                        orelse=[
                                                                    ast.If(
                                                                                test=ast.Compare(left=ast.Name(id='d', ctx=ast.Load()), ops=[ast.Gt()], comparators=[ast.Num(n=100)]),
                                                                                body=[ast.Return(value=ast.Name(id='d', ctx=ast.Load()))],
                                                                                orelse=[]
                                                                    )
                                                        ]
                                                ),
                                                ast.Return(
                                                                value=ast.BinOp(left=ast.Name(id='a', ctx=ast.Load()), op=ast.Add(),
                                                                                right=ast.BinOp(left=ast.Num(n=2), op=ast.Mult(), right=ast.BinOp(left=ast.Name(id='e', ctx=ast.Load()), op=ast.Mod(), right=ast.Num(n=10))))
                                                )
                                        ],
                                        orelse=[]
                                ),
                                ast.Return(
                                            value=ast.BinOp(
                                                                left=ast.Name(id='a', ctx=ast.Load()), op=ast.Add(),
                                                                right=ast.Num(n=6)
                                            )
                                )
                        ],
                        decorator_list=[]
        )

        return ast.copy_location(new_meth, node)




if __name__ == '__main__':

    usage = 'usage: %prog [ file ] -c class_name -v debug'
    parser = argparse.ArgumentParser(prog='analyser')

    parser.add_argument('PATH', type=str, metavar = 'PATH', help='path to file with source code')

    parser.add_argument('-c', type=str, metavar = '', dest = 'class_name', default = 'Foo',
                        help = 'name of the class to modify')

    parser.add_argument('-v', action = 'store_true', dest = 'verbose', default = False,
                        help = 'be verbose')

    args = parser.parse_args()



    if args.verbose:

        ch.setLevel(logging.DEBUG)


    with open(args.PATH, encoding='utf-8', 'rb') as f:
        code_line = reduce(add,tuple(f))

    tree = ast.parse(code_line,mode='exec')
    logger.debug(ast.dump(tree))

    fib_method = ast.FunctionDef(
                            name='fib',
                            args=ast.arguments(args=[ast.Name(id='n', ctx=ast.Param())], vararg=None, kwarg=None, defaults=[ast.Num(n=1)]),
                            body=[ast.If(test=ast.Compare(left=ast.Name(id='n', ctx=ast.Load()), ops=[ast.LtE()], comparators=[ast.Num(n=1)]), body=[ast.Return(value=ast.Name(id='n', ctx=ast.Load()))],
                                        orelse=[ast.Return(value=ast.BinOp(
                                        left=ast.Call(func=ast.Name(id='fib', ctx=ast.Load()), args=[ast.BinOp(left=ast.Name(id='n', ctx=ast.Load()), op=ast.Sub(), right=ast.Num(n=1))], keywords=[], starargs=None, kwargs=None), op=ast.Add(),
                                        right=ast.Call(func=ast.Name(id='fib', ctx=ast.Load()), args=[ast.BinOp(left=ast.Name(id='n', ctx=ast.Load()), op=ast.Sub(), right=ast.Num(n=2))], keywords=[], starargs=None, kwargs=None)))]
                                  )
                            ],
                            decorator_list=[ast.Name(id='staticmethod', ctx=ast.Load())]
    )


    for stmt in ast.walk(tree):
        if isinstance(stmt, ast.ClassDef) and stmt.name == args.class_name:
            logger.debug("class "+str(ast.dump(stmt)))

            stmt.body.append(fib_method)
            logger.debug('\nModified stmts list: '+str(stmt.body))

            for obj in stmt.body:
                if isinstance(obj, ast.FunctionDef) and obj.name == MODIFIED_METH:
                    assign_node = [el for el in obj.body if isinstance(el, ast.Assign)][0]
                    obj = NodeEditor().visit(assign_node)

                elif isinstance(obj, ast.FunctionDef) and obj.name == OPTIMIZED_METH:
                    obj = NodeEditor().visit(obj)


    logger.debug('\nModified tree: '+ast.dump(tree))


    fixed = ast.fix_missing_locations(tree)

    codeobj = compile(fixed, '<string>', 'exec')
    print("\nNew code "+str(codeobj))

























