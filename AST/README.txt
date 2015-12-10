
analyser
==============

analyser - attempt to create simple AST parser, which is 
also capable to perform some modifications of code 
structures on the abstract syntax tree level 

------------------ Challenge Description ------------------

1. build AST for TestingChallenge.py source file and perform 
   some modifications of it's code structures on this level. 
   Needed changes are described below. 

2. add new method fib for class Foo, which will calculate 
   Fibonacci numbers, using recursion call ;
   n - input argument, should be passed only as a single 
   argument ;

3. replace all values of variable "c" in method Foo.baz by 
   Foo.fib method calls. Use appropriate index as argument 
   for Foo.fib for obtaining replacing value and possible 
   remainder ; 

4. perform some code optimizations for Foo.bar method 
   ( remove dead code ) ;

5. compile modified AST into Python code object ;

6. create some unit-tests.

-----------------------------------------------------------

Usage
===========

# ./analyser.py -h
usage: analyser [-h] [-v] PATH

positional arguments:
  PATH        path to file with source code

optional arguments:
  -h, --help  show this help message and exit
  -v          be verbose
root@calypso:~/git/algos/ast#

example of usage:

# ./analyser.py TestingChallenge.py
# ./analyser.py -v TestingChallenge.py

