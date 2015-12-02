#!/usr/bin/env python2


def fib(n=1):
    if n <= 1:
        return n
    else:
        return (fib(n - 1) + fib(n - 2))


