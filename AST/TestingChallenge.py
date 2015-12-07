#!/usr/bin/env python2
# coding: utf-8

'''
------------------ Challenge Description ------------------

1. Построить AST для приведенного ниже скрипта (это можно сделать как встроенными средствами, так и сторонними) и произвести описанные ниже действия на его уровне;
2. Добавить новый метод fib для класса Foo, в задачи которого будет входить рекурсивное вычисление n-го числа ряда Фибоначчи, где n-передается в качестве значения единственного аргумента;
3. Заменить каждое из значений массива переменной c метода baz на вызов метода fib, где аргументом будет достаточное значение числа для получения заменяемого значения массива и возможного остатка;
4. Произвести оптимизацию кода метода bar класса Foo (удаление мертвого кода);
5. Преобразовать результирующий AST обратно в Python-код;
6. Написать юнит-тесты.
7. Нужна программная реализация всех описанных действий:
   - Работа с AST;
   - Добавление методов;
   - Оптимизация кода.

-----------------------------------------------------------
'''

from __future__ import print_function


def blot(cls):
	cls.fib = lambda cls, x: cls.fib(x)
	return cls


@blot
class Foo(object):
	a = 2

	def __init__(self, b=None):
		super(Foo, self).__init__()
		self.a = 2 * (b if isinstance(b, int) and b else 1);

	@staticmethod
	def bar(e=None):
		"""
    	>>> bar(99)
    	38
    	"""
		a, b = 20, (e if isinstance(e, int) else 43) % 10
		c = a + b
		d = c if isinstance(e, int) else c + a

		if d == 100:
			return -1
		elif d > 100:
			return d

		return b + c

	def baz(self, n=None):
		c = [58, 60, 164, 83, 416, 7, n if isinstance(n, int) else 68, 521, 845, 329, 88, 9]
		return map(lambda el: el * self.a, c)


def main():
	obj = Foo()

	# Will be printed: 38
	print(Foo.bar(99))

	# Will be printed: [178, 178, 466, 178, 1220, 16, 178, 1220, 1974, 754, 178, 26]
	print(obj.baz())

if __name__ == '__main__':
	main()
