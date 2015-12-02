def get_fib_index(num):

    a,b = 0,1
    i = 1
    while(True):
        i +=1
        a, b = b, a + b
        if b>=num:
            return i


def bar(e=None):
    a, b = 20, (e if isinstance(e, int) else 43) % 10

    # a = 20, b = 99 || a = 20, b = 3
    c = a + b #119
    # c = a +e || c = a +b (23)
    d = c if isinstance(e, int) else c + a # 2a+3
    # d = a+e || a+b+a (43) > 3+3+20
    if d == 100:
        return -1
    elif d > 100:
        return d

    return b + c


def mybar(e=None):
    a = 20

    if isinstance(e,int):

        d = a+e%10
        if d == 100:
            return -1
        elif d > 100:
            return d

        return a+2*(e%10)

    return a+6



