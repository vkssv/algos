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