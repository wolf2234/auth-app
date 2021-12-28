
def func(number, min, max):
    if number < min:
        return min
    elif number > max:
        return max
    else:
        return number

def clamp(value, lower, upper):
    return min(max(value, lower), upper)


print(func(30, 18, 0))
print(clamp(30, 18, 0))
