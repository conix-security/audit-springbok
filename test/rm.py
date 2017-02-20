__author__ = 'maurice'


with open('file') as f:
    text = f.read()

f = open('file')

i = 0
s = 0
for line in f:
    for c in line:
        i += 1
        if c == 'x':
            s += int(line[i])
    print s
