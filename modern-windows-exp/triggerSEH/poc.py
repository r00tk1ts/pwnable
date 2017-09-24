#!/usr/bin/python

with open(r"name.dat","w") as f:
	handler = 'bbbb'
	f.write('a'*88 + handler + 'c'*(10000-88-len(handler)))