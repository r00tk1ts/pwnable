#!/usr/bin/python

payload = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbccccccccccccccccccccccccccc"

with open(r"name.dat","w") as f:
	f.write(payload)