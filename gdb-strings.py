########################################################################################################
#
# A gdb python script to dump selected mappings and run strings on them
#
# License: do what thou will.
#
##########################################################################################################

import gdb
import os
import re
import subprocess
import sys

# just dump process mappings with these strings in their objfile names
# leave empty to get everything
whitelist_mappings = [ '', ]

#print(dir(gdb))
#print(gdb.inferiors())

def get_proc_mapping():
	'''run gdb command info proc mappings and return the output as a dictionary. the key is the mapping's start
	address and the value is a dictionary of start address, end address, size, offset, and object file'''

	mappings = gdb.execute("info proc mapping", to_string=True)
	tableoffset = mappings.find('Start Addr')
	mydatastr = mappings[tableoffset:]
	mydatalines = (mydatastr.split('\n'))[1:]

	results = {}

	for l in mydatalines:
		m = re.match('\W+(\w+)\W+(\w+)\W+(\w+)\W+(\w+)\W+(.*).*',l)
		if m:
			results[ m.group(1) ] = { 'startaddr': m.group(1), 'endaddr': m.group(2), 'size': m.group(3), 'offset': m.group(4), 'objfile': m.group(5) }
		else:
			if len(l) > 0: print("could not parse %s" % l)

	print("got %d entries from proc mapping" % len(results.keys()))

	return results

def dump_memory(fname,startaddr,endaddr):
	'''run gdb command dump bin memory to write the specified memory to disk in bin format'''
	gdb.execute("dump bin memory %s %s %s" % (fname,startaddr,endaddr))
	print("dumped memory to %s" % fname)



# get the process mappings in dictionary format
mappings = get_proc_mapping()
for m in mappings.values():

	# if this mapping in our whitelist?
	dodump = False
	for wl in whitelist_mappings:
		if m['objfile'].lower().find(wl) > -1:
			dodump = True

	# yes, mapping is in whitelist, or maybe there is an empty whitelist. 
	# dump memory and run strings on it
	if dodump or len(whitelist_mappings) == 0:
		# dump mapping memory to disk in bin format
		ofile = os.path.basename(m['objfile'])
		fname = "%s-%s-%s.bin" % (ofile,m['startaddr'],m['endaddr'])
		dump_memory( fname, m['startaddr'],m['endaddr'] )

		# run strings on the mapping memory
		results = subprocess.check_output(["strings", fname])
		print("strings results on %s, startaddr %s, endaddr %s.\nfile on disk at %s.\n\n" % (m['objfile'],m['startaddr'],m['endaddr'],fname) )
		if len(results) > 0:
			print("%s",results.decode("utf-8"))
		

