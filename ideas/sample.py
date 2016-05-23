

class CFObj(object):
	def __init__(self, name):
		self.name = name
		self.calllist = []
	def add(self, callee):
		self.calllist.append(callee)
	def __str__(self):
		s = 'CFObj:<%s>\n' % self.name
		for c in self.calllist:
			s += '  calee: %s' % str(c)
		return s

if __name__ == '__main__':
	s = '''main
func1
func2
func3
'''
	# make objects
	objpool = {}
	for fname in s.splitlines():
		objpool.update({fname: CFObj(fname)})
	
	print objpool

	calling = [ 'main:func1', 'main:func2', 'func2:func3' ]
	for call in calling:
		caller, callee = call.split(':')
		caller_obj = objpool[caller]
		callee_obj = objpool[callee]
		caller_obj.add(callee_obj)

	for k, v in objpool.iteritems():
		print k + '=' + str(v)


