#! /bin/env python
# coding: utf-8

""" fparse.py is function parser.


It can check a function calls some other/same functions.

"""
__author__ = "AyumiMizumachi"
__version__ = '0.1'

import re, sys, os
# import subprocess
import commands
import pickle, json, tarfile
import glob
gzip_exist = True
try:
	import gzip
except:
	gzip_exist = False

class CtagsLine(object):
	""" object per line of ctags output """
	def __init__(self, string):
		""" the constructor separates ctags output """
		self.name, self.fpath, self.re_tofind, 
			self.type, self.startline, self.scope = self._sepColumn(string)
		self.lastline = -1
		self.lines = []
		self.calllines = set([])

	def getStartLine(self):
		return self.startline

	def setLastLine(self, lastlineno):
		self.lastline = lastlineno

	def getFuncType(self, callline):
		f = open("./untrace.kw", "r")
		untrace = json.load(f)
		f.close()
		f = open("./targets.kw", "r")
		targets = json.load(f)
		f.close()

		retstr = ""
		found_color = "\x1b[32m"
		for key in targets:
			if callline in targets[key]:
				retstr = " : " + key
				found_color = "\x1b[33m"

		if retstr == "":
			for key in untrace:
				if callline in untrace[key]:
					retstr = " : " + key
					found_color = "\x1b[31m"
					break
			
		return (retstr, found_color)

	def __str__(self):
		s = "\x1b[32m"
		s += "=" * 50 + "\n"
		s += "name = %s\n" % self.name
		s += "path = %s\n" % self.fpath
		s += "regx = %s\n" % self.re_tofind 
		s += "type = %s\n" % self.type
		s += "line = %s - %s\n" % (self.startline, self.lastline) 
		s += "scpe = %s\n" % self.scope
		s += "-- calling function --\n"
		for callline in self.calllines:
			functype, found_color = self.getFuncType(callline)
			s += found_color
			s += " > %s%s\n" % (callline, functype)
			s += "\x1b[32m"
		s += "----------------------\n"
		s += "\x1b[39m"
		return s

	def getDumpFileName(self):
		return "./results/" + os.path.basename(self.fpath) + "_" + self.name + ".dump"

	def jsonDump(self, file=None):
		if file is None:
			file = self.getDumpFileName()
		jsondata = {
			"name": self.name,
			"fpath": self.fpath,
			"pattern": self.re_tofind,
			"type": self.type,
			"line_begin": self.startline,
			"line_end": self.lastline,
			"call": list(self.calllines)
		}
		f = open(file, "w")
		json.dump(jsondata, f, ensure_ascii=False, indent=4, sort_keys=True, separators=(',', ': '))
		# json.dump(jsondata, f, ensure_ascii=False, indent=4, separators=(',', ': '))
		f.close()
	
	def pickleDump(self, file):
		pickledata = (self.name, self.fpath, self.re_tofind, self.type, self.startline, self.lastline, list(self.calllines))
		f = open(file, "w")
		pickle.dump(pickledata, f)
		f.close()
 
	def _sepColumn(self, string):
		""" seperate ctags output
			ctags (-f- --fields=+nKs) output is like following:

			ID<tab>SOURCE_PATH<tab>PATTERN;"<tab>TYPE<tab>line:NUM(options)

			
		"""
		
		mobj = re.search(r'([^\t]+)\t([^\t]+)\t(.+);"\t(.+)\tline:([^\t]+)(?:\t(file:))?', string)
		if mobj:
			# print mobj.groups()
			name = mobj.group(1)
			path = mobj.group(2)
			rstr = mobj.group(3)
			type = mobj.group(4)
			line = int(mobj.group(5), 0)
			if mobj.group(6) is not None:
				scope = True
			else:
				scope = False
			return name, path, rstr, type, line, scope
		else:
			return None, None, None, None, None, False
	
	def show(self):
		""" for debug """
		print self.__str__(),

	def loadlines(self):
		""" load target lines from file. and keep it in self.lines[]  """
		f = open(self.fpath, "r")
		lines = f.read().splitlines()
		f.close()
		for i, line in enumerate(lines):
			if self.startline <= (i+1) and (i+1) <= self.lastline:
				self.lines.append(line)
			# if line.startswith("}"):
			# 	break

	def getFuncCandidates(self, line, ary):
		mobj = re.search(r'([_a-zA-Z][_a-zA-Z0-9]*)\s*\(', line)
		if mobj:
			ary.append(mobj.group(1))
			self.getFuncCandidates(line[mobj.end():], ary)
		

	def makecalltree(self):
		""" you have to load target lines with self.loadlines() before you use this method """
		c_keywords = [ "if", "for", "return", "while", "switch", "sizeof" ]
		candidates = []
		for i, line in enumerate(self.lines):
			if i == 0:
				# the line of function definition
				continue
			self.getFuncCandidates(line, candidates)

			""" mobj = re.search(r'([_a-zA-Z][_a-zA-Z0-9]*)\s*\(', line)
			if mobj:
				mobjstr = mobj.group(1)
				if mobjstr in c_keywords:
					pass
				else:
					mo = re.search(r'([_a-zA-Z][_a-zA-Z0-9]*)\s*\(', line)
					if mo:
						self.calllines.add(mo.group(1))
			else:
				pass
			"""
			for candidate in candidates:
				if candidate in c_keywords:
					continue
				else:
					self.calllines.add(candidate)

		
	def showlines(self):
		""" for debug 
			you have to load target lines with self.loadlines() before you use this method """
		self.show()
		return

		for line in self.lines:
			print line

class FTracer(object):
	def __init__(self, fname):
		self.fname = fname
		self.nline = self._getNumOfFile(fname)
		self.debug = True

	def _getNumOfFile(self, fname):
		f = open(fname, "r")
		n = len(f.read().splitlines())
		f.close()
		return n

	def makeRegularCtagsObjects(self):
		cs = []
		for ctl in  commands.getoutput('ctags -f- --fields=+nKs %s' % self.fname).splitlines():
			cl = CtagsLine(ctl)
			cs.append(cl)

		prev_c = None
		cs_sort = sorted(cs, key=lambda u: u.startline)
		for c in cs_sort:
			if prev_c:
				prev_c.setLastLine(c.getStartLine() - 1)
			prev_c = c

		if prev_c:
			prev_c.setLastLine(self.nline)

		# if self.debug:
		# 	for c in cs_sort:
		# 		c.show()
		return cs_sort

	def archive(self, rcobjs):
		global gzip_exist
		if gzip_exist:
			tarflg = "w:gz"
		else:
			tarflg = "w"
		tarf = tarfile.open("./results/" + os.path.basename(self.fname) + ".tar", tarflg)

		for cobj in rcobjs:
			tarf.add(cobj.getDumpFileName())
		tarf.close()
		for pth in glob.glob("./results/*.dump"):
			os.remove(pth)

		if not gzip_exist:
			for pth in glob.glob("./results/*.tar"):
				# subprocess.call("gzip %s" % pth)
				os.system("gzip %s" % pth)

	def run(self):
		regular_ctobjs = self.makeRegularCtagsObjects()
		for ctobj in regular_ctobjs:
			ctobj.loadlines()
			ctobj.makecalltree()
			ctobj.showlines()
			ctobj.jsonDump()
		self.archive(regular_ctobjs)



if __name__ == "__main__":
	for i in xrange(1, len(sys.argv)):
		ftracer = FTracer(sys.argv[i])
		ftracer.run()

