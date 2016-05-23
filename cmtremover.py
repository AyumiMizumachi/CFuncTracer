import re

def multicomment_remove(s):
  def onecomment_remove(s):
    m = re.search(r'/\*.*?\*/', s, re.DOTALL)
    if m:
      s = s[:m.start()]+s[m.end():]
    return (m, s)
  m, s = onecomment_remove(s)
  while m:
    m, s = onecomment_remove(s)

  return s


def linemulti_remove(s):
  def linecomment_remove(s):
    m = re.search(r'//.*', s)
    if m:
      s = s[:m.start()]
    return (m, s)
  sa = []
  for l in s.splitlines():
    m, lt = linecomment_remove(l)
    sa.append(lt)
  return "\n".join(sa)

def cmtremove(s):
  s = multicomment_remove(s)
  s = linemulti_remove(s)
  return s


if __name__ == "__main__":
  s = """a /* b */ c /* d */
// line comment 2
e /* f */ g /* h */ i
/* j k l
  m n o */
p q r s
// line comment
"""
  print cmtremove(s)
