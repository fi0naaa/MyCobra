import sys
import clang.cindex
from clang.cindex import Config
Config.set_library_file("/usr/lib64/llvm/libclang.so")


def showToken(node):
    ts=node.get_tokens()
    for t in ts:
        print t.spelling


def iterAST(cursor):
  for cur in cursor.get_children():
    print(cur)
    iterAST(cur)


index = clang.cindex.Index.create()
tu = index.parse("person.cpp")
# showToken(tu.cursor)
iterAST(tu.cursor)


