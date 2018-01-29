#!/usr/bin/python
# vim: set fileencoding=utf-8

import clang.cindex
import asciitree
import sys

def node_children(node):
    return (c for c in node.get_children() if c.location.file == sys.argv[1])

def print_node(node):
    text = node.spelling or node.displayname
    kind = str(node.kind)[str(node.kind).index('.')+1:]
    return '{} {}'.format(kind, text)

if len(sys.argv) != 2:
    print("Usage: dump_ast.py [header file name]")
    sys.exit()

index = clang.cindex.Index.create()
translation_unit = index.parse(sys.argv[1], ['-x', 'objective-c'])

print asciitree.draw_tree(translation_unit.cursor,
                          lambda n: list(n.get_children()),
                          lambda n: "%s (%s)" % (n.spelling or n.displayname, str(n.kind).split(".")[1]))