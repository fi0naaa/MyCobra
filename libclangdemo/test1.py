#!/usr/bin/env python
""" Usage: call with <filename> <typename>
"""
import sys
import clang.cindex


def find_typerefs(node, typename):
    """ Find all references to the type named 'typename'
    """
    if node.kind.is_reference():
        ref_node = clang.cindex.Cursor_ref(node)
        if ref_node.spelling == typename:
            print 'Found %s [line=%s, col=%s]' % (
                typename, node.location.line, node.location.column)
    # Recurse for children of this node
    for c in node.get_children():
        find_typerefs(c, typename)


index = clang.cindex.Index.create()
tu = index.parse("person.cpp")
print 'Translation unit:', tu.spelling
find_typerefs(tu.cursor, "a")