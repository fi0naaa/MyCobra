#!/usr/bin/env python
# -*- coding=utf-8 -*-
"""
A simple command line tool for dumping a source file using the Clang Index
Library.
"""

"""
grep -P -n "a\s=" person.cpp
Popen调用上面命令查询出：
    19:  int a = 1;
    20:  a = a + 1;
    21:  a = max(1,2);
  如果len > 1 则视为重复赋值漏洞。
"""

# put defined var into varlist
var_list = []


def get_info(node, depth=0):
    if opts.maxDepth is not None and depth >= opts.maxDepth:
        children = None
    else:
        children = [get_info(c, depth + 1)
                    for c in node.get_children()]

        if node.is_definition() and str(node.kind) == "CursorKind.VAR_DECL":
            var_list.append(node.spelling or node.displayname)
    return set(var_list)


def main():
    from clang.cindex import Index
    from pprint import pprint

    from optparse import OptionParser, OptionGroup

    global opts

    parser = OptionParser()
    parser.add_option("", "--show-ids", dest="showIDs",
                      help="Compute cursor IDs (very slow)",
                      action="store_true", default=False)
    parser.add_option("", "--max-depth", dest="maxDepth",
                      help="Limit cursor expansion to depth N",
                      metavar="N", type=int, default=None)
    parser.disable_interspersed_args()
    (opts, args) = parser.parse_args()

    # if len(args) == 0:
    #     parser.error('invalid number arguments')

    index = Index.create()
    tu = index.parse("person.cpp", args)
    if not tu:
        parser.error("unable to load input")

    var_set = get_info(tu.cursor)
    print(var_set)



if __name__ == '__main__':
    main()
