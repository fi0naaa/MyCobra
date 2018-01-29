#!/usr/bin/env python
# -*- coding:utf-8 -*-
import sys
from pprint import pprint
from clang.cindex import Config
from clang.cindex import TypeKind
from clang.cindex import CursorKind
from clang.cindex import Index
import clang

funs_list1 = []

child_list1 = []

# brief : 返回文件中函数信息
# node : cur节点，f:要检查的文件，funs_list:结果列表
# return ： f 文件包含的函数信息（所在的文件，起始和结束的行号，以及函数类型）
def get_funs_info(node, f, funs_list):
    for c in node.get_children():
        children = get_funs_info(c, f, funs_list)
    if node.is_definition() and not node.spelling == "" and str(node.location.file) == f:
        if node.kind == CursorKind.FUNCTION_DECL or node.kind == CursorKind.CXX_METHOD:
            fun = {}
            fun_detail = fun[node.spelling or node.displayname] = {}
            fun_detail["start_line"] = node.extent.start.line
            fun_detail["end_line"] = node.extent.end.line
            fun_detail["kind"] = node.kind
            fun_detail["file"] = str(node.location.file)
            fun_detail["vul_num"] = 0
            fun_detail["vul"] = {}
            funs_list.append(fun)
    return funs_list


# [{'sub_int': {'end_line': 9,
#               'file': 'person.cpp',
#               'kind': CursorKind.CXX_METHOD,
#               'start_line': 7}}
#  ]

# 返回行号所在的函数list, 可能存在内部类，可能在多个函数里
def get_funsSet_byLineNum(line_num, funs_list):
    result_list = []
    for fun in funs_list:
        for fun_name, fun_detail in fun.items():
            if fun_detail["start_line"] <= int(line_num) <= fun_detail["end_line"]:
                result_list.append(fun)
    return result_list


def main():
    index = Index.create()
    tu = index.parse("person.cpp")

    func = get_funs_info(tu.cursor, "person.cpp", [])
    # pprint(('nodes', get_info(tu.cursor)))
    # pprint(func)

   # pprint(func)
    pprint(func)

    funlist = get_funsSet_byLineNum(8,func)
    print(funlist)
    print("end...")


if __name__ == '__main__':
    main()