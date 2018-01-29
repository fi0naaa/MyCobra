# -*- coding:utf-8 -*-
import sys
from clang.cindex import TypeKind
from clang.cindex import CursorKind
from clang.cindex import Config
import clang

#Config.set_library_file("/usr/lib64/llvm/libclang.so")


def get_vars(cur):
    # 这里展示的是一个提取每个分词的方法。
    var_list = []
    for token in cur.get_tokens():
        # 针对一个节点，调用get_tokens的方法。
        cur = token.cursor
        if cur.kind == CursorKind.VAR_DECL and cur.spelling != "":
            var_list.append(cur.spelling)
    return list(set(var_list))


index = clang.cindex.Index.create()
tu = index.parse("person.cpp")
vars_list = get_vars(tu.cursor)
print(vars_list)


