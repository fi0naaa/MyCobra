# -*- coding:utf-8 -*-
import sys
from clang.cindex import Config
from clang.cindex import TypeKind
from clang.cindex import CursorKind
from clang.cindex import Index
from clang.cindex import Config
import clang

Config.set_library_file("/usr/lib64/llvm/libclang.so")


def showToken(node):
    ts=node.get_tokens()
    for t in ts:
        print t.spelling

var = []
def iterAST(cursor, fileStr):

    # 在遍历过程中，遇到了一个节点就进行检查
    # CursorKind指的是这个节点在AST中的位置例如（函数，类，参数定义等）
    # TypeKind指的是这个节点的语义类别，例如这个参数的类别是const char，int等类别

    for cur in cursor.get_children():
        if hasattr(cur, "CursorKind") and cur.CursorKind == CursorKind.FUNCTION_DECL:
            # do something
            print("func==", cur.spelling)
            for cur_sub in cur.get_children():
                if cur_sub .kind == CursorKind.CALL_EXPR:
                    pass
                    # do something
                    # 这一段代码分析的是函数定义调用的其他函数。
            if cur.kind == CursorKind.FIELD_DECL:
                pass
                # do something
            elif cur.type.kind == TypeKind.UCHAR:
                pass
                # do something
            elif cur.is_definition() and cur.kind == CursorKind.VAR_DECL:
                varStr = cur.spelling or cur.displayname
                if varStr in fileStr and varStr != "":
                    var.append(cur.spelling or cur.displayname)
            iterAST(cur, fileStr)
        else:
            continue


def iter_cursor_content(cur):
    # 这里展示的是一个提取每个分词的方法。
    cursor_content = ""
    for token in cur.get_tokens():
        # 针对一个节点，调用get_tokens的方法。
        str_token = token.spelling + " "
        cursor_content = cursor_content + str_token
    return cursor_content


def get_vars(cur):
    # 这里展示的是一个提取每个分词的方法。
    vars = []
    for token in cur.get_tokens():
        # 针对一个节点，调用get_tokens的方法。
        cur = token.cursor
        if cur.kind == CursorKind.VAR_DECL and cur.spelling != "":
            vars.append(cur.spelling)
    return set(vars)


index = clang.cindex.Index.create()
tu = index.parse("person.cpp")

vars = get_vars(tu.cursor)
print(vars)

fileStr = iter_cursor_content(tu.cursor)
print(fileStr)
iterAST(tu.cursor, fileStr)
print(var)




# showToken(tu.cursor)
# iterAST(tu.cursor)


