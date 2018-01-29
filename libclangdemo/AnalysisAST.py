# -*- coding:utf-8 -*-
import sys
from clang.cindex import Config
from clang.cindex import TypeKind
from clang.cindex import CursorKind
from clang.cindex import Config
import clang

def iterAST(cursor):
    '''
    在遍历过程中，遇到了一个节点就进行检查。
    CursorKind指的是这个节点在AST中的位置例如（函数，类，参数定义等）
    TypeKind指的是这个节点的语义类别，例如这个参数的类别是const char，int等类别。
    '''

    filedict = {}
    filedict["global_var"] = []
    for cur in cursor.get_children():
        if hasattr(cur, "CursorKind") and cur.CursorKind == CursorKind.FUNCTION_DECL:
            # do something
            filedict[cur.spelling] = [];
            for cur_sub in cur.get_children():
                if cur_sub .kind == CursorKind.CALL_EXPR:
                    pass
                    # do something
                    # 这一段代码分析的是函数定义调用的其他函数。
                elif cur.kind == CursorKind.VAR_DECL and cur.spelling != "":
                    filedict[cur.spelling].append(cur.spelling)
        elif cur.kind == CursorKind.FIELD_DECL:
            pass
            # do something
        elif cur.type.kind == TypeKind.UCHAR:
            pass
            # do something
        elif cur.kind == CursorKind.VAR_DECL and cur.spelling != "":
            filedict["global_var"].append(cur.spelling)
        iterAST(cur)
    return filedict


# get_tokens词法分析，获取变量和函数
def get_functions(cur):
    # 这里展示的是一个提取每个分词的方法。
    var_list = []
    for token in cur.get_tokens():
        # 针对一个节点，调用get_tokens的方法。
        cur = token.cursor
        if cur.kind == CursorKind.FUNCTION_DECL and cur.spelling != "":
            var_list.append(cur.spelling or cur.displayname)
    return list(set(var_list))


file_content = {}
# AST树语法分析
def yaccAST(cursor):
    """
    在遍历过程中，遇到了一个节点就进行检查。
    CursorKind指的是这个节点在AST中的位置例如（函数，类，参数定义等）
    TypeKind指的是这个节点的语义类别，例如这个参数的类别是const char，int等类别。
    """
    for idx, cur in enumerate(cursor.get_children()):
        file_content[idx] = {}
        if hasattr(cur, "CursorKind") and cur.CursorKind==CursorKind.FUNCTION_DECL:
            funs_var = file_content[idx][cur.spelling or cur.displayname] = []
            for cur_sub in cur.get_children():
                if cur_sub .kind == CursorKind.CALL_EXPR:
                    pass
                    #这一段代码分析的是函数定义调用的其他函数。
                if cur_sub.kind == CursorKind.VAR_DECL:
                    funs_var.append(cur.spelling)
        elif cur.kind == CursorKind.FIELD_DECL:
            file_content[idx]["FIELD_DECL"] = cur.spelling
            pass
        elif cur.type.kind == TypeKind.UCHAR:
            file_content[idx]["UCHAR"] = cur.spelling
            pass
        iterAST(cur)

index = clang.cindex.Index.create()
tu = index.parse("person.cpp")
# f = iterAST(tu.cursor)
# print(f)
print(get_functions(tu.cursor))
yaccAST(tu.cursor)
from pprint import pprint
pprint(file_content)
