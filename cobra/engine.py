# -*- coding: utf-8 -*-

"""
    engine
    ~~~~~~

    Implements scan engine

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import os
import re
import json
import fcntl
import traceback
import subprocess
import multiprocessing
from . import const
from .rule import Rule
from .utils import Tool
from .log import logger
from .config import running_path
from .result import VulnerabilityResult,LSVulnerabilityResult
from .cast import CAST
from .parser import scan_parser
import sys
from clang.cindex import TypeKind
from clang.cindex import CursorKind
from clang.cindex import Config
import clang
from .cve import scan_cve
from prettytable import PrettyTable


class Running:
    def __init__(self, sid):
        self.sid = sid

    def init_list(self, data=None):
        """
        Initialize asid_list file.
        :param data: list or a string
        :return:
        """
        file_path = os.path.join(running_path, '{sid}_list'.format(sid=self.sid))
        if not os.path.exists(file_path):
            if isinstance(data, list):
                with open(file_path, 'w') as f:
                    fcntl.flock(f, fcntl.LOCK_EX)
                    f.write(json.dumps({
                        'sids': {},
                        'total_target_num': len(data),
                    }))
            else:
                with open(file_path, 'w') as f:
                    fcntl.flock(f, fcntl.LOCK_EX)
                    f.write(json.dumps({
                        'sids': {},
                        'total_target_num': 1,
                    }))

    def list(self, data=None):
        """
        Update asid_list file.
        :param data: tuple (s_sid, target)
        :return:
        """
        file_path = os.path.join(running_path, '{sid}_list'.format(sid=self.sid))
        if data is None:
            with open(file_path, 'r') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                result = f.readline()
                return json.loads(result)
        else:
            with open(file_path, 'r+') as f:  # w+ causes a file reading bug
                fcntl.flock(f, fcntl.LOCK_EX)
                result = f.read()
                if result == '':
                    result = {'sids': {}}
                else:
                    result = json.loads(result)
                result['sids'][data[0]] = data[1]
                f.seek(0)
                f.truncate()
                f.write(json.dumps(result))

    def status(self, data=None):
        file_path = os.path.join(running_path, '{sid}_status'.format(sid=self.sid))
        if data is None:
            with open(file_path) as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                result = f.readline()
            return json.loads(result)
        else:
            data = json.dumps(data)
            with open(file_path, 'w') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                f.writelines(data)

    def data(self, data=None):
        file_path = os.path.join(running_path, '{sid}_data'.format(sid=self.sid))
        if data is None:
            with open(file_path) as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                result = f.readline()
            return json.loads(result)
        else:
            data = json.dumps(data, sort_keys=True)
            with open(file_path, 'w+') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                f.writelines(data)

    def is_file(self, is_data=False):
        if is_data:
            ext = 'data'
        else:
            ext = 'status'
        file_path = os.path.join(running_path, '{sid}_{ext}'.format(sid=self.sid, ext=ext))
        return os.path.isfile(file_path)


def score2level(score):
    level_score = {
        'CRITICAL': [9, 10],
        'HIGH': [6, 7, 8],
        'MEDIUM': [3, 4, 5],
        'LOW': [1, 2]
    }
    score = int(score)
    level = None
    for l in level_score:
        if score in level_score[l]:
            level = l
    if level is None:
        return 'Unknown'
    else:
        if score < 10:
            score_full = '0{s}'.format(s=score)
        else:
            score_full = score

        a = '{s}{e}'.format(s=score * '■', e=(10 - score) * '□')
        return '{l}-{s}: {ast}'.format(l=level[:1], s=score_full, ast=a)


def scan_single(target_directory, single_rule):
    try:
        return SingleRule(target_directory, single_rule).process()
    except Exception:
        raise


def scan_single_rule(target_directory, single_rule):
    try:
        return SingleRule(target_directory, single_rule).my_process
    except Exception:
        raise


def scan(target_directory, a_sid=None, s_sid=None, special_rules=None, language=None, framework=None, file_count=0,
         extension_count=0):
    r = Rule()

    # 获取配置文件中的所有缺陷
    vulnerabilities = r.vulnerabilities

    # 获取配置文件中的语言
    languages = r.languages
    frameworks = r.frameworks

    # 如果special_rules为None，获取所有规则
    rules = r.rules(special_rules)
    find_vulnerabilities = []

    # cve_vuls = scan_cve(target_directory)
    # find_vulnerabilities += cve_vuls

    # def store(result):
    #     if result is not None and isinstance(result, list) is True:
    #         for res in result:
    #             res.file_path = res.file_path.replace(target_directory, '')
    #             find_vulnerabilities.append(res)
    #     else:
    #         logger.debug('[SCAN] [STORE] Not found vulnerabilities on this rule!')

    def my_store(result):
        if result is not None and isinstance(result, list) is True:
            for res in result:
                find_vulnerabilities.append(res)
        else:
            logger.debug('[SCAN] [STORE] Not found vulnerabilities on this rule!')

    # brief : 返回文件中函数信息
    # node : cur节点
    # f : 要检查的文件
    # funs_list : 结果列表
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
                fun_detail["kind"] = str(node.kind)
                fun_detail["file"] = str(node.location.file)
                fun_detail["vul"] = {}
                funs_list.append(fun)
        return funs_list

    # 返回行号所在的函数list, 可能存在内部类，可能在多个函数里
    def get_function_list_by_line_num(var, grep_result, funs_list):
        var_line_results = grep_result.strip().split("\n")
        # 当匹配到的行数大于1，则为存在变量重复赋值
        if len(var_line_results) > 1:
            # 38:  durian = aResultSet->add_int(1);
            # 根据：截取 var_line_results
            vul_list = {}
            for var_reevaluate_line in var_line_results:
                line_num = var_reevaluate_line.split(":")[0]
                code_content = var_reevaluate_line.split(":")[1]
                # 判断语句在哪个函数
                for fun in funs_list:
                    for fun_name, fun_detail in fun.items():
                        if fun_detail["start_line"] <= int(line_num) <= fun_detail["end_line"]:
                            var_detail = fun_detail["vul"][var] = fun_detail["vul"].get(var, {})
                            var_detail["line:" + line_num] = code_content
                        continue
        return  funs_list

    # evaluate funs_list, if vul_num < 2, del
    def evaluate_funs_list(funs_list):
        lens = len(funs_list)
        while lens > 0:
            for fun_name, fun_detail in funs_list[lens-1].items():
                for var, var_detail in fun_detail["vul"].items():
                    if len(var_detail) < 2:
                        fun_detail["vul"].pop(var)
                if len(fun_detail["vul"]) == 0:
                    funs_list.pop(lens-1)
                lens -= 1
        return funs_list

    # 递归扫描target中的cpp文件，识别变量重复赋值缺陷、
    def analysis_var_reevaluate(directory):
        var_reevaluate_list = []
        files = os.listdir(directory)
        # 获取clang接口
        index = clang.cindex.Index.create()

        # 获取cur对应AST中的变量（即cur.kind为Cursorkind.VAR_DECL的var）
        # return: vars的一个去重的list集合
        # todo:将这个方法抽象到工具库
        def get_vars(cur):
            # 这里展示的是一个提取每个分词的方法。
            var_list = []
            for token in cur.get_tokens():
                # 针对一个节点，调用get_tokens的方法。
                cur = token.cursor
                if cur.kind == CursorKind.VAR_DECL and cur.spelling != "":
                    var_list.append(cur.spelling)
            # 去重，list和set互相转化
            return list(set(var_list))

        for f in files:
            f = os.path.join(directory, f)
            if os.path.isfile(f):
                if f.lower()[-4:] == ".cpp":
                    tu = index.parse(f)
                    var_reevaluate_list = get_funs_info(tu.cursor, f, [])
                    # 获取cpp文件中的变量
                    vars_list = get_vars(tu.cursor)
                    # 遍历每个变量，grep查询
                    for var in vars_list:
                        # grep命令判断变量后的赋值语句是否包含特定字符串
                        # -s Suppress error messages / -n Show Line number / -r Recursive / -P Perl regular expression
                        # grep -P -n "durian\s?=\s?.*ResultSet*" person.cpp
                        param = [Tool().grep, "-s", "-n", "-r", "-P"] + [var+"\s?=\s?.*ResultSet*", f]
                        try:
                            p = subprocess.Popen(param, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            result, error = p.communicate()  # communicate(stdin、timeout) return stdout and std err
                        except Exception as e:
                            traceback.print_exc()
                            logger.critical('match exception ({e})'.format(e=e.message))
                            continue
                        try:
                            var_line_result = result.decode('utf-8')
                            error = error.decode('utf-8')
                            # exists result
                            if var_line_result == '' or var_line_result is None:
                                logger.debug("没匹配到变量重复赋值！")
                                continue
                            var_reevaluate_list = get_function_list_by_line_num(var, var_line_result, var_reevaluate_list)

                        except AttributeError as e:
                            pass
                        if len(error) is not 0:
                            logger.critical("grep查询变量有误！")
                var_reevaluate_list = evaluate_funs_list(var_reevaluate_list)
                my_store(var_reevaluate_list)
            elif os.path.isdir(f):
                analysis_var_reevaluate(f)
        # evaluate_funs_list(var_reevaluate_list)
        return var_reevaluate_list

    analysis_var_reevaluate(target_directory)
    # my_store(analysis_var_reevaluate(target_directory))

    try:
        pool = multiprocessing.Pool()
        if len(rules) == 0:
            logger.critical('no rules!')
            return False
        logger.info('[PUSH] {rc} Rules'.format(rc=len(rules)))
        push_rules = []
        off_rules = 0
        for idx, single_rule in enumerate(rules):
            if single_rule['status'] is False:
                off_rules += 1
                logger.debug('[CVI-{cvi}] [STATUS] OFF, CONTINUE...'.format(cvi=single_rule['id']))
                continue
            # SR(Single Rule)
            logger.debug("""[PUSH] [CVI-{cvi}] {idx}.{name}({language})""".format(
                cvi=single_rule['id'],
                idx=idx,
                name=single_rule['name'],
                language=single_rule['language']
            ))

            if single_rule['language'] in languages:
                single_rule['extensions'] = languages[single_rule['language']]['extensions']
                push_rules.append(single_rule['id'])
                pool.apply_async(scan_single_rule, args=(target_directory, single_rule), callback=my_store)
            else:
                logger.critical('unset language, continue...')
                continue

        pool.close()
        pool.join()
    except Exception:
        raise

    #     # print
    # data = []
    # table = PrettyTable(['#', 'CVI', 'VUL', 'Rule', 'Lang', 'Level-Score', 'Target', 'Commit(Time, Author)', 'Source Code Content', 'Analysis'])
    # table.align = 'l'
    # trigger_rules = []
    # for idx, x in enumerate(find_vulnerabilities):
    #     trigger = '{fp}:{ln}'.format(fp=x.file_path, ln=x.line_number)
    #     commit = u'{time}, @{author}'.format(author=x.commit_author, time=x.commit_time)
    #     level = score2level(x.level)
    #     cvi = x.id[0:3]
    #     if cvi in vulnerabilities:
    #         cvn = vulnerabilities[cvi]
    #     else:
    #         cvn = 'Unknown'
    #     try:
    #         code_content = x.code_content[:50].strip()
    #     except AttributeError as e:
    #         code_content = x.code_content.decode('utf-8')[:100].strip()
    #     row = [idx + 1, x.id, cvn, x.rule_name, x.language, level, trigger, commit, code_content, x.analysis]
    #     data.append(row)
    #     table.add_row(row)
    #     if x.id not in trigger_rules:
    #         logger.debug(' > trigger rule (CVI-{cvi})'.format(cvi=x.id))
    #         trigger_rules.append(x.id)
    # diff_rules = list(set(push_rules) - set(trigger_rules))
    # vn = len(find_vulnerabilities)
    # if vn == 0:
    #     logger.info('[SCAN] Not found vulnerability!')
    # else:
    #     logger.info("[SCAN] Trigger Rules/Not Trigger Rules/Off Rules: {tr}/{ntr}/{fr} Vulnerabilities ({vn})\r\n{table}".format(tr=len(trigger_rules), ntr=len(diff_rules), fr=off_rules, vn=len(find_vulnerabilities), table=table))
    #     if len(diff_rules) > 0:
    #         logger.info('[SCAN] Not Trigger Rules ({l}): {r}'.format(l=len(diff_rules), r=','.join(diff_rules)))

    # completed running data
    if s_sid is not None:
        Running(s_sid).data({
            'code': 1001,
            'msg': 'scan finished',
            'result': {
                'vulnerabilities': find_vulnerabilities,
                'language': language,
                'framework': framework,
                'extension': extension_count,
                'file': file_count,
                'push_rules': len(rules),
                'target_directory': target_directory,
            }
        })
    return True


class SingleRule(object):
    def __init__(self, target_directory, single_rule):
        self.target_directory = target_directory
        self.find = Tool().find
        self.grep = Tool().grep
        self.sr = single_rule
        # Single Rule Vulnerabilities
        """
        [
            vr
        ]
        """
        self.rule_vulnerabilities = []

    def origin_results(self):
        logger.debug('[ENGINE] [ORIGIN] match-mode {m}'.format(m=self.sr['match-mode']))
        if self.sr['match-mode'] == const.mm_find_extension:
            # find
            filters = []
            for index, e in enumerate(self.sr['extensions']):
                if index > 0:
                    filters.append('-o')
                filters.append('-iname')
                filters.append('*{e}'.format(e=e))
            # Find Special Ext Files -type f (regular file)
            param = [self.find, self.target_directory, "-type", "f"] + filters
        else:
            # grep
            if self.sr['match-mode'] == const.mm_regex_only_match or self.sr['match-mode'] == const.mm_regex_param_controllable:
                match = self.sr['match']
            elif self.sr['match-mode'] == const.mm_function_param_controllable:
                # param controllable
                if '|' in self.sr['match']:
                    match = const.fpc_multi.replace('[f]', self.sr['match'])
                else:
                    match = const.fpc_single.replace('[f]', self.sr['match'])
            else:
                logger.warning('Exception match mode: {m}'.format(m=self.sr['match-mode']))

            filters = []
            for e in self.sr['extensions']:
                filters.append('--include=*' + e)

            # explode dirs
            explode_dirs = ['.svn', '.cvs', '.hg', '.git', '.bzr']
            for explode_dir in explode_dirs:
                filters.append('--exclude-dir={0}'.format(explode_dir))

            # -s Suppress error messages / -n Show Line number / -r Recursive / -P Perl regular expression
            param = [self.grep, "-s", "-n", "-r", "-P"] + filters + [match, self.target_directory]
        try:
            p = subprocess.Popen(param, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result, error = p.communicate()     #communicate(stdin、timeout) return stdout and std err
        except Exception as e:
            traceback.print_exc()
            logger.critical('match exception ({e})'.format(e=e.message))
            return None
        try:
            result = result.decode('utf-8')
            error = error.decode('utf-8')
        except AttributeError as e:
            pass
        if len(error) is not 0:
            logger.critical('[CVI-{cvi}] [ORIGIN] [ERROR] {err}'.format(cvi=self.sr['id'], err=error.strip()))
        return result

    def process(self):
        """
        Process Single Rule
        :return: SRV(Single Rule Vulnerabilities)
        """
        origin_results = self.origin_results()    #shell匹配cvi文件中正则表达式结果
        # exists result
        if origin_results == '' or origin_results is None:
            logger.debug('[CVI-{cvi}] [ORIGIN] NOT FOUND!'.format(cvi=self.sr['id']))
            return None

        origin_vulnerabilities = origin_results.strip().split("\n")
        for index, origin_vulnerability in enumerate(origin_vulnerabilities):
            origin_vulnerability = origin_vulnerability.strip()
            logger.debug('[CVI-{cvi}] [ORIGIN] {line}'.format(cvi=self.sr['id'], line=origin_vulnerability))
            if origin_vulnerability == '':
                logger.debug(' > continue...')
                continue
            vulnerability = self.parse_match(origin_vulnerability)
            if vulnerability is None:
                logger.debug('Not vulnerability, continue...')
                continue
            is_test = False
            try:
                is_vulnerability, reason = Core(self.target_directory, vulnerability, self.sr, 'project name', ['whitelist1', 'whitelist2'], test=is_test, index=index).scan()
                if is_vulnerability:
                    logger.debug('[CVI-{cvi}] [RET] Found {code}'.format(cvi=self.sr['id'], code=reason))
                    vulnerability.analysis = reason
                    self.rule_vulnerabilities.append(vulnerability)
                else:
                    logger.debug('Not vulnerability: {code}'.format(code=reason))
            except Exception:
                raise
        logger.debug('[CVI-{cvi}] {vn} Vulnerabilities: {count}'.format(cvi=self.sr['id'], vn=self.sr['name'], count=len(self.rule_vulnerabilities)))
        return self.rule_vulnerabilities

    @property
    def my_process(self):
        """
        Process Single Rule
        :return: SRV(Single Rule Vulnerabilities)
        """
        # 返回vulnerabilities结果列表
        process_result = []

        # shell匹配cvi文件中正则表达式结果
        origin_results = self.origin_results()

        # exists result
        if origin_results == '' or origin_results is None:
            logger.debug('[CVI-{cvi}] [ORIGIN] NOT FOUND!'.format(cvi=self.sr['id']))
            return None
        origin_vulnerabilities = origin_results.strip().split("\n")

        # 判断文件f的line_num行上面是否有写文档注释
        def read_before_line(f, fun_line_num):
            line_num = int(fun_line_num)
            while line_num > 1:
                line_num -= 1
                line_content = f.readlines()[line_num].strip()
                if line_content == '':
                    continue
                elif line_content.endswith('*/'):
                    return True
                else:
                    # 没有文档注释
                    return False
            return False

        inc_files = []  # 包含ls打印日志规则的文件
        for index, origin_vulnerability in enumerate(origin_vulnerabilities):
            origin_vulnerability = origin_vulnerability.strip()
            logger.debug('[CVI-{cvi}] [ORIGIN] {line}'.format(cvi=self.sr['id'], line=origin_vulnerability))
            if origin_vulnerability == '':
                logger.debug(' > continue...')
                continue
            vulnerability = self.parse_match(origin_vulnerability)
            inc_files.append(vulnerability.file_path)

            # cvi rules start with '110' is function annotation
            if vulnerability.id[:3] == '110' and vulnerability.file_path.endswith(".cpp"):
                vir_f = open(vulnerability.file_path, 'r')
                have_annotation = read_before_line(vir_f, vulnerability.line_number)
                if not have_annotation:
                    ano_dict = {"rule_id": vulnerability.id, "file_path": vulnerability.file_path,
                                "line_num": vulnerability.line_number, "rule_name": vulnerability.rule_name,
                                "solution": vulnerability.solution, "commit_author": vulnerability.commit_author,
                                "commit_time": vulnerability.commit_time, "level": vulnerability.level}
                    process_result.append(ano_dict)

        # 递归将不符合规则的文件添加到返回list中
        def append_process_result(directory):
            files = os.listdir(directory)
            for f in files:
                f = os.path.join(directory, f)
                if os.path.isfile(f):
                    if f in inc_files:
                        continue
                    if f.lower()[-3:] == ".ls":
                        log_dict = {"rule_id": vulnerability.id, "file_path": vulnerability.file_path,
                                    "level": vulnerability.level,
                                    "rule_name": vulnerability.rule_name, "solution": vulnerability.solution,
                                    "commit_author": vulnerability.commit_author, "commit_time": vulnerability.commit_time}
                        process_result.append(log_dict)
                        continue
                if os.path.isdir(f):
                    append_process_result(f)

        # 以CVI-100开头的规则为LS算法打印规则
        if vulnerability.id[:3] == '100':
            append_process_result(self.target_directory)
        return process_result

    def parse_match(self, single_match):
        mr = VulnerabilityResult()
        # grep result
        if ':' in single_match:
            #
            # Rules
            #
            # v.php:2:$password = "C787AFE9D9E86A6A6C78ACE99CA778EE";
            # v.php:2:$password 2017:01:01
            # v.exe Binary file
            try:
                mr.line_number, mr.code_content = re.findall(r':(\d+):(.*)', single_match)[0]
                mr.file_path = single_match.split(u':{n}:'.format(n=mr.line_number))[0]
            except Exception:
                logger.warning('match line parse exception')
                mr.file_path = ''
                mr.code_content = ''
                mr.line_number = 0
        else:
            if 'Binary file' in single_match:
                return None
            else:
                # find result
                mr.file_path = single_match
                mr.code_content = ''
                mr.line_number = 0
        # vulnerability information
        mr.rule_name = self.sr['name']
        mr.id = self.sr['id']
        mr.language = self.sr['language']
        mr.solution = self.sr['solution']
        mr.level = self.sr['level']

        # committer
        from .pickup import Git
        c_ret, c_author, c_time = Git.committer(self.target_directory, mr.file_path, mr.line_number)
        if c_ret:
            mr.commit_author = c_author
            mr.commit_time = c_time
        return mr


class Core(object):
    def __init__(self, target_directory, vulnerability_result, single_rule, project_name, white_list, test=False, index=None):
        """
        Initialize
        :param: target_directory:
        :param: vulnerability_result:
        :param single_rule: rule info
        :param project_name: project name
        :param white_list: white-list
        :param test: is test
        :param index: vulnerability index
        """
        self.data = []

        self.target_directory = target_directory

        self.file_path = vulnerability_result.file_path.strip()
        self.line_number = vulnerability_result.line_number
        self.code_content = vulnerability_result.code_content.strip()

        self.rule_match = single_rule['match']
        self.rule_match_mode = single_rule['match-mode']
        self.rule_match2 = single_rule['match2']
        self.rule_match2_block = single_rule['match2-block']
        self.rule_repair = single_rule['repair']
        self.repair_block = single_rule['repair-block']
        self.cvi = single_rule['id']

        self.project_name = project_name
        self.white_list = white_list
        self.test = test

        self.status = None
        self.status_init = 0
        self.status_fixed = 2

        # const.py
        self.repair_code = None
        self.repair_code_init = 0
        self.repair_code_fixed = 1
        self.repair_code_not_exist_file = 4000
        self.repair_code_special_file = 4001
        self.repair_code_whitelist = 4002
        self.repair_code_test_file = 4003
        self.repair_code_annotation = 4004
        self.repair_code_modify = 4005
        self.repair_code_empty_code = 4006
        self.repair_code_const_file = 4007
        self.repair_code_third_party = 4008

        self.method = None
        logger.debug("""[CVI-{cvi}] [VERIFY-VULNERABILITY] ({index})
        > File: `{file}:{line}`
        > Code: `{code}`
        > Match2: `{m2}({m2b})`
        > Repair: `{r}({rb})`""".format(
            cvi=single_rule['id'],
            index=index,
            file=self.file_path.replace(self.target_directory, ''),
            line=self.line_number,
            code=self.code_content,
            m2=self.rule_match2,
            m2b=self.rule_match2_block,
            r=self.rule_repair,
            rb=self.repair_block))

    def is_white_list(self):
        """
        Is white-list file
        :return: boolean
        """
        return self.file_path.split(self.target_directory, 1)[1] in self.white_list

    def is_special_file(self):
        """
        Is special file
        :method: According to the file name to determine whether the special file
        :return: boolean
        """
        special_paths = [
            '/node_modules/',
            '/bower_components/',
            '.min.js',
        ]
        for path in special_paths:
            if path in self.file_path:
                return True
        return False

    def is_test_file(self):
        """
        Is test case file
        :method: file name
        :return: boolean
        """
        test_paths = [
            '/test/',
            '/tests/',
            '/unitTests/'
        ]
        for path in test_paths:
            if path in self.file_path:
                return True
        return False

    def is_match_only_rule(self):
        """
        Whether only match the rules, do not parameter controllable processing
        :method: It is determined by judging whether the left and right sides of the regex_location are brackets
        :return: boolean
        """
        if self.rule_match_mode == 'regex-only-match':
            return True
        else:
            return False

    def is_annotation(self):
        """
        Is annotation
        :method: Judgment by matching comment symbols (skipped when self.is_match_only_rule condition is met)
               - PHP:  `#` `//` `\*` `*`
                    //asdfasdf
                    \*asdfasdf
                    #asdfasdf
                    *asdfasdf
               - Java:
        :return: boolean
        """
        match_result = re.findall(r"^(#|\\\*|\/\/)+", self.code_content)
        # Skip detection only on match
        if self.is_match_only_rule():
            return False
        else:
            return len(match_result) > 0

    def is_can_parse(self):
        """
        Whether to parse the parameter is controllable operation
        :return:
        """
        for language in CAST.languages:
            if self.file_path[-len(language):].lower() == language:
                return True
        return False

    def scan(self):
        """
        Scan vulnerabilities
        :flow:
        - whitelist file
        - special file
        - test file
        - annotation
        - rule
        :return: is_vulnerability, code
        """
        self.method = 0
        self.code_content = self.code_content
        if len(self.code_content) > 512:
            self.code_content = self.code_content[:500]
        self.status = self.status_init
        self.repair_code = self.repair_code_init
        if self.is_white_list():
            logger.debug("[RET] Whitelist")
            return False, 'Whitelists(白名单)'

        if self.is_special_file():
            logger.debug("[RET] Special File")
            return False, 'Special File(特殊文件)'

        if self.is_test_file():
            logger.debug("[CORE] Test File")

        if self.is_annotation():
            logger.debug("[RET] Annotation")
            return False, 'Annotation(注释)'

        if self.rule_match_mode == const.mm_find_extension:
            #
            # Find-Extension
            # Match(extension) -> Done
            #
            return True, 'FIND-EXTENSION(后缀查找)'
        elif self.rule_match_mode == const.mm_regex_only_match:
            #
            # Regex-Only-Match
            # Match(regex) -> Repair -> Done
            #
            logger.debug("[CVI-{cvi}] [ONLY-MATCH]".format(cvi=self.cvi))
            if self.rule_match2 is not None:
                ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number, self.code_content)
                is_match, data = ast.match(self.rule_match2, self.rule_match2_block)
                if is_match:
                    logger.debug('[CVI-{cvi}] [MATCH2] True'.format(cvi=self.cvi))
                    return True, 'REGEX-ONLY-MATCH+MATCH2(正则仅匹配+二次匹配)'
                else:
                    logger.debug('[CVI-{cvi}] [MATCH2] False'.format(cvi=self.cvi))
                    return False, 'REGEX-ONLY-MATCH+Not matched2(未匹配到二次规则)'

            if self.rule_repair is not None:
                logger.debug('[VERIFY-REPAIR]')
                ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number, self.code_content)
                is_repair, data = ast.match(self.rule_repair, self.repair_block)
                if is_repair:
                    # fixed
                    logger.debug('[CVI-{cvi}] [RET] Vulnerability Fixed'.format(cvi=self.cvi))
                    return False, 'REGEX-ONLY-MATCH+Vulnerability-Fixed(漏洞已修复)'
                else:
                    logger.debug('[CVI-{cvi}] [REPAIR] [RET] Not fixed'.format(cvi=self.cvi))
                    return True, 'REGEX-ONLY-MATCH+NOT FIX(未修复)'
            else:
                return True, 'REGEX-ONLY-MATCH(正则仅匹配+无修复规则)'
        else:
            #
            # Function-Param-Controllable
            # Match(function) -> Match2(regex) -> Param-Controllable -> Repair -> Done
            #

            #
            # Regex-Param-Controllable
            # Match(regex) -> Match2(regex) -> Param-Controllable -> Repair -> Done
            #
            logger.debug('[CVI-{cvi}] match-mode {mm}'.format(cvi=self.cvi, mm=self.rule_match_mode))
            if self.file_path[-3:].lower() == 'php':
                try:
                    ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number, self.code_content)
                    rule_repair = []
                    if self.rule_match_mode == const.mm_function_param_controllable:
                        rule_match = self.rule_match.strip('()').split('|')  # 漏洞规则整理为列表
                        if self.rule_repair is not None:
                            rule_repair = self.rule_repair.strip('()').split('|')  # 修复规则整理为列表
                        logger.debug('[RULE_MATCH] {r}'.format(r=rule_match))
                        try:
                            with open(self.file_path, 'r') as fi:
                                code_contents = fi.read()
                                result = scan_parser(code_contents, rule_match, self.line_number, rule_repair)
                                logger.debug('[AST] [RET] {c}'.format(c=result))
                                if len(result) > 0:
                                    if result[0]['code'] == 1:  # 函数参数可控
                                        return True, 'FUNCTION-PARAM-CONTROLLABLE(函数入参可控)'

                                    if result[0]['code'] == 2:  # 函数为敏感函数
                                        return False, 'FUNCTION-PARAM-CONTROLLABLE(函数入参来自所在函数)'

                                    if result[0]['code'] == 0:  # 漏洞修复
                                        return False, 'FUNCTION-PARAM-CONTROLLABLE+Vulnerability-Fixed(漏洞已修复)'

                                    if result[0]['code'] == -1:  # 函数参数不可控
                                        return False, 'FUNCTION-PARAM-CONTROLLABLE(入参不可控)'

                                    logger.debug('[AST] [CODE] {code}'.format(code=result[0]['code']))
                                else:
                                    logger.debug('[AST] Parser failed / vulnerability parameter is not controllable {r}'.format(r=result))
                        except Exception as e:
                            logger.warning(traceback.format_exc())
                            raise

                    # Match2
                    if self.rule_match2 is not None:
                        is_match, data = ast.match(self.rule_match2, self.rule_match2_block)
                        if is_match:
                            logger.debug('[CVI-{cvi}] [MATCH2] True'.format(cvi=self.cvi))
                            return True, 'FPC+MATCH2(函数入参可控+二次匹配)'
                        else:
                            logger.debug('[CVI-{cvi}] [MATCH2] False'.format(cvi=self.cvi))
                            return False, 'FPC+NOT-MATCH2(函数入参可控+二次未匹配)'

                    # Param-Controllable
                    param_is_controllable, data = ast.is_controllable_param()
                    if param_is_controllable:
                        logger.debug('[CVI-{cvi}] [PARAM-CONTROLLABLE] Param is controllable'.format(cvi=self.cvi))
                        # Repair
                        is_repair, data = ast.match(self.rule_repair, self.repair_block)
                        if is_repair:
                            # fixed
                            logger.debug('[CVI-{cvi}] [REPAIR] Vulnerability Fixed'.format(cvi=self.cvi))
                            return False, 'Vulnerability-Fixed(漏洞已修复)'
                        else:
                            logger.debug('[CVI-{cvi}] [REPAIR] [RET] Not fixed'.format(cvi=self.cvi))
                            return True, 'MATCH+REPAIR(匹配+未修复)'
                    else:
                        logger.debug('[CVI-{cvi}] [PARAM-CONTROLLABLE] Param Not Controllable'.format(cvi=self.cvi))
                        return False, 'Param-Not-Controllable(参数不可控)'
                except Exception as e:
                    logger.debug(traceback.format_exc())
                    return False, 'Exception'
