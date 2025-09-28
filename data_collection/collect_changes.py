from pathlib import Path
import sys
import pickle
from urllib.parse import urlparse
from xxlimited import Str

from git import repo
sys.path.append(Path(__file__).parent.parent.as_posix())
from pydriller.domain.commit import Method, Class, ModifiedFile, Variable

from data_collection.github_utils import find_potential_commits_from_github
import random
from data_collection.constant import REPO_DIR,DATA_DIR,CODE_CHANGES_DIR,SCOPE_CACHE_DIR_DATE,CODE_CHANGES_DIR_DATE, DIFF_CACHE_DIR, DIFF_CACHE_DIR_DATE,AST_TYPE_CACHE_DIR_DATE,COMMITS_DIR_DATE,SCOPE_CVE_CACHE_DIR_DATE,CVE2ADVISORY_VF_FILE_DATE, SUFFIX
import json
random.seed(42)
import datetime
from tqdm import tqdm
import uuid
import os
from joblib import Parallel, delayed
import multiprocessing
from data_collection.get_compatable_python_version import  filter_versions
from collections import defaultdict,Counter
from typing import List, Dict
from data_collection.vul_analyze import  adjust_message, filter_files, read_cve2advisory, read_fixing_commits,read_possible_urls,get_pkg2url,get_modified_files,read_commit2methods
from data_collection.my_utils import get_repo_name,normalize_package_name
from data_collection.collect_commits import get_extracted_urls_for_repo,get_all_unique_affected_projects,is_source_code_modified
# from collect_snyk_urls import get_snyk_urls_for_cve
# 在文件顶部添加导入
from data_collection.logger import logger
from pydriller import Repository, Git
# from patch_analyze import extract_patch_diff
from joblib import Parallel, delayed
import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Query
import re

from data_collection.dependency_track import ScopeAwareDependencyTracker
PY_LANGUAGE = Language(tspython.language())

class ScopeAnalyzer():
    """AST visitor for analyzing Python methods"""
    
    def __init__(self, source_code, commit_hash,file_path=None,change_before=False):
        self.parser = Parser(PY_LANGUAGE)


        self.functions = []
        self.global_functions=[]
        self.class_functions = {}

        self.classes = []

        self.current_class = None
        self.source_code = source_code
        self._filename = file_path
        self.before = change_before
        self.commit_hash=commit_hash

        tree = self.parser.parse(bytes(self.source_code, "utf8"))
        self.root_node = tree.root_node

    def get_ast_type_for_lines(self, lines):
        result = {'module': [], 'class': [], 'function': []}
        
        # 2. 处理deleted和added lines
        two_scope_lines = {'module':lines['module'], 'class':lines['class']}
        for scope in ['module', 'class']:
            for line_no, content in two_scope_lines[scope]:
                ast_info = self._analyze_line_ast_type(line_no, content, scope)
                result[scope].append({
                    'line_no': line_no,
                    'content': content,
                    'ast_type': ast_info
                })
    
        return result
    
    def _analyze_line_ast_type(self,line_no, content, known_scope):
        """分析特定行的AST类型"""
        
        # 找到包含该行的最具体AST节点
        target_node = self._get_most_specific_node_at_line(line_no,content)
        
        if not target_node:
            return {'type': 'unknown', 'category': 'unknown'}
        
        # 根据AST node type和scope进行分类
        if target_node == 'ERROR':
            content_stripped = content.strip() if content else ""
            if content_stripped.startswith('class '):
                ast_type = 'class_definition'
            elif content_stripped.startswith(('def ')):  # @decorator或def
                ast_type = 'function_definition'
            elif content_stripped.startswith(('import ', 'from ')):
                ast_type = 'import_statement'
            elif content_stripped.startswith(('if ', 'else', 'elif ')):
                ast_type = 'if_statement'
            elif content_stripped.startswith(('try')):
                ast_type = 'try_statement'
            elif content_stripped.startswith(('return ')):
                ast_type = 'return_statement'
        else:
            ast_type = target_node.type
        category = self._categorize_ast_type(ast_type, known_scope, content)
        
        return {
            'type': ast_type,
            'category': category,
            'scope': known_scope
        }
    def _get_most_specific_node_at_line(self, line_no, content):
        """获取指定行号最相关的AST节点"""
        target_line = line_no - 1
        
        def find_relevant_nodes(node, candidates=None):
            if candidates is None:
                candidates = []
                
            # 检查节点是否在目标行
            if node.start_point[0] <= target_line <= node.end_point[0]:
                candidates.append(node)
                
                # 递归检查子节点
                for child in node.children:
                    find_relevant_nodes(child, candidates)
            
            return candidates
        
        # 获取所有包含目标行的节点
        candidate_nodes = find_relevant_nodes(self.root_node)
        logger.debug(f"candidate_nodes:{[node.type for node in candidate_nodes]}")
        if not candidate_nodes:
            return None
        # 过滤出有意义的节点类型，排除标点符号和wrapper节点
        meaningful_nodes = []
        for node in candidate_nodes:
            if self._is_meaningful_node_type(node.type):
                meaningful_nodes.append(node)
        logger.info(f"{line_no}, {content}")
        logger.debug(f"meaningful_nodes:{[node.type for node in meaningful_nodes]} for {line_no} ... {len([node.type for node in meaningful_nodes])}")
        
        # 如果没有有意义的节点，回退到所有候选节点
        
        if len([node.type for node in meaningful_nodes])==0:
            if 'ERROR' in [node.type for node in candidate_nodes]:
                logger.warning(f"ERROR")
                return 'ERROR'
            meaningful_nodes = candidate_nodes
        
        # 根据内容和节点类型选择最相关的节点
        ret_node = self._select_most_relevant_node(meaningful_nodes,content)
        
        logger.debug(f"ret_node:{ret_node.type}")
        return ret_node


    def _is_meaningful_node_type(self,node_type):
        """判断是否为有意义的AST节点类型，排除标点符号"""
        # 排除的token类型
        punctuation_types = {
            '=', '(', ')', '[', ']', '{', '}', ',', '.', ':', ';',
            'string_start', 'string_end', 'comment', 'call'
        }
        
        if node_type in punctuation_types:
            return False
        
        # 保留的有意义节点类型
        meaningful_types = {
            # 你现有的类型
            'assignment', 'augmented_assignment', 'expression_statement',
            'call', 'function_definition', 'class_definition', 
            'import_statement', 'import_from_statement',
            'future_import_statement',
            
            # 添加控制流类型
            'if_statement', 'elif_clause', 'else_clause',
            'for_statement', 'while_statement',
            'try_statement', 'except_clause', 'finally_clause',
            'with_statement', 'break_statement', 'continue_statement',
            
            # 其他可能重要的
            'return_statement', 'raise_statement', 'assert_statement'
        }
        
        return node_type in meaningful_types

    def _select_most_relevant_node(self,nodes, content):
        """从有意义的节点中选择最相关的节点"""
        if not nodes:
            return None
        
        # 首先基于内容进行启发式匹配
        content_stripped = content.strip() if content else ""
        
        # 精确匹配：根据行内容确定最可能的节点类型
        if content_stripped.startswith('class '):
            for node in reversed(nodes):
                if node.type == 'class_definition':
                    return node
        
        elif content_stripped.startswith(('def ')):  # @decorator或def
            for node in reversed(nodes):
                if node.type == 'function_definition':
                    return node
        
            
            
        elif content_stripped.startswith(('@')):  # @decorator或def
            for node in reversed(nodes):
                if node.type == 'decorator_definition':
                    return node
        
        elif content_stripped.startswith(('import ', 'from ')):
            for node in reversed(nodes):
                if node.type in ['import_statement', 'import_from_statement']:
                    return node
        
        elif '=' in content_stripped and not content_stripped.startswith('#'):
            for node in reversed(nodes):
                if node.type in ['assignment', 'augmented_assignment']:
                    return node
        
        elif content_stripped.startswith('return '):
            for node in reversed(nodes):
                if node.type == 'return_statement':
                    return node
        
        # 如果没有精确匹配，使用改进的优先级策略
        # 选择最具体且有意义的节点（通常是最深层的statement级别节点）
        statement_level_nodes = [n for n in nodes if n.type in [
            'assignment', 'augmented_assignment', 'class_definition', 'decorated_definition',
            'function_definition', 'import_statement', 'import_from_statement',
            'return_statement', 'expression_statement'
        ]]
        
        if statement_level_nodes:
            return statement_level_nodes[-1]  # 最深层的statement节点

        # 最后的fallback
        return nodes[-1]
    def _refine_node_selection(self, node, content, all_candidates):
        """根据行内容细化节点选择"""
        # 如果是赋值语句，确保返回assignment节点而不是expression
        if '=' in content and not content.strip().startswith('#'):
            for candidate in reversed(all_candidates):
                if candidate.type in ['assignment', 'augmented_assignment']:
                    return candidate
        
        # 如果是import语句
        if content.strip().startswith(('import ', 'from ')):
            for candidate in reversed(all_candidates):
                if 'import' in candidate.type:
                    return candidate
        
        return node
    def _categorize_ast_type(self, ast_type, scope, content):
        """将AST类型分类为vulnerability analysis相关的categories"""
        
        # Module scope的典型类型
        if scope == 'module':
            if ast_type in ['assignment', 'augmented_assignment']:
                return 'global_variable_assignment'
            elif ast_type in ['import_statement', 'import_from_statement', 'future_import_statement']:
                return 'import_statement'
            elif ast_type == 'function_definition':
                return 'module_function_definition'
            elif ast_type == 'class_definition':
                return 'module_class_definition'
            elif ast_type == 'decorated_definition':
                return 'module_decorated_definition'
            elif ast_type in ['if_statement', 'for_statement','elif_clause', 'while_statement','else_clause']:
                return 'module_control_flow'
            elif ast_type == 'with_statement':
                return 'module_context_manager'
            elif ast_type in ['raise_statement', 'assert_statement','try_statement','except_clause','finally_clause']:
                return 'module_exception_assertion'
            elif ast_type == 'expression_statement':
                return 'module_expression'
        
        # Class scope的典型类型
        elif scope == 'class':
            if ast_type in ['assignment', 'augmented_assignment']:
                return 'class_attribute_assignment'
            elif ast_type in ['import_statement', 'import_from_statement', 'future_import_statement']:
                return 'class_import_statement'
            elif ast_type == 'function_definition':
                # 检查是否为special methods
                if content and self._is_special_method(content):
                    return 'special_method_definition'
                return 'method_definition'
            elif ast_type == 'class_definition':
                return 'class_definition'
            elif ast_type == 'decorated_definition':
                # 检查装饰器定义中是否包含special method
                if content and self._is_special_method(content):
                    return 'decorated_special_method_definition'
                return 'decorated_method_definition'
            elif ast_type in ['if_statement', 'for_statement', 'elif_clause','while_statement', 'else_clause']:
                return 'class_control_flow'
            elif ast_type == 'with_statement':
                return 'class_context_manager'
            elif ast_type in ['raise_statement', 'assert_statement','try_statement','except_clause','finally_clause']:
                return 'class_exception_assertion'
            elif ast_type == 'expression_statement':
                return 'class_expression'
        
        # Function scope的典型类型
        elif scope == 'function':
            if ast_type in ['assignment', 'augmented_assignment']:
                return 'local_variable_assignment'
            elif ast_type == 'call':
                return 'function_call'
            elif ast_type == 'return_statement':
                return 'return_statement'
            elif ast_type == 'function_definition':
                # 嵌套函数也可能是special method (虽然罕见)
                if content and self._is_special_method(content):
                    return 'nested_special_method_definition'
                return 'nested_function_definition'
            elif ast_type == 'class_definition':
                return 'local_class_definition'
            elif ast_type == 'decorated_definition':
                if content and self._is_special_method(content):
                    return 'local_decorated_special_method'
                return 'local_decorated_definition'
            elif ast_type in ['if_statement', 'for_statement', 'while_statement', 'try_statement']:
                return 'function_control_flow'
            elif ast_type == 'with_statement':
                return 'function_context_manager'
            elif ast_type in ['raise_statement', 'assert_statement']:
                return 'function_exception_assertion'
        
        return 'other'

    def _is_special_method(self, content):
        """检测是否为Python special method"""
        if not content:
            return False
        
        # 常见的special methods
        special_method_patterns = [
            '__init__', '__str__', '__repr__', '__call__', '__len__',
            '__getitem__', '__setitem__', '__delitem__', '__contains__',
            '__add__', '__sub__', '__mul__', '__div__', '__truediv__',
            '__eq__', '__ne__', '__lt__', '__le__', '__gt__', '__ge__',
            '__enter__', '__exit__', '__new__', '__del__', '__hash__'
        ]
        
        return any(pattern in content for pattern in special_method_patterns)



def format_changed_funcs(code_changes):
    #得到和jarvis输出格式的func
    funcs = []
    for file, sig2method in code_changes.items():
        file_suffix = Path(file).suffix
        for sig, method in sig2method.items():
            # func_id = file.replace(file_suffix,'').replace('/','.')+f".{method['name']}.({method['start_line']},{method['end_line']})"
            funcs.append((method['name'], method['full_name']))
    return funcs

def extract_vulnerable_funcs_for_func_scope(file:ModifiedFile):
    ...
    vfs_dict = {
            'old_method_direct_modified_by_deleted_lines':set(),
            'old_method_only_modified_by_added_lines':set(),
            'special_method_only_existed_in_new_file':set(),
            'added_methods_replace_same_name_old_methods':set(),
        }
    
    logger.debug(f"changed line, added:{file.cleaned_added_lines}, deleted:{file.cleaned_deleted_lines}")
    # get func, class, and vars
    # file.get_class_and_function_and_var_list()
    old_methods_changed:List[Method] = file.methods_changed_old
    new_methods_changed:List[Method] = file.methods_changed_new
    old_methods:List[Method] = file.methods_before
    new_methods:List[Method] = file.methods
    # 1. function-scope 
    # 1.1 functions modified by deleted lines (may modified by added lines  simultaneously)
    old_methods_changed_long_names:List[str] = {
        y.long_name
        for y in old_methods_changed
    }
    # vul_dict['old_method_direct_modified_by_deleted_lines'] = {old_method.long_name for old_method in old_methods_changed}
    vfs_dict['old_method_direct_modified_by_deleted_lines'] = {old_method for old_method in old_methods_changed}
    vulnerable_methods= set(old_methods_changed)

    # 1.2 functions explicitly declared in old file, ONLY modified by added lines.
    new_changed_method_long_names:List[Str] = {
        y.long_name
        for y in new_methods_changed
    }
    for old_method in old_methods:
        # if only modified by by added lines.
        if old_method.long_name in new_changed_method_long_names and old_method.long_name not in old_methods_changed_long_names:
            vulnerable_methods.add(old_method)
            # vulnerable_methods_long_names.add(method.long_name)
            if old_method.long_name == 'gradio.routes.App.create_app':
                print(f"new_changed_method_long_names:{new_changed_method_long_names}")
                assert False
            vfs_dict['old_method_only_modified_by_added_lines'].add(old_method)
    
    # 1.3 functions implicitly declared in old file, such as special methods (which ONLY explicitly be declared only in new file), for a class existed in old file.
    # classes existed in old file.
    classes_before_long_names:List[str] = [cls.long_name for cls in file.classes_before]
    logger.debug(f"classes_before:{classes_before_long_names}")

    # methods changed by added lines->modified special methods.
    for method in new_methods_changed:
        if not file._is_special_method(method):
            continue
        
        # ONLY focus the classes existed in old file
        first_parent_class = method.first_parent_class
        if not first_parent_class or first_parent_class not in classes_before_long_names:
            continue
        
        # vulnerable_methods_long_names.add(method.long_name)
        vulnerable_methods.add(method)
        vfs_dict['special_method_only_existed_in_new_file'].add(method)

    # 1.4 new added functions replace the functions existed in old file with same name, and other functions existed in old file calls added functions
    old_method_long_names = {
        y.long_name
        for y in old_methods
    }
    # get the added functions
    added_methods = []
    for method_long_name in new_changed_method_long_names:
        if method_long_name not in old_method_long_names:
            added_methods.append(method_long_name)
    logger.info(f"added_methods:{added_methods}")
    # search the caller in old_file for added_methods based on the CG for new_file
    for new_method in new_methods:
        caller = new_method.long_name
        # check if method with the same long name as new_method exists in old_file
        logger.info(f"caller:{caller}, {caller not in old_method_long_names or caller in added_methods}")
        if caller not in old_method_long_names or caller in added_methods:
            continue
        callees = file.cg.get(caller,[])
        logger.info(f"callees:{callees}")
        inter = set(callees)&set(added_methods)
        if inter:
            # vulnerable_methods_long_names.add(caller)
            # vulnerable_methods.add(method)
            # get_old_method_obj:
            for old_method in old_methods:
                if old_method.long_name == caller:
                    old_method_obj = old_method
                    break
            if old_method in vulnerable_methods:
                # has been capture by previous steps:
                continue
            # print(caller)
            # print(file.cg)
            vfs_dict['added_methods_replace_same_name_old_methods'].add(old_method_obj)
    return vfs_dict
    

def get_vulnerable_funcs_for_file(file:ModifiedFile,scope_lines):
    vfs_dict = {
            'old_method_direct_modified_by_deleted_lines':set(),
            'old_method_only_modified_by_added_lines':set(),
            'special_method_only_existed_in_new_file':set(),
            'added_methods_replace_same_name_old_methods':set(),
            'module_vars_impact_functions':set(),
            'class_vars_impact_functions':set(),
            'module_called_functions':set(),
        }
   
    # !1.function-scope
    file.get_code_changes_scopes()
    vfs_dict_func:Dict[List[Method]]= extract_vulnerable_funcs_for_func_scope(file=file)
    vfs_dict.update(vfs_dict_func)
    for cate, methods in vfs_dict_func.items():
        print('='*50)
        print(f"Category: {cate}")
        print(f"Methods: {[method.long_name for method in methods]}")
        print('='*50)
        if cate in ['special_method_only_existed_in_new_file'] and len(methods):
            # assert False
            ...
        if cate in ['added_methods_replace_same_name_old_methods'] and len(methods):
            # assert False
            ...
    # !1.1 filter_methods, since functions has dependency with vars may keep the same body.
    vulnerable_methods = set()
    for cate, methods in vfs_dict.items():
        vulnerable_methods.update(methods)
    # 基于body判断是否真正有修改，减少FP (refactoring, docs, multi-line comments)
    filtered_vulnerable_methods = filter_vulnerable_methods(file,vulnerable_methods)
    filtered_vulnerable_methods_long_names = [method.long_name for method in filtered_vulnerable_methods]
    # !2.class-scope, module-scope, e.g., CVE-2024-27351
    changed_module_vars = file.changed_module_vars
    changed_class_vars = file.changed_class_vars
    logger.debug(f"changed_module_vars: {[var.long_name for var in changed_module_vars]}")
    logger.debug(f"changed_class_vars: {[var.long_name for var in changed_class_vars]}")
    # 2.1 find the vars existed in the old file

    if len(changed_module_vars) or len(changed_class_vars):
        # 1. for each function, get use-def
        var_tracker = ScopeAwareDependencyTracker(file=file)
        module_impact_functions,class_impact_functions = var_tracker.analyze_variable_impact_functions()
        if len(module_impact_functions):
            logger.info(f"module_impact_functions: {[func.long_name for func in module_impact_functions]}")
            vfs_dict['module_vars_impact_functions'] = module_impact_functions
            filtered_vulnerable_methods.extend(module_impact_functions)
            filtered_vulnerable_methods_long_names.extend([func.long_name for func in module_impact_functions])
        if len(class_impact_functions):
            logger.info(f"class_impact_functions: {[func.long_name for func in class_impact_functions]}")
            vfs_dict['class_vars_impact_functions'] = class_impact_functions
            filtered_vulnerable_methods.extend(class_impact_functions)
            filtered_vulnerable_methods_long_names.extend([func.long_name for func in class_impact_functions])
    
    filtered_vulnerable_methods = list(set(filtered_vulnerable_methods))
    filtered_vulnerable_methods_long_names = list(set(filtered_vulnerable_methods_long_names))
    if len(filtered_vulnerable_methods)==0 and len(vulnerable_methods):
        # only added functions
        # print(vul_dict)
        # print(file.cleaned_added_lines, file.cleaned_deleted_lines)
        # assert False
        ...
    # ! 4. methods called at module-level
    # for long_name in self._function_list_before_called_top_level:
    #         if long_name in vulnerable_methods_long_names:
    #             main_func = self._generate_module_main()
    #             vulnerable_methods.add(main_func)
    #             vulnerable_methods_long_names.add(main_func.long_name)
    #             vul_dict['top_level_vulnerable_call'].add(method.long_name)
    print(file.change_type)
    module_level_callee = file._function_list_before_called_top_level
    
    for callee in module_level_callee:
        if callee in filtered_vulnerable_methods_long_names:
            main_func = file._generate_module_main()
            filtered_vulnerable_methods.append(main_func)
            filtered_vulnerable_methods_long_names.append(main_func.long_name)
            vfs_dict['module_called_functions'].add(callee)
    if len(module_level_callee) and len(vfs_dict['module_called_functions']):
        logger.debug(f"module_level_callee: {module_level_callee}")
        logger.debug(f"vul_dict['module_called_functions']:{vfs_dict['module_called_functions']}")
        # assert False
    return filtered_vulnerable_methods,vulnerable_methods,vfs_dict


class FunctionBodyComparator:
    def __init__(self):
        self.parser = Parser(PY_LANGUAGE)
    
    def normalize_function_body(self, code: str) -> str:
        """
        Normalize function code by removing comments, empty lines, and standardizing whitespace.
        """
        try:
            # Parse the code with tree-sitter
            tree = self.parser.parse(bytes(code, "utf8"))
            root_node = tree.root_node
            
            # Find the function body
            function_node = self._find_function_node(root_node)
            if not function_node:
                # If no function found, treat entire code as body
                return self._normalize_node(root_node, code)
            
            # Get function body (skip def line, parameters, etc.)
            body_node = function_node.child_by_field_name('body')
            if not body_node:
                return ""
            
            return self._normalize_node(body_node, code)
            
        except Exception as e:
            print(f"Error parsing code with tree-sitter: {e}")
            # Fallback to regex-based normalization
            return self._fallback_normalize(code)
            
    def _find_function_node(self, node):
        """Find the first function definition node."""
        if node.type == 'function_definition':
            return node
        
        for child in node.children:
            result = self._find_function_node(child)
            if result:
                return result
        
        return None
    
    def _normalize_node(self, node, source_code: str) -> str:
        """
        Normalize a tree-sitter node by extracting meaningful code elements.
        """
        normalized_parts = []
        self._extract_meaningful_content(node, source_code, normalized_parts)
        
        # Join all parts and normalize whitespace
        result = ' '.join(normalized_parts)
        # Remove extra whitespace
        result = re.sub(r'\s+', ' ', result).strip()
        
        return result
    
    def _extract_meaningful_content(self, node, source_code: str, parts: List[str]):
        """
        Recursively extract meaningful content from AST nodes, skipping comments.
        """
        # Skip comment nodes
        if node.type == 'comment':
            return
        
        # Skip docstring nodes (string literals at the beginning of function body)
        if self._is_docstring(node):
            return
        
        # For leaf nodes (terminals), extract text
        if len(node.children) == 0:
            text = self._get_node_text(node, source_code).strip()
            if text and not text.startswith('#'):
                parts.append(text)
        else:
            # For non-leaf nodes, recurse into children
            for child in node.children:
                self._extract_meaningful_content(child, source_code, parts)
    
    def _is_docstring(self, node) -> bool:
        """
        Check if a node is likely a docstring.
        """
        if node.type != 'expression_statement':
            return False
        
        # Check if it's a string literal at the start of a function/class body
        for child in node.children:
            if child.type == 'string':
                # Check if this is the first statement in a function/class body
                parent = node.parent
                if parent and parent.type == 'block':
                    # Find position in block
                    siblings = [child for child in parent.children if child.type in ['expression_statement', 'simple_statements']]
                    if siblings and siblings[0] == node:
                        return True
        
        return False
    
    def _get_node_text(self, node, source_code: str) -> str:
        """Extract text content from a tree-sitter node."""
        start_byte = node.start_byte
        end_byte = node.end_byte
        return source_code.encode('utf8')[start_byte:end_byte].decode('utf8')
    
    def _fallback_normalize(self, code: str) -> str:
        """
        Fallback normalization using regex when tree-sitter fails.
        """
        lines = code.split('\n')
        normalized_lines = []
        
        in_multiline_string = False
        in_docstring = False
        docstring_quotes = None
        
        for i, line in enumerate(lines):
            # Skip empty lines
            stripped = line.strip()
            if not stripped:
                continue
            
            # Handle docstrings
            if i == 0 or (i == 1 and lines[0].strip().startswith('def ')):
                # Check for docstring start
                docstring_match = re.match(r'\s*(""".*?"""|\'\'\'.+?\'\'\'|".*?"|\'.*?\')\s*$', stripped)
                if docstring_match or stripped.startswith('"""') or stripped.startswith("'''"):
                    if not (stripped.startswith('"""') and stripped.endswith('"""') and len(stripped) > 6):
                        in_docstring = True
                        docstring_quotes = '"""' if '"""' in stripped else "'''"
                    continue
            
            # Handle multiline docstring end
            if in_docstring:
                if docstring_quotes in stripped:
                    in_docstring = False
                continue
            
            # Skip single-line comments
            if stripped.startswith('#'):
                continue
            
            # Remove inline comments (simple approach)
            if '#' in stripped:
                # More sophisticated comment removal would need proper parsing
                code_part = stripped.split('#')[0].strip()
                if code_part:
                    normalized_lines.append(code_part)
            else:
                normalized_lines.append(stripped)
        
        # Join lines and normalize whitespace
        result = ' '.join(normalized_lines)
        result = re.sub(r'\s+', ' ', result)
        
        return result.strip()
func_comparator = FunctionBodyComparator()
def filter_vulnerable_methods(file:ModifiedFile,vulnerable_methods):
    filtered_methods = []

    # 去除空白字符后判断是否完全一样
    methods_changed_new = {
        new_method.long_name:new_method
        for new_method in  file.methods_changed_new
    }
    methods_changed_old = {
        old_method.long_name:old_method
        for old_method in  file.methods_changed_old
    }
    
    for method in vulnerable_methods:
        if not method.long_name:  # Handle empty name case
            assert False
            continue
            
        old_method = methods_changed_old.get(method.long_name)
        new_method = methods_changed_new.get(method.long_name)
        
        if old_method and new_method:  # Ensure both methods exist
            code1 = old_method.code
            code2 = new_method.code
            # print(code1)
            # print(code2)
            normalized1 = func_comparator.normalize_function_body(code1)
            normalized2 = func_comparator.normalize_function_body(code2)
            # print(normalized1)
            # print(normalized2)
                
            if normalized1 != normalized2:
                filtered_methods.append(method)
        else:
            filtered_methods.append(method)
    return filtered_methods

def filter_methods(vulnerable_methods, commit_hash, repo_path,file):

    ref_methods_ids = get_ref_methods(repo_path, commit_hash)
    logger.debug(f"ref_methods_ids, {ref_methods_ids}")
    all_extracted_methods = []
    filtered_vulnerable_methods = []

    for  method_before in vulnerable_methods:
        # if  method_id not in file_methods_after:
        #     file_methods.append(method_before)
        # else:
        #     methods_after = file_methods_after[method_id]
        #     method_before_code = method_before['code']
        #     methods_after_code = methods_after['code']
        #     # 是否只有空行缩进和注释变化
        #     if is_space_change(method_before_code, methods_after_code):
        #         logger.debug(f"Method {method_id} only has space change, skipping.")

        #         continue
        #     else:
        #         # print("method_before:",method_before)
        #         # print("methods_after:",methods_after)
        #         pass

        # 是否是私有方法
        # if is_private_method(method_before['name']):
        #     logger.debug(f"Method {method['signature']} is private, skipping.")
        #     continue
        # print('commit_hash:',commit_hash)
        # ref_type = is_ref_method(method_before, ref_methods_ids)
        # if ref_type is None:

        #     continue
        # else:
        #     if ref_type == 'Extract Method':
        #         logger.debug(f"Method {method_before['full_name']} is extracted method....")
        #         all_extracted_methods.append(method_before)
        #         continue
        filtered_vulnerable_methods.append(method_before)
    
    return filtered_vulnerable_methods,all_extracted_methods

def get_methods(file, ret_dict=False):
    """
    获取文件中修改前后的方法信息
    返回格式: [{
        'method_change_id': str,
        'file_change_id': str,
        'name': str,
        'signature': str,
        'start_line': int,
        'end_line': int,
        'before_change': bool,
        'code': str
    }]
    """
    all_vulnerable_methods = []
    # print(file.__dict__)
    # print(file._c_diff)
    # print(file.vulnerable_methods)
    # print(file.vulnerable_methods)
    # for method in file.vulnerable_methods:
    #     print(method.__dict__)
    try:
        if not file.vulnerable_methods:
            return []

        logger.debug('-' * 70)
        logger.debug(f'Processing changed methods in file: {file.filename}')
        
        # 处理修改前的方法


        for method in file.vulnerable_methods:

            try:
                all_vulnerable_methods.append({
                    # 'method_change_id': str(uuid.uuid4()),
                    # 'file_change_id': file_change_id,
                    'name': method.name,
                    'full_name': method.long_name,
                    'signature': method.signature,
                    'start_line': method.start_line,
                    'end_line': method.end_line,
                    'before_change': method.before_change,
                    'params':method.parameters,
                    'code': method.code,
                    'first_ciass':method.first_class
                })
            except Exception as e:
                logger.error(f'Error processing methods in file {file.old_path}: {str(e)}')
                assert False

     
        logger.debug(f"file: {file.old_path}")
        for method in all_vulnerable_methods:
            info = {k: v for k, v in method.items() if k != 'code'}
            logger.debug(f"Method info: {info}")
            # if method['name'] =='edit_file' and method['full_name'] == 'lib.ansible.parsing.vault.__init__.VaultEditor.edit_file':
            #     assert False
            
        # # logger.debug(f"file_methods_after, {file_methods_after}")
        # assert False
        if ret_dict:
            return all_vulnerable_methods,file.vul_dict
        return all_vulnerable_methods

    except Exception as e:
        logger.error(f'Error processing methods in file {file.filename}: {str(e)}')
        assert False
        return file_methods

def get_file_2_code_changes(commit2methods):

    code_changes = defaultdict(dict)
    for fixing_commit,file2methods in commit2methods.items():
        # logger.info(f'Processing {fixing_commit} code changes...')
        for file_path,methods in file2methods.items():
            # 提取方法的signature
            # methods_signatures = [(method['name'],method['signature'])for method in methods]
            # method_signatures = set(methods_signatures)
            for method in methods:
                # print('method:',method)
                full_name =f"{method['full_name']}" 
                if full_name not in code_changes[file_path]:
                    code_changes[file_path][full_name]=method
    return code_changes
def extract_changed_methods_group_by_source_type(commit2methods,possible_urls):
    # commit2methods = identify_vulnerable_location(fixing_commits, repo_path,extracted_urls_for_repo)

    commit_urls, pull_urls, issue_urls = possible_urls['commit'], possible_urls['pull'], possible_urls['issue']
    changed_methods_from_commit = {fixing_commit:commit2methods[fixing_commit] for fixing_commit in commit_urls if fixing_commit in commit2methods}

    if len(changed_methods_from_commit):
        return changed_methods_from_commit
    logger.warning(f'No code changes from commit for {repo_url}')
    

    changed_methods_from_issue = {fixing_commit:commit2methods[fixing_commit] for fixing_commit in issue_urls if fixing_commit in commit2methods}
    if len(changed_methods_from_issue):
        return changed_methods_from_issue
    
    changed_methods_from_pull = {fixing_commit:commit2methods[fixing_commit] for fixing_commit in pull_urls if fixing_commit in commit2methods}
    if len(changed_methods_from_pull):
        return changed_methods_from_pull
    

    return {}
def identify_vulnerable_location(fixing_commits, repo_path,cve_id,extracted_urls_for_repo=[]):
    
    # 分析每个修复提交
    repo = Git(repo_path)
    commit2methods = defaultdict(dict)
    modified_non_py_files,modified_py_files = [],[]

    vulnerable_funcs_cnt = 0
    all_vul_dict = defaultdict(list)
    for fixing_commit in fixing_commits:
        logger.info(f'Processing commit {fixing_commit}')
        commit_hash_ = fixing_commit.split('/')[-1]
        # logger.info(f'Processing commit {commit_hash}')
        # 提取代码变化
        # 缓存commit对象
        diff_cached = DIFF_CACHE_DIR_DATE / f"{cve_id}/{commit_hash_}.pkl"
        if not diff_cached.parent.exists():
            diff_cached.parent.mkdir(parents=True, exist_ok=True)
         
        modified_files = None
        if diff_cached.exists():
            try:
                logger.info(f'Loading commit {commit_hash_} from cache...')
                with open(diff_cached, 'rb') as f:
                    commit_hash,modified_files = pickle.load(f)
            except Exception as e:
                continue
        if not modified_files:
            try:
                commit = repo.get_commit(commit_hash_)
                commit_hash = commit.hash
            except Exception as e:
                logger.warning(f'Commit {commit_hash_} not found, skipping...')
                continue
            
            # 提取代码变化
            logger.debug(f'Extracting {repo_url}/commit/{commit_hash} code changes...')
            modified_files = get_modified_files(commit)
            try:
                with open(diff_cached, 'wb') as f:
                    pickle.dump((commit_hash,modified_files), f)
            except Exception as e:
                
                continue
        
        try:    
            if not modified_files:
                continue
            modified_non_py_files,modified_py_files = modified_files 
            
            
            if len(modified_files) == 0:
                logger.warning(f'No files modified in commit {commit_hash}')
                
            for file in modified_py_files:
                logger.info(f'Processing file {file.old_path} in {commit_hash}')
                all_vulnerable_methods = get_methods(file)
                vulnerable_funcs_cnt += len(all_vulnerable_methods)
                for type_, funcs in file.vul_dict.items():
                    if type_ in all_vul_dict:
                        all_vul_dict[type_].extend(funcs)
                # filtered_file_methods =all_vulnerable_methods
                commit2methods[fixing_commit][file.old_path] =  all_vulnerable_methods
            for file in modified_non_py_files:
                commit2methods[fixing_commit][file.old_path] =  []
        except Exception as e:
            logger.error(f'Extracting {commit_hash} code changes error {cve_id}, skipping...')
            assert False
            continue 

    if vulnerable_funcs_cnt == 0:
        logger.debug(f"commit2methods:{commit2methods}")
        for file in modified_py_files:
            if len(file.changed_class_vars) or len(file.changed_class_vars_before) or len(file.changed_global_vars) or len(file.changed_global_vars_before):
                logger.debug(f"changed_class_vars:{file.changed_class_vars}")
                logger.debug(f"changed_class_vars_before:{file.changed_class_vars_before}")
                logger.debug(f"changed_global_vars:{file.changed_global_vars}")
                logger.debug(f"changed_global_vars_before:{file.changed_global_vars_before}")
    commit2methods=extract_changed_methods_group_by_source_type(commit2methods,extracted_urls_for_repo)
    # TODO https://github.com/laowantong/mocodo/commit/f9368df28518b6c4a92fd207c260f1978ec34d6e 


    return commit2methods,modified_non_py_files,modified_py_files,all_vul_dict
    

def filtered_by_merge_commit_and_large_pull(fixing_commits,extracted_urls_for_repo, repo_path, cve_id):
    repo = Git(repo_path)
    ret_fixing_commits = []

    # 过滤direct commit in cve
    for commit_raw in fixing_commits:
        if commit_raw not in extracted_urls_for_repo['commit']:
            continue
        commit_hash = commit_raw.split('/')[-1]
        try:
            commit = repo.get_commit(commit_hash)
        except Exception as e:
            logger.warning(f'Commit {commit_hash} not found, skipping...')
            continue
        if not commit.merge:
            ret_fixing_commits.append(commit_raw)
    if len(ret_fixing_commits):
        return ret_fixing_commits
    issue_urls = extracted_urls_for_repo['issue']
    if len(issue_urls)>10:
        logger.warning(f'Found too{len(issue_urls)} issue urls for {cve_id}')
        # 从pull request里提取commit
        # 只保留pull request的commit
    else:
        return issue_urls
    pull_urls = extracted_urls_for_repo['pull']
    if len(pull_urls)>10:
        logger.warning(f'Found too{len(pull_urls)} pull urls for {cve_id}')
        # 从pull request里提取commit
        # 只保留pull request的commit
    else:
        return pull_urls
    return []



def get_code_change_scope_for_all(cve2advisory):
    for idxx, (cve_id, advisory) in enumerate(tqdm(cve2advisory.items(), desc="get_code_change_scope_for_all")):
        
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        logger.debug(f"Processing {cve_id} ({idxx}/{len(cve2advisory)}), advisory: {advisory['id']}")
        logger.debug(f"Found {len(all_unique_affected_projects)} unique affected projects: {all_unique_affected_projects}")
        # if cve_id not in ['CVE-2021-29431']:
        #     continue
        
        for package_name, repo_url in all_unique_affected_projects:
            
            fixing_commits = advisory['fixing_commits'].get(package_name, [])
            if len(fixing_commits) == 0:
                continue
            if len(fixing_commits) > 10:
                assert False
                continue
            for fixing_commit in fixing_commits:
                
                fixing_commit_ = fixing_commit.split('/')[-1]
                diff_cached = DIFF_CACHE_DIR_DATE / f"{cve_id}/{fixing_commit_}.pkl"
                logger.info(f"processing {fixing_commit}")
                with open(diff_cached, 'rb') as f:
                    commit_hash,modified_files = pickle.load(f)
                _, modified_py_files = is_source_code_modified(modified_files)
                if len(modified_py_files) ==0:
                    continue
                scope_cached = SCOPE_CACHE_DIR_DATE / f"{cve_id}/{fixing_commit_}.pkl"
                if not scope_cached.parent.exists():
                    scope_cached.parent.mkdir(parents=True, exist_ok=True)
                if scope_cached.exists() and True:
                    with open(scope_cached, 'rb') as f:
                        file2scope = pickle.load(f)
                else:
                    file2scope = {}
                    # 并行处理
                    # for file in modified_py_files:
                        # print(file.cleaned_added_lines)
                        # ret = process_modified_file_joblib(file)
                        # print(ret)
                        # assert False
                    
                    results = Parallel(n_jobs=5)(
                        delayed(process_modified_file_joblib)(mf) for mf in modified_py_files
                    )
                    # 构建结果字典
                    file2scope = {}
                    for result in results:
                        if result:
                            file_id, scope_data = result
                            file2scope[file_id] = scope_data

                    with open(scope_cached,'wb') as f:
                        pickle.dump(file2scope,f)
                        
    logger.info(f"get_code_change_scope_for_all done")
SEP_CVE = [ 'CVE-2010-4340']
def evaluate_code_change_scope(cve2advisory):
    """
    分析代码变更类型分布
    1. 统计修改module、class、function的CVE分布
    2. 分析CVE之间的重叠情况
    3. 统计VFC数量和changed lines
    4. 输出详细的统计信息
    """
    print("\n=== 代码变更类型分析 ===")
    
    # 初始化统计计数器
    module_modified_cves = set()
    class_modified_cves = set()
    function_modified_cves = set()
    
    # 使用line_type_stats替代change_type_stats
    line_type_stats = {
        'module': 0,
        'class': 0,
        'function': 0
    }
    
    # 新增统计指标
    total_stats = {
        'total_cves': 0,
        'total_vfcs': 0,
        'total_changed_lines': 0,
        'total_deleted_lines': 0,
        'total_added_lines': 0,
        'total_modified_files': 0,
        'assigns': 0,
        'imports': 0
    }
    
    # CVE级别的详细统计
    cve_detailed_stats = {}
    
    # VFC级别的统计 - 使用set来避免重复计数
    vfc_stats = {
        'module_vfcs': set(),
        'class_vfcs': set(),
        'function_vfcs': set(),
        'total_vfcs': set()
    }
    
    total_cve = set()
    
    for idxx, (cve_id, advisory) in enumerate(tqdm(cve2advisory.items(), desc="分析代码变更类型")):
        # if cve_id not in  SEP_CVE:

        #     continue
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        logger.debug(f"Processing {cve_id} ({idxx}/{len(cve2advisory)}), advisory: {advisory['id']}")
        logger.debug(f"Found {len(all_unique_affected_projects)} unique affected projects: {all_unique_affected_projects}")
        
        # 当前CVE的变更类型统计
        cve_change_types = {
            'module': 0,
            'class': 0,
            'function': 0
        }
        
        # 当前CVE的详细统计
        cve_stats = {
            'vfc_count': 0,
            'changed_lines': 0,
            'deleted_lines': 0,
            'added_lines': 0,
            'modified_files': 0,
            'assigns': 0,
            'imports': 0
        }
        
        total_cve.add(cve_id)
        # 更精确的正则表达式
        import_pattern = re.compile(r'^\s*(import\s+[\w\.]+(?:\s+as\s+\w+)?|from\s+[\w\.]+\s+import\s+.+)$', re.IGNORECASE)
        
        for package_name, repo_url in all_unique_affected_projects:
            if package_name not in advisory['fixing_commits']:
                continue
            fixing_commits = advisory['fixing_commits'][package_name]
            repo_name = get_repo_name(repo_url)
            logger.debug(f'Processing {repo_url} {repo_name}, {len(fixing_commits)} fixing_commits')
            
            # 统计当前package的VFC数量
            cve_stats['vfc_count'] += len(fixing_commits)
            # print(fixing_commits, len(fixing_commits))
            # assert False
            candidate_vfc_info_file = COMMITS_DIR_DATE/f'{cve_id}_{package_name}_candidate_vfc_infos.json'
            with candidate_vfc_info_file.open('r') as f:
                candidate_vfc_infos = json.load(f)
            
            for fixing_commit in fixing_commits:
                logger.debug(f'{fixing_commit}')
                fixing_commit_ = fixing_commit.split('/')[-1]
                
                # 将VFC添加到总统计中
                vfc_stats['total_vfcs'].add((cve_id, fixing_commit_))


                diff_cached = DIFF_CACHE_DIR_DATE / f"{cve_id}/{fixing_commit_}.pkl"
                with open(diff_cached, 'rb') as f:
                    commit_hash, modified_files = pickle.load(f)
                _, modified_py_files = is_source_code_modified(modified_files)
                logger.info(modified_py_files)
                if len(modified_py_files) ==0:
                    info = candidate_vfc_infos.get(fixing_commit,None)
                    logger.info(info)
                    # assert False
                    continue
                scope_cached = SCOPE_CACHE_DIR_DATE / f"{cve_id}/{fixing_commit_}.pkl"
                with open(scope_cached, 'rb') as f:
                    file2scope = pickle.load(f)

            
                _, modified_py_files = is_source_code_modified(modified_files)
                # print([file.filename for file in modified_py_files])
                # print(file2scope)
                cve_stats['modified_files'] += len(modified_py_files)
  
                for modified_file in modified_py_files:
                    key_components = (
                        getattr(modified_file, '_commit_hash', ''),
                        modified_file.change_type.name,
                        modified_file.old_path or '',
                        modified_file.new_path or '',
                    )
                    file_id = '|'.join(key_components)
                    
                    if file_id not in file2scope:
                        logger.warning(f"File ID {file_id} not found in scope cache")
                        continue
                        
                    deleted_line_scope, added_line_scope = file2scope[file_id]
                    
                    # 统计changed lines
                    for change_type in ['module', 'class', 'function']:
                        deleted_lines = deleted_line_scope.get(change_type, [])
                        added_lines = added_line_scope.get(change_type, [])
                        scope_lines = deleted_lines + added_lines
                        
                        if len(scope_lines) > 0:
                            cve_change_types[change_type] += len(scope_lines)
                            line_type_stats[change_type] += len(scope_lines)  # 使用line_type_stats
                            
                            # 统计VFC类型 - 使用你更新的逻辑
                            if change_type == 'module':
                                vfc_stats['module_vfcs'].add((cve_id, fixing_commit_))
                            elif change_type == 'class':
                                vfc_stats['class_vfcs'].add((cve_id, fixing_commit_))
                            elif change_type == 'function':
                                vfc_stats['function_vfcs'].add((cve_id, fixing_commit_))
                        
                        # 详细统计deleted和added lines
                        cve_stats['deleted_lines'] += len(deleted_lines)
                        cve_stats['added_lines'] += len(added_lines)
                        cve_stats['changed_lines'] += len(scope_lines)
                        
                        # 统计特殊内容
                        if change_type != 'function':
                            for line_no, content in scope_lines:
                                if ' = ' in content:
                                    cve_stats['assigns'] += 1
                                    total_stats['assigns'] += 1
                                

                                if import_pattern.match(content.strip()):
                                    cve_stats['imports'] += 1
                                    total_stats['imports'] += 1
                                # if 'import ' in content:
                                    # cve_stats['imports'] += 1
                                    # total_stats['imports'] += 1
        
        # 根据变更类型将CVE分类
        if cve_change_types['module'] > 0:
            module_modified_cves.add(cve_id)
        if cve_change_types['class'] > 0:
            class_modified_cves.add(cve_id)
        if cve_change_types['function'] > 0:
            function_modified_cves.add(cve_id)
        
        # 保存CVE详细统计
        cve_detailed_stats[cve_id] = cve_stats
        
        # 累加到总统计
        total_stats['total_vfcs'] += cve_stats['vfc_count']
        # total_stats['total_changed_lines'] += cve_stats['changed_lines']
        total_stats['total_deleted_lines'] += cve_stats['deleted_lines']
        total_stats['total_added_lines'] += cve_stats['added_lines']
        total_stats['total_modified_files'] += cve_stats['modified_files']
    
    total_stats['total_cves'] = len(total_cve)
    # 输出统计结果
    print(f"\n=== 总体统计 ===")
    print(f"CVE数量: {total_stats['total_cves']}")
    print(f"VFC总数: {len(vfc_stats['total_vfcs'])}")
    print(f"平均每个CVE的VFC数: {len(vfc_stats['total_vfcs'])/total_stats['total_cves']:.2f}")
    print(f"修改的文件总数: {total_stats['total_modified_files']}")
    print(f"变更行数总计: {total_stats['total_changed_lines']}")
    print(f"删除行数总计: {total_stats['total_deleted_lines']}")
    print(f"新增行数总计: {total_stats['total_added_lines']}")
    print(f"赋值语句数: {total_stats['assigns']}")
    print(f"导入语句数: {total_stats['imports']}")
    
    print(f"\n=== CVE变更类型统计 ===")
    print(f"修改module的CVE数量: {len(module_modified_cves)} ({len(module_modified_cves)/total_stats['total_cves']*100:.1f}%)")
    print(f"修改class的CVE数量: {len(class_modified_cves)} ({len(class_modified_cves)/total_stats['total_cves']*100:.1f}%)")
    print(f"修改function的CVE数量: {len(function_modified_cves)} ({len(function_modified_cves)/total_stats['total_cves']*100:.1f}%)")
    
    print("\n=== 详细变更行数统计 ===")
    total_line = total_stats['total_deleted_lines'] + total_stats['total_added_lines']
    print(f"总module变更行数: {line_type_stats['module']} ({line_type_stats['module']/total_line*100:.1f}%)")
    print(f"总class变更行数: {line_type_stats['class']} ({line_type_stats['class']/total_line*100:.1f}%)")
    print(f"总function变更行数: {line_type_stats['function']} ({line_type_stats['function']/total_line*100:.1f}%)")
    
    print("\n=== VFC类型分布 ===")
    print(f"涉及module变更的VFC: {len(vfc_stats['module_vfcs']) } ({len(vfc_stats['module_vfcs'])/len(vfc_stats['total_vfcs'])*100:.1f}%)")
    print(f"涉及class变更的VFC: {len(vfc_stats['class_vfcs'])} ({len(vfc_stats['class_vfcs'])/len(vfc_stats['total_vfcs'])*100:.1f}%)")
    print(f"涉及function变更的VFC: {len(vfc_stats['function_vfcs'])} ({len(vfc_stats['function_vfcs'])/len(vfc_stats['total_vfcs'])*100:.1f}%)")
    
    print("\n=== 重叠分析 ===")
    module_cves =  module_modified_cves - class_modified_cves - function_modified_cves  # 只有module
    class_cves = class_modified_cves - module_modified_cves - function_modified_cves   # 只有class
    module_class_cves = (module_modified_cves & class_modified_cves) - function_modified_cves # module + class
    # 计算所有可能的组合
    combinations = {
        '100': module_modified_cves - class_modified_cves - function_modified_cves,  # 只有module
        '010': class_modified_cves - module_modified_cves - function_modified_cves,   # 只有class
        '001': function_modified_cves - module_modified_cves - class_modified_cves,  # 只有function
        '110': (module_modified_cves & class_modified_cves) - function_modified_cves, # module + class
        '101': (module_modified_cves & function_modified_cves) - class_modified_cves, # module + function
        '011': (class_modified_cves & function_modified_cves) - module_modified_cves,  # class + function
        '111': module_modified_cves & class_modified_cves & function_modified_cves     # 全部三种
    }

    # 计算每种组合的VFC数量和changed lines
    combination_stats = {}
    for pattern, cve_set in combinations.items():
        vfc_count = 0
        changed_lines = 0
        
        for cve_id in cve_set:
            if cve_id in cve_detailed_stats:
                vfc_count += cve_detailed_stats[cve_id]['vfc_count']
                changed_lines += cve_detailed_stats[cve_id]['changed_lines']
        
        combination_stats[pattern] = {
            'cve_count': len(cve_set),
            'vfc_count': vfc_count,
            'changed_lines': changed_lines,
            'avg_vfc_per_cve': vfc_count / len(cve_set) if len(cve_set) > 0 else 0,
            'avg_lines_per_cve': changed_lines / len(cve_set) if len(cve_set) > 0 else 0
        }

    # 输出详细的组合统计
    total_cves_with_changes = len(module_modified_cves | class_modified_cves | function_modified_cves)

    print(f"变更类型组合分析 (M=Module, C=Class, F=Function):")
    print(f"{'组合':<8} {'描述':<20} {'CVE数':<8} {'VFC数':<8} {'变更行数':<10} {'平均VFC/CVE':<12} {'平均行数/CVE':<12}")
    print("-" * 85)

    for pattern in ['100', '010', '001', '110', '101', '011', '111']:
        stats = combination_stats[pattern]
        m, c, f = pattern
        description = []
        if m == '1': description.append('Module')
        if c == '1': description.append('Class')
        if f == '1': description.append('Function')
        
        desc_str = ' + '.join(description) if description else 'None'
        
        print(f"{pattern:<8} {desc_str:<20} {stats['cve_count']:<8} {stats['vfc_count']:<8} {stats['changed_lines']:<10} {stats['avg_vfc_per_cve']:<12.1f} {stats['avg_lines_per_cve']:<12.1f}")
    # 替换第687行及其后续内容
    for pattern in ['single-scope', 'multi-scope']:
        if pattern == 'single-scope':
            # 单一作用域：只修改一种类型的CVE
            single_scope_cves = combinations['100'] | combinations['010'] | combinations['001']
            single_scope_stats = {
                'cve_count': len(single_scope_cves),
                'vfc_count': sum(cve_detailed_stats[cve]['vfc_count'] for cve in single_scope_cves if cve in cve_detailed_stats),
                'changed_lines': sum(cve_detailed_stats[cve]['changed_lines'] for cve in single_scope_cves if cve in cve_detailed_stats)
            }
            print(f"{pattern:<8} {'Single Type':<20} {single_scope_stats['cve_count']:<8} {single_scope_stats['vfc_count']:<8} {single_scope_stats['changed_lines']:<10} {single_scope_stats['vfc_count']/single_scope_stats['cve_count'] if single_scope_stats['cve_count'] > 0 else 0:<12.1f} {single_scope_stats['changed_lines']/single_scope_stats['cve_count'] if single_scope_stats['cve_count'] > 0 else 0:<12.1f}")
        
        elif pattern == 'multi-scope':
            # 多作用域：修改多种类型的CVE
            multi_scope_cves = combinations['110'] | combinations['101'] | combinations['011'] | combinations['111']
            multi_scope_stats = {
                'cve_count': len(multi_scope_cves),
                'vfc_count': sum(cve_detailed_stats[cve]['vfc_count'] for cve in multi_scope_cves if cve in cve_detailed_stats),
                'changed_lines': sum(cve_detailed_stats[cve]['changed_lines'] for cve in multi_scope_cves if cve in cve_detailed_stats)
            }
            print(f"{pattern:<8} {'Multiple Types':<20} {multi_scope_stats['cve_count']:<8} {multi_scope_stats['vfc_count']:<8} {multi_scope_stats['changed_lines']:<10} {multi_scope_stats['vfc_count']/multi_scope_stats['cve_count'] if multi_scope_stats['cve_count'] > 0 else 0:<12.1f} {multi_scope_stats['changed_lines']/multi_scope_stats['cve_count'] if multi_scope_stats['cve_count'] > 0 else 0:<12.1f}")

    # 添加单一作用域 vs 多作用域的对比分析
    print(f"\n=== 单一作用域 vs 多作用域对比 ===")
    single_scope_cves = combinations['100'] | combinations['010'] | combinations['001']
    multi_scope_cves = combinations['110'] | combinations['101'] | combinations['011'] | combinations['111']

    single_stats = {
        'cve_count': len(single_scope_cves),
        'vfc_count': sum(cve_detailed_stats[cve]['vfc_count'] for cve in single_scope_cves if cve in cve_detailed_stats),
        'changed_lines': sum(cve_detailed_stats[cve]['changed_lines'] for cve in single_scope_cves if cve in cve_detailed_stats)
    }

    multi_stats = {
        'cve_count': len(multi_scope_cves),
        'vfc_count': sum(cve_detailed_stats[cve]['vfc_count'] for cve in multi_scope_cves if cve in cve_detailed_stats),
        'changed_lines': sum(cve_detailed_stats[cve]['changed_lines'] for cve in multi_scope_cves if cve in cve_detailed_stats)
    }

    print(f"单一作用域CVE: {single_stats['cve_count']} ({single_stats['cve_count']/total_cves_with_changes*100:.1f}%)")
    print(f"多作用域CVE: {multi_stats['cve_count']} ({multi_stats['cve_count']/total_cves_with_changes*100:.1f}%)")
    print(f"")
    print(f"单一作用域平均VFC/CVE: {single_stats['vfc_count']/single_stats['cve_count'] if single_stats['cve_count'] > 0 else 0:.1f}")
    print(f"多作用域平均VFC/CVE: {multi_stats['vfc_count']/multi_stats['cve_count'] if multi_stats['cve_count'] > 0 else 0:.1f}")
    print(f"")
    print(f"单一作用域平均变更行数/CVE: {single_stats['changed_lines']/single_stats['cve_count'] if single_stats['cve_count'] > 0 else 0:.1f}")
    print(f"多作用域平均变更行数/CVE: {multi_stats['changed_lines']/multi_stats['cve_count'] if multi_stats['cve_count'] > 0 else 0:.1f}")

    # 复杂度分析
    if multi_stats['cve_count'] > 0 and single_stats['cve_count'] > 0:
        vfc_complexity_ratio = (multi_stats['vfc_count']/multi_stats['cve_count']) / (single_stats['vfc_count']/single_stats['cve_count'])
        lines_complexity_ratio = (multi_stats['changed_lines']/multi_stats['cve_count']) / (single_stats['changed_lines']/single_stats['cve_count'])
        
        print(f"\n=== 复杂度分析 ===")
        print(f"多作用域CVE的VFC复杂度是单一作用域的 {vfc_complexity_ratio:.2f} 倍")
        print(f"多作用域CVE的变更行数复杂度是单一作用域的 {lines_complexity_ratio:.2f} 倍")
        
    # 验证总数
    total_categorized_cves = sum(stats['cve_count'] for stats in combination_stats.values())
    total_categorized_vfcs = sum(stats['vfc_count'] for stats in combination_stats.values())
    total_categorized_lines = sum(stats['changed_lines'] for stats in combination_stats.values())

    print(f"\n=== 验证统计 ===")
    print(f"分类CVE总数: {total_categorized_cves} / 有变更CVE总数: {total_cves_with_changes}")
    print(f"分类VFC总数: {total_categorized_vfcs} / 总VFC数: {total_stats['total_vfcs']}")
    print(f"分类变更行数: {total_categorized_lines} / 总变更行数: {total_stats['total_changed_lines']}")

    # 按比例分析
    print(f"\n=== 比例分析 ===")
    print(f"{'组合':<8} {'CVE比例':<10} {'VFC比例':<10} {'变更行比例':<12}")
    print("-" * 45)

    for pattern in ['100', '010', '001', '110', '101', '011', '111']:
        stats = combination_stats[pattern]
        cve_ratio = f"{stats['cve_count']/total_cves_with_changes*100:.1f}%" if total_cves_with_changes > 0 else "0.0%"
        vfc_ratio = f"{stats['vfc_count']/total_stats['total_vfcs']*100:.1f}%" if total_stats['total_vfcs'] > 0 else "0.0%"
        lines_ratio = f"{stats['changed_lines']/total_stats['total_changed_lines']*100:.1f}%" if total_stats['total_changed_lines'] > 0 else "0.0%"
        
        print(f"{pattern:<8} {cve_ratio:<10} {vfc_ratio:<10} {lines_ratio:<12}")

    # 额外的深度分析
    print(f"\n=== 深度分析 ===")

    # 找出VFC密度最高的组合
    max_vfc_density = max(combination_stats.values(), key=lambda x: x['avg_vfc_per_cve'])
    max_vfc_pattern = [k for k, v in combination_stats.items() if v == max_vfc_density][0]
    print(f"VFC密度最高的组合: {max_vfc_pattern} (平均 {max_vfc_density['avg_vfc_per_cve']:.1f} VFC/CVE)")

    # 找出变更行数密度最高的组合
    max_lines_density = max(combination_stats.values(), key=lambda x: x['avg_lines_per_cve'])
    max_lines_pattern = [k for k, v in combination_stats.items() if v == max_lines_density][0]
    print(f"变更行数密度最高的组合: {max_lines_pattern} (平均 {max_lines_density['avg_lines_per_cve']:.1f} 行/CVE)")

    # 分析复杂度（同时修改多种类型的CVE）
    complex_combinations = ['110', '101', '011', '111']
    complex_cves = sum(combination_stats[pattern]['cve_count'] for pattern in complex_combinations)
    complex_vfcs = sum(combination_stats[pattern]['vfc_count'] for pattern in complex_combinations)
    complex_lines = sum(combination_stats[pattern]['changed_lines'] for pattern in complex_combinations)

    print(f"\n复杂变更（涉及多种类型）统计:")
    print(f"  CVE数量: {complex_cves} ({complex_cves/total_cves_with_changes*100:.1f}%)")
    print(f"  VFC数量: {complex_vfcs} ({complex_vfcs/total_stats['total_vfcs']*100:.1f}%)")

    print(f"\n=== Top 10 CVE (按变更行数) ===")
    sorted_cves = sorted(cve_detailed_stats.items(), 
                        key=lambda x: x[1]['changed_lines'], reverse=True)[:10]
    for i, (cve_id, stats) in enumerate(sorted_cves, 1):
        print(f"{i:2d}. {cve_id}: {stats['changed_lines']} lines, {stats['vfc_count']} VFCs")
    

    return module_cves, class_cves, module_class_cves
def find_minimal_enclosing_scope(line_no, functions, classes):
    """
    查找包含指定行号的最小（最具体）的scope
    """
    # 收集所有包含该行的scopes
    containing_scopes = []
    
    # 检查所有functions
    for func in functions:
        if func.start_line <= line_no <= func.end_line:
            containing_scopes.append(('function', func))
    
    # 检查所有classes
    for cls in classes:
        if cls.start_line <= line_no <= cls.end_line:
            containing_scopes.append(('class', cls))
    
    if not containing_scopes:
        return 'module'
    
    # 找到最小的包含范围（行数最少的）
    min_scope = max(containing_scopes, 
                key=lambda x: x[1].start_line)
    
    return min_scope[0]


def get_code_change_scope(lines, functions, classes):
    line_scopes = {'function':[],'class':[],'module':[]}
    for line in lines:
        line_no, content = line
        scope = find_minimal_enclosing_scope(line_no, functions, classes)
        line_scopes[scope].append(line)
           
    logger.info(f"line_scopes:{line_scopes}")
    return line_scopes


def process_modified_file_joblib(modified_file):
    """使用joblib处理单个修改文件"""
    deleted_line_scope, added_line_scope = modified_file.get_code_changes_scopes()

    key_components = (
        getattr(modified_file, '_commit_hash', ''),
        modified_file.change_type.name,
        modified_file.old_path or '',
        modified_file.new_path or '',
    )
    file_id = '|'.join(key_components)
    return (file_id, [deleted_line_scope, added_line_scope])


def get_vulnerable_functions_for_all(cve2advisory):
    cves_has_filter_func=set()
    for idxx, (cve_id, advisory) in enumerate(tqdm(cve2advisory.items(), desc="分析代码变更类型")):
        
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        logger.debug(f"Processing {cve_id} ({idxx}/{len(cve2advisory)}), advisory: {advisory['id']}")
        logger.debug(f"Found {len(all_unique_affected_projects)} unique affected projects: {all_unique_affected_projects}")
    
        
        for package_name, repo_url in all_unique_affected_projects:
            fixing_commits = advisory['fixing_commits'].get(package_name, [])
            if len(fixing_commits) == 0:
                continue
            repo_name = get_repo_name(repo_url)

            logger.debug(f'Processing {repo_url}, {len(fixing_commits)}fixing_commits')
            code_changes_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}.json'
            code_changes_dict_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}_dict.pkl'
            if not code_changes_path.parent.exists():
                code_changes_path.parent.mkdir(parents=True)
            if code_changes_path.exists() and code_changes_dict_path.exists() and False:
                # if cve_id =='CVE-2017-16613':
                #     print(code_changes_path)
                #     print(code_changes_dict_path)
                #     print(code_changes_path.exists() and code_changes_dict_path.exists() )
                #     assert False
                logger.info(f'Code changes for {cve_id}_{repo_name} already exists, skipping...')
                # with code_changes_path.open('rb') as f:
                #     commit2methods = pickle.load(f)
            else:
                commit2methods=defaultdict(dict)
                commit2methods_dict=defaultdict(dict)
                for fixing_commit in fixing_commits:
                    logger.info(f'{fixing_commit}')
                    fixing_commit_ = fixing_commit.split('/')[-1]

                    diff_cached = DIFF_CACHE_DIR_DATE / f"{cve_id}/{fixing_commit_}.pkl" # may different commit_hash_ getting from git command
                    with open(diff_cached, 'rb') as f:
                        _, modified_files  = pickle.load(f)
                    _, modified_py_files = is_source_code_modified(modified_files)
                    if len(modified_py_files) == 0:
                        continue
                    scope_cached = SCOPE_CACHE_DIR_DATE / f"{cve_id}/{fixing_commit_}.pkl"
                    with open(scope_cached, 'rb') as f:
                        file2scope = pickle.load(f)
                        # file2scope[modified_file_id] = [deleted_line_scope, added_line_scope]
                    file2methods = {}
                    file2methods_dict={}
                    for modified_file in modified_py_files:
                        key_components = (
                                getattr(modified_file, '_commit_hash', ''),
                                modified_file.change_type.name,
                                modified_file.old_path or '',
                                modified_file.new_path or '',
                            )
                        file_id = '|'.join(key_components)
                        filtered_vulnerable_funcs, vulnerable_funcs,vfs_dict  = get_vulnerable_funcs_for_file(modified_file,file2scope[file_id])
                        if len(filtered_vulnerable_funcs) < len(vulnerable_funcs):
                            cves_has_filter_func.add(cve_id)
                        if len(filtered_vulnerable_funcs):
                            file2methods[modified_file.filename] = [method.long_name for method in filtered_vulnerable_funcs]
                            file2methods_dict[modified_file.filename] = vfs_dict
                    commit2methods[fixing_commit]=file2methods
                    commit2methods_dict[fixing_commit]=file2methods_dict
                with open(code_changes_path, 'w') as f:
                    json.dump((commit2methods), f)
                with open(code_changes_dict_path, 'wb') as f:
                    pickle.dump((commit2methods_dict), f)
                with code_changes_path.open('r') as f:
                    commit2methods = json.load(f)
                with code_changes_dict_path.open('rb') as f:
                    commit2methods_dict = pickle.load(f)
                
cached_line = list()               
def study_code_change_ast_type(cve2advisory,module_cves, class_cves, module_class_cves):
    # 统计变量
    # 按行统计
    ast_type_stats = defaultdict(Counter)
    category_stats = defaultdict(Counter)
    scope_stats = Counter()
    
    # 按CVE统计
    cve_ast_type_stats = defaultdict(lambda: defaultdict(Counter))
    cve_category_stats = defaultdict(lambda: defaultdict(Counter))
    cve_scope_stats = defaultdict(Counter)
    
    # 按VFC统计
    vfc_ast_type_stats = defaultdict(lambda: defaultdict(Counter))
    vfc_category_stats = defaultdict(lambda: defaultdict(Counter))
    vfc_scope_stats = defaultdict(Counter)
    
    # CVE和VFC级别的统计
    cve_summary_stats = defaultdict(lambda: {
        'total_lines': 0,
        'deleted_lines': 0,
        'added_lines': 0,
        'vfc_count': 0,
        'file_count': 0
    })
    
    vfc_summary_stats = defaultdict(lambda: {
        'total_lines': 0,
        'deleted_lines': 0,
        'added_lines': 0,
        'file_count': 0,
        'cve_id': ''
    })
    
    for idxx, (cve_id, advisory) in enumerate(tqdm(cve2advisory.items(), desc="get_code_change_scope_for_all")):
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        logger.debug(f"Processing {cve_id} ({idxx}/{len(cve2advisory)}), advisory: {advisory['id']}")
        logger.debug(f"Found {len(all_unique_affected_projects)} unique affected projects: {all_unique_affected_projects}")
        
        for package_name, repo_url in all_unique_affected_projects:
            fixing_commits = advisory['fixing_commits'].get(package_name, [])
            if len(fixing_commits) == 0:
                continue
            if len(fixing_commits) > 10:
                continue
                
            cve_summary_stats[cve_id]['vfc_count'] += len(fixing_commits)
            
            for fixing_commit in fixing_commits:
                fixing_commit_ = fixing_commit.split('/')[-1]
                vfc_id = f"{cve_id}_{fixing_commit_}"
                vfc_summary_stats[vfc_id]['cve_id'] = cve_id
                
                diff_cached = DIFF_CACHE_DIR_DATE / f"{cve_id}/{fixing_commit_}.pkl"
                logger.info(f"processing {fixing_commit}")
                
                with open(diff_cached, 'rb') as f:
                    commit_hash, modified_files = pickle.load(f)
                    
                _, modified_py_files = is_source_code_modified(modified_files)
                if len(modified_py_files) == 0:
                    continue
                astype_cached = AST_TYPE_CACHE_DIR_DATE / f"{cve_id}/{fixing_commit_}.pkl"
                if astype_cached.exists() and True:
                    with open(astype_cached,'r') as f:
                        file2ast_type = json.load(f)
                else:
                    file2ast_type = {}
                    scope_cached = SCOPE_CACHE_DIR_DATE / f"{cve_id}/{fixing_commit_}.pkl"
                    
                    with open(scope_cached, 'rb') as f:
                        file2scope = pickle.load(f)
                    for modified_file in modified_py_files:
                        key_components = (
                            getattr(modified_file, '_commit_hash', ''),
                            modified_file.change_type.name,
                            modified_file.old_path or '',
                            modified_file.new_path or '',
                        )
                        file_id = '|'.join(key_components)
                        
                        if file_id not in file2scope:
                            logger.warning(f"File ID {file_id} not found in scope cache")
                            continue
                            
                        deleted_line_scope, added_line_scope = file2scope[file_id]
                        logger.debug(file2scope[file_id])
                        ast_type_for_deleted_line, ast_type_for_added_line = get_code_change_ast_type(
                            modified_file, 
                            deleted_line_scope=deleted_line_scope, 
                            added_line_scope=added_line_scope
                        )
                        file2ast_type[file_id] = ast_type_for_deleted_line, ast_type_for_added_line
                    astype_cached.parent.mkdir(parents=True, exist_ok=True)
                    with open(astype_cached, 'w') as f:
                        json.dump(file2ast_type, f)
                        
                cve_summary_stats[cve_id]['file_count'] += len(modified_py_files)
                vfc_summary_stats[vfc_id]['file_count'] += len(modified_py_files)
               
                for _, (ast_type_for_deleted_line, ast_type_for_added_line) in file2ast_type.items():
                  
                    # 统计删除行的AST类型
                    for scope, lines_info in ast_type_for_deleted_line.items():
                        line_count = len(lines_info)
                        
                        # 按行统计
                        scope_stats[f'deleted_{scope}'] += line_count
                        
                        # 按CVE统计
                        cve_scope_stats[cve_id][f'deleted_{scope}'] += line_count
                        cve_summary_stats[cve_id]['deleted_lines'] += line_count
                        cve_summary_stats[cve_id]['total_lines'] += line_count
                        
                        # 按VFC统计
                        vfc_scope_stats[vfc_id][f'deleted_{scope}'] += line_count
                        vfc_summary_stats[vfc_id]['deleted_lines'] += line_count
                        vfc_summary_stats[vfc_id]['total_lines'] += line_count
                        
                        for line_info in lines_info:
                            ast_info = line_info['ast_type']
                            
                            # 按行统计
                            ast_type_stats[f'deleted_{scope}'][ast_info['type']] += 1
                            category_stats[f'deleted_{scope}'][ast_info['category']] += 1
                            # if 'decorated' in ast_info['category'].lower() and line_info['line_no'] !=57:
                            #     print(line_info)
                            #     assert False
                            if 'expression' in ast_info['category'].lower() :
                                print(line_info)
                                cached_line.append(line_info)
                                # assert False
                            
                            # 按CVE统计
                            cve_ast_type_stats[cve_id][f'deleted_{scope}'][ast_info['type']] += 1
                            cve_category_stats[cve_id][f'deleted_{scope}'][ast_info['category']] += 1
                            
                            # 按VFC统计
                            vfc_ast_type_stats[vfc_id][f'deleted_{scope}'][ast_info['type']] += 1
                            vfc_category_stats[vfc_id][f'deleted_{scope}'][ast_info['category']] += 1
                    
                    # 统计添加行的AST类型
                    for scope, lines_info in ast_type_for_added_line.items():
                        line_count = len(lines_info)
                        
                        # 按行统计
                        scope_stats[f'added_{scope}'] += line_count
                        
                        # 按CVE统计
                        cve_scope_stats[cve_id][f'added_{scope}'] += line_count
                        cve_summary_stats[cve_id]['added_lines'] += line_count
                        cve_summary_stats[cve_id]['total_lines'] += line_count
                        
                        # 按VFC统计
                        vfc_scope_stats[vfc_id][f'added_{scope}'] += line_count
                        vfc_summary_stats[vfc_id]['added_lines'] += line_count
                        vfc_summary_stats[vfc_id]['total_lines'] += line_count
                        
                        for line_info in lines_info:
                            ast_info = line_info['ast_type']
                            
                            # 按行统计
                            ast_type_stats[f'added_{scope}'][ast_info['type']] += 1
                            category_stats[f'added_{scope}'][ast_info['category']] += 1
                            # if 'decorated' in ast_info['category'].lower() and line_info['line_no'] not in [57, 167,79]:
                            #     print(line_info)
                            #     assert False
                            if 'expression' in ast_info['category'].lower() :
                                print(line_info)
                                cached_line.append(line_info)
                                # assert False
                            
                            # 按CVE统计
                            cve_ast_type_stats[cve_id][f'added_{scope}'][ast_info['type']] += 1
                            cve_category_stats[cve_id][f'added_{scope}'][ast_info['category']] += 1
                            
                            # 按VFC统计
                            vfc_ast_type_stats[vfc_id][f'added_{scope}'][ast_info['type']] += 1
                            vfc_category_stats[vfc_id][f'added_{scope}'][ast_info['category']] += 1
    
    # 输出统计结果
    print("\n" + "="*50)
    print("=== 总体AST类型分布 (按行统计) ===")
    print("="*50)
    
    print("\n--- AST Type Distribution ---")
    for scope_type, counter in ast_type_stats.items():
        print(f"\n{scope_type}:")
        for ast_type, count in counter.most_common():
            print(f"  {ast_type}: {count}")
    
    print("\n--- Category Distribution ---")
    for scope_type, counter in category_stats.items():
        print(f"\n{scope_type}:")
        for category, count in counter.most_common():
            print(f"  {category}: {count}")
    
    print("\n--- Scope Distribution ---")
    for scope, count in scope_stats.most_common():
        print(f"  {scope}: {count}")

        print("==只有module scope修改的VFC的统计==\n")
    # evaluate_ast_stats_by_category(cve2advisory={cve_id:advisory for cve_id, advisory in cve2advisory.items() if cve_id in module_cves })
    # print("==只有class  scope修改的VFC的统计==\n")

    # evaluate_ast_stats_by_category(cve2advisory={cve_id:advisory for cve_id, advisory in cve2advisory.items() if cve_id in class_cves })
    # print("==non-function scope修改的VFC的统计==\n")
    # evaluate_ast_stats_by_category(cve2advisory={cve_id:advisory for cve_id, advisory in cve2advisory.items() if cve_id in( module_class_cves|class_cves|module_cves) })

  
def get_code_change_ast_type(modified_file, deleted_line_scope, added_line_scope):
    # 1. module-scope, variable, import, other(?)
    # 2. class-scope, attribute
    
    # 1. innermost scope
    # the innermost scope, which is searched first, contains the local names

    # 2. the scopes of any enclosing functions, which are searched starting with the nearest enclosing scope, contain non-local, but also non-global names

    # 3. the next-to-last scope contains the current module’s global names

    # 4. the outermost scope (searched last) is the namespace containing built-in names
                    

    # TODO: module和class都修改了什么内容
    # import和class？


    print(len(deleted_line_scope['module']) or len(deleted_line_scope['class']))
    print(len(added_line_scope['module']) or len(added_line_scope['class']))
    ast_type_for_deleted_line, ast_type_for_added_line = {},{}
    if len(deleted_line_scope['module']) or len(deleted_line_scope['class']):
        analyzer = ScopeAnalyzer(source_code=modified_file.source_code_before, commit_hash = modified_file.commit_hash, file_path=modified_file.old_path)

        ast_type_for_deleted_line = analyzer.get_ast_type_for_lines(deleted_line_scope)
        logger.info(f"ast_type_for_deleted_line:{ast_type_for_deleted_line}")

        # assert False

    
    if len(added_line_scope['module']) or len(added_line_scope['class']):
        analyzer = ScopeAnalyzer(source_code=modified_file.source_code, commit_hash = modified_file.commit_hash, file_path=modified_file.new_path)

        ast_type_for_added_line =  analyzer.get_ast_type_for_lines(added_line_scope)
        logger.info(f"ast_type_for_added_line:{ast_type_for_added_line}")
        # assert False
    
    return ast_type_for_deleted_line, ast_type_for_added_line
    

def note():
    pkg2url = get_pkg2url()
    # create cve2advisory_id    

    # extract code changes from each commit
    # only keep N samples for debug
    N=10*1000
    cve2advisory = {k: v for k, v in list(cve2advisory.items())[:N]}  
    repo_not_download = []
    rewrite = False
    for idxx,(cve_id, advisory) in enumerate(tqdm(cve2advisory.items())):
        if idxx < 197:
            continue
        # if cve_id not in ['CVE-2021-3828']:
        #     continue
        true_extract_method = ['CVE-2025-24795']
        false_extract_method = ['CVE-2015-0222','CVE-2020-17495','CVE-2022-39254','CVE-2022-29255']
        # if cve_id not in false_extract_method+true_extract_method:
        #     continue
        
        # else:
        #     rewrite = True

        # ['CVE-2020-23478','CVE-2022-3364','CVE-2020-25449','CVE-2023-43804',
        # ''CVE-2022-3371','CVE-2021-32837','CVE-2020-36242','CVE-2024-53949'] DDG TP
        # ['CVE-2013-0270'] DDG FP new_class
        # ['CVE-2022-3644','CVE-2018-1000805','CVE-2023-2227','CVE-2021-27291',
        # 'CVE-2021-38540','CVE-2021-20270','CVE-2022-3298','CVE-2023-46126',
        # 'CVE-2021-26559','CVE-2015-5145','CVE-2023-25171','CVE-2023-39349',
        # 'CVE-2024-9340] no_method_used_in_file

        #global
        # TP ['CVE-2022-47950',''CVE-2022-1930','CVE-2021-32838',''CVE-2018-7537'','CVE-2021-29063','CVE-2022-40899','CVE-2020-29651','CVE-2017-12794',''CVE-2022-23452'']
        # not handle ['CVE-2023-46125','CVE-2020-1753']
        # no in file ['CVE-2019-1020005','CVE-2023-25657','CVE-2021-3828','CVE-2023-30608','CVE-2023-50263'',''CVE-2024-53947'','CVE-2023-44463','CVE-2021-28957','CVE-2024-34707','CVE-2020-26137','CVE-2020-1734','CVE-2024-11404']
        # FP ['CVE-2024-39705','CVE-2022-24857','CVE-2022-22846']
        # if cve_id != 'CVE-2023-36464':
        #     continue
        fixing_commits = read_fixing_commits(cve_id)
        # fixing_commits_snyk = get_snyk_urls_for_cve(cve_id)
        # logger.debug(f'fixing_commits_snyk, {fixing_commits_snyk}')
        aid = advisory['id'] 
        
            # continue
        # if aid != 'GHSA-cqhg-xjhh-p8hf': #验证是否能够有效过滤掉comments修改
            # continue

        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        extracted_urls = read_possible_urls(cve_id)
        for _, repo_url in all_unique_affected_projects:
            print(repo_url)

            repo_name = get_repo_name(repo_url)
            logger.debug(f'Processing {repo_url} {repo_name}')
            code_changes_path = CODE_CHANGES_DIR / f'{cve_id}_{repo_name}.json'
            modified_files_path = CODE_CHANGES_DIR / f'{cve_id}_{repo_name}_modified_files.pkl'
            if not code_changes_path.parent.exists():
                code_changes_path.parent.mkdir(parents=True)
            if code_changes_path.exists() and False:
                logger.info(f'Code changes for {cve_id}_{repo_name} already exists, skipping...')
                commit2methods = json.load(code_changes_path.open('r'))
                
            else:
                extracted_urls_for_repo = get_extracted_urls_for_repo(extracted_urls,repo_url)
                repo_path = REPO_DIR / get_repo_name(repo_url)
                logger.info(f'Processing {cve_id}')
            
            
                if len(extracted_urls_for_repo) == 0:
                    logger.warning(f'No extracted_urls for {repo_url},{cve_id}')
                    continue
                #TODO: 处理merge pull的问题
                # 先判断commit的values是否存在不属于merge commit
                # 如果有，则只使用这部分
                # 否则，从pull和issue里提取
                if not repo_path.exists():
                    logger.info(f'Repo {repo_url} not found, cloning...')
                    # write repo_url to candidate_repos.txt need to be cloned
                    # repo_not_download.append(repo_url+'\t'+str(repo_path)+'\n')
                    logger.warning(f"Repository {repo_url} not cloned. Skipping.")
                    clone_repo(repo_url, repo_path)
                    # assert False
                    continue
                logger.debug(f'Extracting {repo_url} code changes...')
                filtered_fixing_commits = filtered_by_merge_commit_and_large_pull(fixing_commits,extracted_urls_for_repo,repo_path,cve_id)
                if len(filtered_fixing_commits) == 0:
                    logger.warning(f'No fixing commits for {cve_id}, {len(filtered_fixing_commits)}/{len(fixing_commits)}')
                    continue
                else:
                    logger.info(f'Found {len(filtered_fixing_commits)} filtered fixing commits from {len(fixing_commits)} fixing commits for {cve_id}')
                
                commit2methods,modified_non_py_files,modified_py_files, all_vul_dict= identify_vulnerable_location(filtered_fixing_commits, repo_path,cve_id,extracted_urls_for_repo)
                logger.debug(f"commit2methods, {commit2methods}")
                # assert False
                with code_changes_path.open('w') as f:
                    json.dump(commit2methods, f)
                print(modified_files_path)
                with modified_files_path.open('wb') as f:
                    pickle.dump((modified_non_py_files,modified_py_files, all_vul_dict), f)
                code_changes = get_file_2_code_changes(commit2methods)
                # 打印，每个文件即其对应方法的signature
                method_cnt = 0
                for file, code_changes in code_changes.items():
                    methods = list(code_changes.keys())
                    logger.info(f"File {file}: {methods}")
                    method_cnt += len(methods)
                logger.info("="*70)
                
                logger.info(f"Found {method_cnt} code changes for {cve_id}_{repo_name}")
        
def evaluate_ast_stats_by_category(cve2advisory):
    """
    基于category的AST统计分析函数，只显示统计数字，不显示具体cases
    
    Args:
        cve2advisory: CVE到advisory信息的映射字典
    """
    
    # 统计变量初始化
    # 总体category统计（不区分added/deleted）
    overall_category_stats = defaultdict(Counter)  # scope -> {category: count}
    
    # VFC级别的category统计
    vfc_categories = {}  # vfc_id -> {scope: set of categories}
    vfc_summary = {}     # vfc_id -> {cve_id, total_changes, categories_summary}
    
    # 用于分析重叠情况
    category_combinations = defaultdict(list)  # category组合 -> [vfc_ids]
    single_category_vfcs = defaultdict(list)   # 单一category -> [vfc_ids]
    
    # 遍历所有CVE
    for idxx, (cve_id, advisory) in enumerate(tqdm(cve2advisory.items(), desc="analyze_by_category")):
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        
        # 遍历每个受影响的项目
        for package_name, repo_url in all_unique_affected_projects:
            fixing_commits = advisory['fixing_commits'].get(package_name, [])
            if len(fixing_commits) == 0 or len(fixing_commits) > 10:
                continue
            
            # 遍历每个修复提交

            for fixing_commit in fixing_commits:
                fixing_commit_ = fixing_commit.split('/')[-1]
                vfc_id = f"{cve_id}_{fixing_commit_}"
                
                # 加载AST类型缓存
                scope_cached = SCOPE_CACHE_DIR_DATE / f"{cve_id}/{fixing_commit_}.pkl"
                astype_cached = AST_TYPE_CACHE_DIR_DATE / f"{cve_id}/{fixing_commit_}.pkl"
                if not astype_cached.exists():
                    continue
                with open(scope_cached,'rb') as f:
                    file2scope = pickle.load(f)
                with open(astype_cached,'r') as f:
                    file2ast_type = json.load(f)
                
                if not file2ast_type:
                    continue
                # 统计VFC是否修改了function
                
                # 收集该VFC的所有categories
                vfc_categories[vfc_id] = defaultdict(set)
                total_changes = 0
                
                # 处理每个文件的AST类型信息
                has_function=False
                for file_id, (ast_type_for_deleted_line, ast_type_for_added_line) in file2ast_type.items():
                    scopes = file2scope[file_id]
                    deleted_line_scope, added_line_scope = scopes
                    if len(deleted_line_scope['function']) or len(added_line_scope['function']):
                        ...
                        has_function=True
                        continue
                    
                    # 处理删除行和添加行，统一到scope级别
                    all_scope_changes = {}
                    
                    # 合并删除行的信息
                    for scope, lines_info in ast_type_for_deleted_line.items():
                        if scope not in all_scope_changes:
                            all_scope_changes[scope] = []
                        all_scope_changes[scope].extend(lines_info)
                    
                    # 合并添加行的信息
                    for scope, lines_info in ast_type_for_added_line.items():
                        if scope not in all_scope_changes:
                            all_scope_changes[scope] = []
                        all_scope_changes[scope].extend(lines_info)
                    
                    # 统计每个scope的categories
                    for scope, lines_info in all_scope_changes.items():
                        for line_info in lines_info:
                            category = line_info['ast_type']['category']
                            vfc_categories[vfc_id][scope].add(category)
                            overall_category_stats[scope][category] += 1
                            total_changes += 1
                
                # 汇总该VFC的信息
                if has_function:
                    continue
                all_categories = set()
                for scope_categories in vfc_categories[vfc_id].values():
                    all_categories.update(scope_categories)
                
                vfc_summary[vfc_id] = {
                    'cve_id': cve_id,
                    'total_changes': total_changes,
                    'categories': sorted(all_categories),
                    'scope_details': {scope: sorted(cats) for scope, cats in vfc_categories[vfc_id].items()}
                }
                
                # 分析category组合
                categories_tuple = tuple(sorted(all_categories))
                category_combinations[categories_tuple].append(vfc_id)
                
                # 记录单一category的VFCs
                if len(all_categories) == 1:
                    single_category = list(all_categories)[0]
                    single_category_vfcs[single_category].append(vfc_id)
    
    # 输出统计结果
    print("\n" + "="*60)
    print("=== 基于Category的AST统计分析 ===")
    print("="*60)
    
    # 1. 总体category分布
    print("\n--- 总体Category分布 ---")
    for scope, counter in overall_category_stats.items():
        print(f"\n{scope}:")
        for category, count in counter.most_common():
            print(f"  {category}: {count}")
    
    # 2. 单一category的VFCs统计
    print("\n" + "="*60)
    print("=== 单一Category修改的VFCs统计 ===")
    print("="*60)
    
    for category, vfc_list in sorted(single_category_vfcs.items(), key=lambda x: len(x[1]), reverse=True):
        # 按CVE分组统计
        cve_groups = defaultdict(list)
        for vfc_id in vfc_list:
            cve_id = vfc_summary[vfc_id]['cve_id']
            cve_groups[cve_id].append(vfc_id)
        
        print(f"\n'{category}': {len(vfc_list)}个VFCs, 涉及{len(cve_groups)}个CVE")
    
    # 3. Category组合统计
    print("\n" + "="*60)
    print("=== Category组合统计 ===")
    print("="*60)
    
    # 按组合频率排序
    sorted_combinations = sorted(category_combinations.items(), 
                               key=lambda x: len(x[1]), reverse=True)
    
    print(f"\n总共发现 {len(sorted_combinations)} 种不同的category组合")
    print(f"总VFC数: {sum(len(vfc_list) for _, vfc_list in sorted_combinations)}")
    
    print("\n主要组合 (前20种):")
    for i, (categories_tuple, vfc_list) in enumerate(sorted_combinations[:]):
        categories_str = ' + '.join(categories_tuple)
        
        # 按CVE分组
        cve_groups = defaultdict(int)
        for vfc_id in vfc_list:
            cve_id = vfc_summary[vfc_id]['cve_id']
            cve_groups[cve_id] += 1
        
        print(f"{i+1:2d}. [{categories_str}]: {len(vfc_list)}个VFCs, {len(cve_groups)}个CVE")
    
    # 4. 特定category的重叠分析
    print("\n" + "="*60)
    print("=== 特定Category重叠分析 ===")
    print("="*60)
    
    # 分析一些关键categories的重叠情况
    key_categories = ['global_variable_assignment', 'import_statement', 
                     'function_call', 'conditional_logic', 'error_handling',
                     'data_structure_operation', 'string_operation']
    
    for target_category in key_categories:
        # 找到所有包含该category的组合
        related_combinations = []
        total_vfcs_with_category = 0
        total_cves_with_category = set()
        
        for categories_tuple, vfc_list in category_combinations.items():
            if target_category in categories_tuple:
                related_combinations.append((categories_tuple, len(vfc_list)))
                total_vfcs_with_category += len(vfc_list)
                for vfc_id in vfc_list:
                    total_cves_with_category.add(vfc_summary[vfc_id]['cve_id'])
        
        if not related_combinations:
            continue
        
        # 按VFC数量排序
        related_combinations.sort(key=lambda x: x[1], reverse=True)
        
        # 单独使用该category的VFCs数量
        single_count = len(single_category_vfcs.get(target_category, []))
        single_cves = set()
        if target_category in single_category_vfcs:
            for vfc_id in single_category_vfcs[target_category]:
                single_cves.add(vfc_summary[vfc_id]['cve_id'])
        
        print(f"\n'{target_category}':")
        print(f"  总计: {total_vfcs_with_category}个VFCs, {len(total_cves_with_category)}个CVE, {len(related_combinations)}种组合")
        if single_count > 0:
            print(f"  单独使用: {single_count}个VFCs ({single_count/total_vfcs_with_category*100:.1f}%), {len(single_cves)}个CVE")
        print(f"  与其他组合: {total_vfcs_with_category - single_count}个VFCs ({(total_vfcs_with_category - single_count)/total_vfcs_with_category*100:.1f}%)")
    
    # 5. 简要总结
    print("\n" + "="*60)
    print("=== 总结 ===")
    print("="*60)
    
    total_vfcs = len(vfc_summary)
    single_category_total = sum(len(vfc_list) for vfc_list in single_category_vfcs.values())
    multi_category_total = total_vfcs - single_category_total
    
    print(f"\n总VFC数: {total_vfcs}")
    print(f"单一category修改: {single_category_total}个 ({single_category_total/total_vfcs*100:.1f}%)")
    print(f"多category组合修改: {multi_category_total}个 ({multi_category_total/total_vfcs*100:.1f}%)")
    print(f"不同category组合数: {len(sorted_combinations)}")
    
    return {
        'overall_stats': dict(overall_category_stats),
        'vfc_summary': vfc_summary,
        'single_category_vfcs': dict(single_category_vfcs),
        'category_combinations': dict(category_combinations)
    }


def evaluate_vulnerable_functions(cve2advisory):
    #统计每个category的分布
    #以及有多少个VFC成功提取到了vulnerable function
        # 初始化统计变量
    vfc_stats = {
        'total_vfcs': 0,
        'vfcs_with_functions': 0,
        'vfcs_without_functions': 0,
        'total_functions_extracted': 0
    }
    cve_has_vfcs = set()
    no_vfs_cve = set()
    # CVE级别统计
    cve_function_stats = {}  # cve_id -> {vfc_count, functions_count, success_rate}
    vfc_details = {}
    valid_cves = set()
    # 新增：CVE functions_count统计
    cve_functions_distribution = {}  # cve_id -> functions_count
    
    # 新增：vfc_vfs_dict各key的全局统计
    global_vfc_vfs_stats = {
        'old_method_direct_modified_by_deleted_lines': 0,
        'old_method_only_modified_by_added_lines': 0,
        'special_method_only_existed_in_new_file': 0,
        'added_methods_replace_same_name_old_methods': 0,
        'module_vars_impact_functions': 0,
        'class_vars_impact_functions': 0,
        'module_called_functions': 0,
    }
    
    for idxx, (cve_id, advisory) in enumerate(tqdm(cve2advisory.items(), desc="分析代码变更类型")):
        
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        logger.debug(f"Processing {cve_id} ({idxx}/{len(cve2advisory)}), advisory: {advisory['id']}")
        logger.debug(f"Found {len(all_unique_affected_projects)} unique affected projects: {all_unique_affected_projects}")
        
        # 初始化当前CVE的统计
        cve_vfc_count = 0
        cve_functions_count = 0
        cve_successful_vfcs = 0
        
        for package_name, repo_url in all_unique_affected_projects:
            fixing_commits = advisory['fixing_commits'].get(package_name, [])
            if len(fixing_commits) == 0:
                continue
            repo_name = get_repo_name(repo_url)

            logger.debug(f'Processing {repo_url}, {len(fixing_commits)}fixing_commits')
            code_changes_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}.json'
            code_changes_dict_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}_dict.pkl'
            logger.info(f'Code changes for {cve_id}_{repo_name} already exists, skipping...')
            with code_changes_path.open('r') as f:
                commit2methods = json.load(f)
            with code_changes_dict_path.open('rb') as f:
                commit2methods_dict = pickle.load(f)
            if len(commit2methods) ==0:
                no_vfs_cve.add(cve_id)
            
            for fixing_commit in commit2methods:
                cve_vfc_count += 1
                vfc_function_count = 0
                vfc_stats['total_vfcs'] += 1

                vfc_vfs_dict = {
                'old_method_direct_modified_by_deleted_lines':set(),
                'old_method_only_modified_by_added_lines':set(),
                'special_method_only_existed_in_new_file':set(),
                'added_methods_replace_same_name_old_methods':set(),
                'module_vars_impact_functions':set(),
                'class_vars_impact_functions':set(),
                'module_called_functions':set(),
                }
                vfc_id = f"{cve_id}_{fixing_commit.split('/')[-1]}"
                for file_path, (methods) in commit2methods[fixing_commit].items():
                    vfs_dict = commit2methods_dict[fixing_commit][file_path]
                    vfc_function_count += len(methods)
                # 更新统计
                if vfc_function_count > 0:
                    vfc_stats['vfcs_with_functions'] += 1
                    for cate, methods in vfs_dict.items():
                        vfc_vfs_dict[cate].update(methods)
                        # 新增：统计各category的数量
                        global_vfc_vfs_stats[cate] += len(methods)
                    cve_has_vfcs.add(cve_id)
                    cve_successful_vfcs += 1
                else:
                    vfc_stats['vfcs_without_functions'] += 1  
                vfc_stats['total_functions_extracted'] += vfc_function_count
                cve_functions_count += vfc_function_count
                    
                # 记录VFC详细信息
                vfc_details[vfc_id] = {
                    'cve_id': cve_id,
                    'has_functions': vfc_function_count > 0,
                    'function_count': vfc_function_count,
                    'categories': vfc_vfs_dict
                }
        # 保存CVE级别统计
        if cve_vfc_count > 0:

            success_rate = cve_successful_vfcs / cve_vfc_count
            cve_function_stats[cve_id] = {
                'vfc_count': cve_vfc_count,
                'successful_vfcs': cve_successful_vfcs,
                'functions_count': cve_functions_count,
                'success_rate': success_rate
            }
            # 新增：记录CVE的functions_count
            cve_functions_distribution[cve_id] = cve_functions_count
            
        # 输出统计结果
    print("\n" + "="*60)
    print("=== Vulnerable Functions 提取统计 ===")
    print("="*60)
    
    print(f"\n总体统计:")
    print(f"  总VFC数量: {vfc_stats['total_vfcs']}")
    print(f"  成功提取函数的VFC: {vfc_stats['vfcs_with_functions']} ({vfc_stats['vfcs_with_functions']/vfc_stats['total_vfcs']*100:.1f}%)")
    print(f"  未提取到函数的VFC: {vfc_stats['vfcs_without_functions']} ({vfc_stats['vfcs_without_functions']/vfc_stats['total_vfcs']*100:.1f}%)")
    print(f"  总提取函数数量: {vfc_stats['total_functions_extracted']}")
    print(f"  平均每个VFC提取函数数: {vfc_stats['total_functions_extracted']/vfc_stats['total_vfcs']:.2f}")

    print(f"  总CVE数量: {len(cve2advisory)}")
    print(f"  成功提取函数的CVE: {len(cve_has_vfcs)}")
    print(f"  未提取到函数的CVE: {len(cve2advisory)-len(cve_has_vfcs)}")
    
    # 新增：CVE functions_count分布统计
    print(f"\n=== CVE Functions Count 分布统计 ===")
    if cve_functions_distribution:
        functions_counts = list(cve_functions_distribution.values())
        print(f"  CVE functions_count 总计: {sum(functions_counts)}")
        print(f"  平均每个CVE的functions_count: {sum(functions_counts)/len(functions_counts):.2f}")
        print(f"  最大functions_count: {max(functions_counts)}")
        print(f"  最小functions_count: {min(functions_counts)}")
        
        # 新增：按函数数量分区间统计分布比例
        print(f"\n  Functions Count 区间分布:")
        from collections import Counter
        
        # 定义区间
        count_ranges = {
            '0': lambda x: x == 0,
            '1': lambda x: x == 1,
            '2-5': lambda x: 2 <= x <= 5,
            '6-10': lambda x: 6 <= x <= 10,
            '11-20': lambda x: 11 <= x <= 20,
            '21-50': lambda x: 21 <= x <= 50,
            '51-100': lambda x: 51 <= x <= 100,
            '>100': lambda x: x > 100,
        }
        
        total_cves = len(functions_counts)
        range_stats = {}
        
        for range_name, condition in count_ranges.items():
            count = sum(1 for fc in functions_counts if condition(fc))
            percentage = (count / total_cves * 100) if total_cves > 0 else 0
            range_stats[range_name] = {'count': count, 'percentage': percentage}
            print(f"    {range_name} functions: {count} CVEs ({percentage:.1f}%)")
        
        # 新增：精确数量统计（显示前10个最常见的数量）
        print(f"\n  Functions Count 精确数量分布 (Top 10):")
        count_frequency = Counter(functions_counts)
        top_10_counts = count_frequency.most_common(10)
        
        for func_count, cve_count in top_10_counts:
            percentage = (cve_count / total_cves * 100) if total_cves > 0 else 0
            print(f"    {func_count} functions: {cve_count} CVEs ({percentage:.1f}%)")
        
        # 按functions_count排序显示Top 10 CVE
        sorted_cve_functions = sorted(cve_functions_distribution.items(), 
                                    key=lambda x: x[1], reverse=True)[:10]
        print(f"\n  Top 10 CVE (按functions_count排序):")
        for cve_id, func_count in sorted_cve_functions:
            print(f"    {cve_id}: {func_count} functions")
    
    # 新增：VFC级别的函数数量分布统计
    print(f"\n=== VFC Functions Count 分布统计 ===")
    if vfc_details:
        vfc_function_counts = [detail['function_count'] for detail in vfc_details.values()]
        total_vfcs_analyzed = len(vfc_function_counts)
        
        print(f"  VFC functions_count 总计: {sum(vfc_function_counts)}")
        print(f"  平均每个VFC的functions_count: {sum(vfc_function_counts)/len(vfc_function_counts):.2f}")
        print(f"  最大functions_count: {max(vfc_function_counts)}")
        print(f"  最小functions_count: {min(vfc_function_counts)}")
        
        # VFC函数数量区间分布
        print(f"\n  VFC Functions Count 区间分布:")
        vfc_range_stats = {}
        
        for range_name, condition in count_ranges.items():
            count = sum(1 for fc in vfc_function_counts if condition(fc))
            percentage = (count / total_vfcs_analyzed * 100) if total_vfcs_analyzed > 0 else 0
            vfc_range_stats[range_name] = {'count': count, 'percentage': percentage}
            print(f"    {range_name} functions: {count} VFCs ({percentage:.1f}%)")
        
        # VFC精确数量统计
        print(f"\n  VFC Functions Count 精确数量分布 (Top 10):")
        vfc_count_frequency = Counter(vfc_function_counts)
        vfc_top_10_counts = vfc_count_frequency.most_common(10)
        
        for func_count, vfc_count in vfc_top_10_counts:
            percentage = (vfc_count / total_vfcs_analyzed * 100) if total_vfcs_analyzed > 0 else 0
            print(f"    {func_count} functions: {vfc_count} VFCs ({percentage:.1f}%)")
    
    # 新增：vfc_vfs_dict各key数量统计
    print(f"\n=== VFC VFS Dict 各Category统计 ===")
    total_vfs_functions = sum(global_vfc_vfs_stats.values())
    print(f"  VFS函数总数: {total_vfs_functions}")
    
    for category, count in sorted(global_vfc_vfs_stats.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_vfs_functions * 100) if total_vfs_functions > 0 else 0
        print(f"  {category}: {count} ({percentage:.1f}%)")

    print(f"\n=== CVE级别统计 (Top 10 by success rate) ===")
    sorted_cves = sorted(cve_function_stats.items(), 
                        key=lambda x: x[1]['success_rate'], reverse=True)[:15]
    for cve_id, stats in sorted_cves:
        print(f"{cve_id}: {stats['successful_vfcs']}/{stats['vfc_count']} VFCs成功 "
              f"({stats['success_rate']*100:.1f}%), 提取{stats['functions_count']}个函数")
    
    # 返回统计结果（包含新增的分布统计）
    return {
        'vfc_stats': vfc_stats,
        'cve_function_stats': cve_function_stats,
        'cve_functions_distribution': cve_functions_distribution,
        'cve_functions_range_stats': range_stats if 'range_stats' in locals() else {},
        'vfc_functions_range_stats': vfc_range_stats if 'vfc_range_stats' in locals() else {},
        'global_vfc_vfs_stats': global_vfc_vfs_stats,
        'vfc_details': vfc_details,
        'cve_has_vfcs': cve_has_vfcs
    }
    
def ablation_study_vulnerable_functions(cve2advisory):
    """
    消融研究：统计禁用某些category后，CVE是否还能提取到函数
    测试每个category对函数提取的贡献度
    """
    print("\n" + "="*80)
    print("=== Vulnerable Functions Ablation Study ===")
    print("="*80)
    
    # 所有可能的category
    all_categories = [
        'old_method_direct_modified_by_deleted_lines',
        'old_method_only_modified_by_added_lines', 
        'special_method_only_existed_in_new_file',
        'added_methods_replace_same_name_old_methods',
        'module_vars_impact_functions',
        'class_vars_impact_functions',
        'module_called_functions'
    ]
    
    # 基线统计：使用所有category
    baseline_stats = get_cve_function_stats_with_categories(cve2advisory, all_categories)
    
    print(f"\n=== 基线统计 (使用所有categories) ===")
    print(f"成功提取函数的CVE数量: {baseline_stats['successful_cves']}")
    print(f"总提取函数数量: {baseline_stats['total_functions']}")
    print(f"平均每个CVE提取函数数: {baseline_stats['avg_functions_per_cve']:.2f}")
    
    # 单个category消融研究
    print(f"\n=== 单个Category消融研究 ===")
    print(f"{'Category':<45} {'Cul. CVE':<5} {'Cul. Func.':<5} {'Impact CVE':<5} {'Impact CVE':<5} {'Impact Func.':<5} {'Coverage':<10}")
    print("-" * 105)
    
    single_ablation_results = {}
    
    for category in all_categories:
        # 禁用当前category
        remaining_categories = [c for c in all_categories if c != category]
        stats = get_cve_function_stats_with_categories(cve2advisory, remaining_categories)
        
        # 计算影响
        affected_cves = baseline_stats['successful_cves'] - stats['successful_cves']
        affected_functions = baseline_stats['total_functions'] - stats['total_functions']
        impact_rate = (affected_functions / baseline_stats['total_functions'] * 100) if baseline_stats['total_functions'] > 0 else 0
        
        # 计算该category涉及的总CVE数量
        category_total_cves = get_category_total_cves(cve2advisory, category)
        
        single_ablation_results[category] = {
            'remaining_successful_cves': stats['successful_cves'],
            'remaining_functions': stats['total_functions'],
            'total_cves': category_total_cves,
            'affected_cves': affected_cves,
            'affected_functions': affected_functions,
            'impact_rate': impact_rate
        }
        
        print(f"{category:<45} {stats['successful_cves']:<10} {stats['total_functions']:<10} {category_total_cves:<10} {affected_cves:<10} {affected_functions:<10} {impact_rate:<9.1f}%")
    
    # 多个category组合消融研究
    print(f"\n=== 多Category组合消融研究 ===")
    
    # 测试一些重要的组合
    important_combinations = [
        # 保留所有categories（对照组）
        [],
        
        # 禁用所有function-level categories
        ['old_method_direct_modified_by_deleted_lines', 'old_method_only_modified_by_added_lines', 
         'special_method_only_existed_in_new_file', 'added_methods_replace_same_name_old_methods'],
        
        # 禁用所有module/class-level categories  
        ['module_vars_impact_functions', 'class_vars_impact_functions'],
        
        # 禁用最重要的两个categories
        ['old_method_direct_modified_by_deleted_lines', 'old_method_only_modified_by_added_lines'],
        
        # 只保留direct的category
        ['special_method_only_existed_in_new_file',
         'added_methods_replace_same_name_old_methods', 'module_vars_impact_functions', 
         'class_vars_impact_functions', 'module_called_functions',
         'old_method_only_modified_by_added_lines'],
         # 只保留only的category
        ['special_method_only_existed_in_new_file',
         'added_methods_replace_same_name_old_methods', 'module_vars_impact_functions', 
         'class_vars_impact_functions', 'module_called_functions',
         'old_method_direct_modified_by_deleted_lines'],
        
        # 只保留两个最基本的method categories
        ['special_method_only_existed_in_new_file', 'added_methods_replace_same_name_old_methods',
         'module_vars_impact_functions', 'class_vars_impact_functions', 'module_called_functions'],

        # 只保留module
        [
        'old_method_direct_modified_by_deleted_lines',
        'old_method_only_modified_by_added_lines', 
        'special_method_only_existed_in_new_file',
        'added_methods_replace_same_name_old_methods',
        'class_vars_impact_functions',
        'module_called_functions'
        ],
        # 只保留class
        [
        'old_method_direct_modified_by_deleted_lines',
        'old_method_only_modified_by_added_lines', 
        'special_method_only_existed_in_new_file',
        'added_methods_replace_same_name_old_methods',
        'module_vars_impact_functions',
        'module_called_functions'
        ],
        # 禁用所有module/class-level categories外
        [
        'old_method_direct_modified_by_deleted_lines',
        'old_method_only_modified_by_added_lines', 
        'special_method_only_existed_in_new_file',
        'added_methods_replace_same_name_old_methods',
        'module_called_functions'
        ],
        [
        'module_called_functions'
        ]
    
    ]
    
    combination_names = [
        "所有categories",
        "禁用function-level",
        "禁用module/class-level", 
        "禁用two important",
        "禁用direct_modified外",
        "禁用only_added外",
        "禁用two important外",
        "禁用module外",
        "禁用class外",
        "禁用module/class-level外", 
        "禁用module_called", 


    ]
    
    print(f"{'组合描述':<20} {'成功CVE':<10} {'函数数':<8} {'影响CVE':<10} {'影响函数':<6} {'影响率':<10}")
    print("-" * 90)
    
    combination_results = {} 
    
    for i, disabled_categories in enumerate(important_combinations):
        remaining_categories = [c for c in all_categories if c not in disabled_categories]
        stats = get_cve_function_stats_with_categories(cve2advisory, remaining_categories)
        
        affected_cves = baseline_stats['successful_cves'] - stats['successful_cves']
        affected_functions = baseline_stats['total_functions'] - stats['total_functions']
        impact_rate = (affected_functions / baseline_stats['total_functions'] * 100) if baseline_stats['total_functions'] > 0 else 0
        
        combination_results[combination_names[i]] = {
            'disabled_categories': disabled_categories,
            'remaining_successful_cves': stats['successful_cves'],
            'remaining_functions': stats['total_functions'],
            'affected_cves': affected_cves,
            'affected_functions': affected_functions,
            'impact_rate': impact_rate
        }
        
        print(f"{combination_names[i]:<25} {stats['successful_cves']:<10} {stats['total_functions']:<10} {affected_cves:<10} {affected_functions:<10} {impact_rate:<9.1f}%")
    
    # Category重要性排序
    print(f"\n=== Category重要性排序 (按影响函数数) ===")
    sorted_categories = sorted(single_ablation_results.items(), 
                             key=lambda x: x[1]['affected_functions'], reverse=True)
    
    for i, (category, result) in enumerate(sorted_categories, 1):
        print(f"{i:2d}. {category}: 影响{result['affected_functions']}个函数 ({result['impact_rate']:.1f}%), {result['affected_cves']}个CVE")
    
    # 详细分析：找出受影响最大的CVE
    print(f"\n=== 受影响最大的CVE分析 ===")
    
    # 分析禁用最重要category时受影响的CVE
    most_important_category = sorted_categories[0][0]
    print(f"\n禁用最重要的category '{most_important_category}' 时:")
    
    affected_cves_detail = get_affected_cves_detail(cve2advisory, most_important_category)
    
    print(f"受影响的CVE数量: {len(affected_cves_detail)}")
    if len(affected_cves_detail) > 0:
        print(f"\nTop 10 受影响最大的CVE:")
        sorted_affected = sorted(affected_cves_detail.items(), 
                               key=lambda x: x[1]['lost_functions'], reverse=True)[:10]
        
        for cve_id, detail in sorted_affected:
            print(f"  {cve_id}: 失去{detail['lost_functions']}个函数 (原有{detail['original_functions']}个)")
    
    return {
        'baseline_stats': baseline_stats,
        'single_ablation_results': single_ablation_results,
        'combination_results': combination_results,
        'category_importance_ranking': sorted_categories
    }

def get_category_total_cves(cve2advisory, target_category):
    """
    计算特定category涉及的总CVE数量
    """
    category_cves = set()
    
    for cve_id, advisory in cve2advisory.items():
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        
        for package_name, repo_url in all_unique_affected_projects:
            fixing_commits = advisory['fixing_commits'].get(package_name, [])
            if len(fixing_commits) == 0:
                continue
                
            repo_name = get_repo_name(repo_url)
            code_changes_dict_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}_dict.pkl'
            
            if not code_changes_dict_path.exists():
                continue
                
            try:
                with code_changes_dict_path.open('rb') as f:
                    commit2methods_dict = pickle.load(f)
                
                # 检查该CVE是否使用了目标category
                for fixing_commit in commit2methods_dict:
                    for file_path, vfs_dict in commit2methods_dict[fixing_commit].items():
                        if target_category in vfs_dict and len(vfs_dict[target_category]) > 0:
                            category_cves.add(cve_id)
                            break
                    if cve_id in category_cves:
                        break
                        
            except Exception as e:
                logger.warning(f"Error processing {cve_id}_{repo_name}: {e}")
                continue
    
    return len(category_cves)
def get_cve_function_stats_with_categories(cve2advisory, enabled_categories):
    """
    使用指定的categories计算CVE函数提取统计
    """
    successful_cves = 0
    total_functions = 0
    cve_function_counts = {}
    successful_vfcs=0
    
    for cve_id, advisory in cve2advisory.items():
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        cve_functions_count = 0
        
        for package_name, repo_url in all_unique_affected_projects:
            fixing_commits = advisory['fixing_commits'].get(package_name, [])
            if len(fixing_commits) == 0:
                continue
                
            repo_name = get_repo_name(repo_url)
            code_changes_dict_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}_dict.pkl'
            
            if not code_changes_dict_path.exists():
                continue
                
            try:
                with code_changes_dict_path.open('rb') as f:
                    commit2methods_dict = pickle.load(f)
                
                for fixing_commit in commit2methods_dict:
                    vfc_has_vf = False
                    for file_path, vfs_dict in commit2methods_dict[fixing_commit].items():
                        # 只统计启用的categories中的函数
                        for category in enabled_categories:
                            if category in vfs_dict:
                                cve_functions_count += len(vfs_dict[category])
                                
                                if vfs_dict[category]:
                                    vfc_has_vf=True
                    if vfc_has_vf:
                        successful_vfcs +=1
            except Exception as e:
                logger.warning(f"Error processing {cve_id}_{repo_name}: {e}")
                continue
        
        if cve_functions_count > 0:
            successful_cves += 1
            total_functions += cve_functions_count
            cve_function_counts[cve_id] = cve_functions_count
    
    avg_functions_per_cve = total_functions / successful_cves if successful_cves > 0 else 0
    
    return {
        'successful_cves': successful_cves,
        'successful_vfcs': successful_vfcs,
        'total_functions': total_functions,
        'avg_functions_per_cve': avg_functions_per_cve,
        'cve_function_counts': cve_function_counts
    }


def get_category_total_cves(cve2advisory, category):
    """
    计算特定category涉及的总CVE数量
    """
    category_cves = set()
    
    for cve_id, advisory in cve2advisory.items():
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        
        for package_name, repo_url in all_unique_affected_projects:
            fixing_commits = advisory['fixing_commits'].get(package_name, [])
            if len(fixing_commits) == 0:
                continue
                
            repo_name = get_repo_name(repo_url)
            code_changes_dict_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}_dict.pkl'
            
            if not code_changes_dict_path.exists():
                continue
                
            try:
                with code_changes_dict_path.open('rb') as f:
                    commit2methods_dict = pickle.load(f)
                
                for fixing_commit in commit2methods_dict:
                    for file_path, vfs_dict in commit2methods_dict[fixing_commit].items():
                        # 检查该category是否有函数
                        if category in vfs_dict and len(vfs_dict[category]) > 0:
                            category_cves.add(cve_id)
                            break
                    if cve_id in category_cves:
                        break
                        
            except Exception as e:
                logger.warning(f"Error processing {cve_id}_{repo_name}: {e}")
                continue
                
            if cve_id in category_cves:
                break
    
    return len(category_cves)


def get_affected_cves_detail(cve2advisory, disabled_category):
    """
    获取禁用特定category后受影响的CVE详细信息
    """
    all_categories = [
        'old_method_direct_modified_by_deleted_lines',
        'old_method_only_modified_by_added_lines', 
        'special_method_only_existed_in_new_file',
        'added_methods_replace_same_name_old_methods',
        'module_vars_impact_functions',
        'class_vars_impact_functions',
        'module_called_functions'
    ]
    
    # 获取原始统计
    original_stats = get_cve_function_stats_with_categories(cve2advisory, all_categories)
    
    # 获取禁用category后的统计
    remaining_categories = [c for c in all_categories if c != disabled_category]
    new_stats = get_cve_function_stats_with_categories(cve2advisory, remaining_categories)
    
    # 找出受影响的CVE
    affected_cves = {}
    
    for cve_id in original_stats['cve_function_counts']:
        original_count = original_stats['cve_function_counts'][cve_id]
        new_count = new_stats['cve_function_counts'].get(cve_id, 0)
        
        if new_count < original_count:
            affected_cves[cve_id] = {
                'original_functions': original_count,
                'remaining_functions': new_count,
                'lost_functions': original_count - new_count
            }
    
    return affected_cves

def cumulative_strategy_analysis(cve2advisory):
    """
    累积策略分析：逐步添加不同类型的category，观察效果的累积变化
    包括CVE和VFC的影响统计
    """
    print("\n" + "="*80)
    print("=== 累积策略分析 ===")
    print("="*80)
    
    # 定义累积策略顺序（基于图表）
    cumulative_strategies = [
        {
            'name': 'Deleted Lines',
            'categories': ['old_method_direct_modified_by_deleted_lines']
        },
        {
            'name': '+ Added Lines',
            'categories': ['old_method_direct_modified_by_deleted_lines', 'old_method_only_modified_by_added_lines']
        },
        {
            'name': '+ Special Methods',
            'categories': ['old_method_direct_modified_by_deleted_lines', 'old_method_only_modified_by_added_lines', 
                          'special_method_only_existed_in_new_file']
        },
        {
            'name': '+ Module Variables',
            'categories': ['old_method_direct_modified_by_deleted_lines', 'old_method_only_modified_by_added_lines',
                          'special_method_only_existed_in_new_file', 'module_vars_impact_functions']
        },
        {
            'name': '+ Class Variables',
            'categories': ['old_method_direct_modified_by_deleted_lines', 'old_method_only_modified_by_added_lines',
                          'special_method_only_existed_in_new_file', 'module_vars_impact_functions',
                          'class_vars_impact_functions']
        },
        {
            'name': '+ Function Replacement',
            'categories': ['old_method_direct_modified_by_deleted_lines', 'old_method_only_modified_by_added_lines',
                          'special_method_only_existed_in_new_file', 'module_vars_impact_functions',
                          'class_vars_impact_functions', 'added_methods_replace_same_name_old_methods']
        },
        {
            'name': '+ Module-level Calls',
            'categories': ['old_method_direct_modified_by_deleted_lines', 'old_method_only_modified_by_added_lines',
                          'special_method_only_existed_in_new_file', 'module_vars_impact_functions',
                          'class_vars_impact_functions', 'added_methods_replace_same_name_old_methods',
                          'module_called_functions']
        }
    ]
    
    print(f"{'Strategy':<25} {'成功CVE':<6}{'成功VFC':<6} {'函数数':<6} {'影响CVE':<6} {'影响VFC':<6} {'CVE增量':<6} {'函数增量':<6} {'累积率':<8}")
    print("-" * 105)
    
    previous_stats = {'successful_cves': 0, 'total_functions': 0}
    cumulative_results = []
    
    # 计算总的CVE和VFC数量作为基准
    total_cves_with_functions = len([cve for cve, advisory in cve2advisory.items() 
                                   if any(len(commits) > 0 for commits in advisory['fixing_commits'].values())])
    total_vfcs = sum(len(commits) for advisory in cve2advisory.values() 
                    for commits in advisory['fixing_commits'].values())
    
    for i, strategy in enumerate(cumulative_strategies):
        # 计算当前策略的统计
        stats = get_cve_function_stats_with_categories(cve2advisory, strategy['categories'])
        
        # 计算增量
        cve_increment = stats['successful_cves'] - previous_stats['successful_cves']
        function_increment = stats['total_functions'] - previous_stats['total_functions']
        
        # 计算影响的CVE和VFC数量
        affected_cves, affected_vfcs = get_strategy_affected_counts(cve2advisory, strategy['categories'])
        
        cumulative_results.append({
            'name': strategy['name'],
            'categories': strategy['categories'],
            'successful_cves': stats['successful_cves'],
            'successful_vfcs': stats['successful_vfcs'],
            'total_functions': stats['total_functions'],
            'affected_cves': affected_cves,
            'affected_vfcs': affected_vfcs,
            'cve_increment': cve_increment,
            'function_increment': function_increment
        })
        
        previous_stats = stats
    
    # 计算累积率（相对于最终完整策略）
    final_stats = cumulative_results[-1]
    
    for result in cumulative_results:
        cumulative_rate = (result['total_functions'] / final_stats['total_functions'] * 100) if final_stats['total_functions'] > 0 else 0
        result['cumulative_rate'] = cumulative_rate
        
        print(f"{result['name']:<25} {result['successful_cves']:<8} {result['successful_vfcs']:<8} {result['total_functions']:<8} {result['affected_cves']:<8} {result['affected_vfcs']:<8} {result['cve_increment']:<8} {result['function_increment']:<8} {cumulative_rate:<7.1f}%")
    
    # 详细的贡献度分析
    print(f"\n=== 策略贡献度分析 ===")
    print(f"{'策略':<20} {'CVE贡献':<8} {'函数贡献':<6} {'CVE覆盖率':<6} {'VFC覆盖率':<6} {'函数贡献率':<10}")
    print("-" * 85)
    
    for i, result in enumerate(cumulative_results):
        if i == 0:
            cve_contribution_rate = (result['cve_increment'] / final_stats['successful_cves'] * 100) if final_stats['successful_cves'] > 0 else 0
            function_contribution_rate = (result['function_increment'] / final_stats['total_functions'] * 100) if final_stats['total_functions'] > 0 else 0
        else:
            cve_contribution_rate = (result['cve_increment'] / final_stats['successful_cves'] * 100) if final_stats['successful_cves'] > 0 else 0
            function_contribution_rate = (result['function_increment'] / final_stats['total_functions'] * 100) if final_stats['total_functions'] > 0 else 0
        
        cve_coverage_rate = (result['affected_cves'] / total_cves_with_functions * 100) if total_cves_with_functions > 0 else 0
        vfc_coverage_rate =result['affected_vfcs']
        
        print(f"{result['name']:<25} {result['cve_increment']:<8} {result['function_increment']:<8} {cve_coverage_rate:<9.1f}% {vfc_coverage_rate:<9.1f}% {function_contribution_rate:<9.1f}%")
    
    # 关键策略识别
    print(f"\n=== 关键策略识别 ===")
    
    # 找出贡献最大的策略
    max_cve_contribution = max(cumulative_results, key=lambda x: x['cve_increment'])
    max_function_contribution = max(cumulative_results, key=lambda x: x['function_increment'])
    max_coverage = max(cumulative_results, key=lambda x: x['affected_cves'])
    
    print(f"CVE贡献最大的策略: {max_cve_contribution['name']} (+{max_cve_contribution['cve_increment']} CVE)")
    print(f"函数贡献最大的策略: {max_function_contribution['name']} (+{max_function_contribution['function_increment']} 函数)")
    print(f"CVE覆盖最广的策略: {max_coverage['name']} (影响{max_coverage['affected_cves']}个CVE, {max_coverage['affected_vfcs']}个VFC)")
    
    # 计算前两个策略的覆盖率
    if len(cumulative_results) >= 2:
        first_two_coverage = (cumulative_results[1]['total_functions'] / final_stats['total_functions'] * 100) if final_stats['total_functions'] > 0 else 0
        print(f"\n前两个基础策略覆盖率: {first_two_coverage:.1f}%")
        print(f"前两个基础策略影响: {cumulative_results[1]['affected_cves']}个CVE, {cumulative_results[1]['affected_vfcs']}个VFC")
    
    return {
        'cumulative_results': cumulative_results,
        'final_stats': final_stats,
        'total_stats': {'total_cves': total_cves_with_functions, 'total_vfcs': total_vfcs},
        'key_insights': {
            'max_cve_contributor': max_cve_contribution['name'],
            'max_function_contributor': max_function_contribution['name'],
            'max_coverage_strategy': max_coverage['name']
        }
    }


def get_strategy_affected_counts(cve2advisory, target_categories):
    """
    计算特定策略组合影响的CVE和VFC数量
    """
    affected_cves = set()
    affected_vfcs = 0
    
    for cve_id, advisory in cve2advisory.items():
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        cve_has_target_categories = False
        
        for package_name, repo_url in all_unique_affected_projects:
            fixing_commits = advisory['fixing_commits'].get(package_name, [])
            if len(fixing_commits) == 0:
                continue
                
            repo_name = get_repo_name(repo_url)
            code_changes_dict_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}_dict.pkl'
            
            if not code_changes_dict_path.exists():
                continue
                
            try:
                with code_changes_dict_path.open('rb') as f:
                    commit2methods_dict = pickle.load(f)
                
                # 检查该CVE的VFC是否使用了目标categories
                for fixing_commit in commit2methods_dict:
                    vfc_has_target = False
                    for file_path, vfs_dict in commit2methods_dict[fixing_commit].items():
                        for category in target_categories[-1:]:
                            if category in vfs_dict and len(vfs_dict[category]) > 0:
                                vfc_has_target = True
                                cve_has_target_categories = True
                                break
                        if vfc_has_target:
                            break
                    
                    if vfc_has_target:
                        affected_vfcs += 1
                        
            except Exception as e:
                logger.warning(f"Error processing {cve_id}_{repo_name}: {e}")
                continue
        
        if cve_has_target_categories:
            affected_cves.add(cve_id)
    
    return len(affected_cves), affected_vfcs


def filter_cves_by_vulnerable_functions(cve2advisory, 
                                         min_functions=None, 
                                         max_functions=None,
                                         min_vfcs=None,
                                         max_vfcs=None,
                                         require_specific_categories=None,
                                         exclude_categories=None,
                                         data_dir=None):
    """
    根据vulnerable function的数量和类型过滤CVE
    
    Args:
        cve2advisory (dict): CVE到advisory信息的映射字典
        min_functions (int, optional): 最小函数数量阈值
        max_functions (int, optional): 最大函数数量阈值
        min_vfcs (int, optional): 最小VFC数量阈值
        max_vfcs (int, optional): 最大VFC数量阈值
        require_specific_categories (list, optional): 必须包含的vulnerability类型
        exclude_categories (list, optional): 需要排除的vulnerability类型
        data_dir (Path, optional): 数据目录路径，默认使用CODE_CHANGES_DIR_DATE
        
    Returns:
        dict: 过滤后的cve2advisory字典
        dict: 统计信息包含每个CVE的详细函数信息
    """

    
    if data_dir is None:
        # 假设CODE_CHANGES_DIR_DATE已定义
        data_dir = CODE_CHANGES_DIR_DATE
    
    filtered_cves = {}
    cve_statistics = {}
    
    # 可用的vulnerability categories
    all_categories = [
        'old_method_direct_modified_by_deleted_lines',
        'old_method_only_modified_by_added_lines', 
        'special_method_only_existed_in_new_file',
        'added_methods_replace_same_name_old_methods',
        'module_vars_impact_functions',
        'class_vars_impact_functions',
        'module_called_functions'
    ]
    
    if require_specific_categories:
        require_specific_categories = set(require_specific_categories)
    if exclude_categories:
        exclude_categories = set(exclude_categories)
    
    for cve_id, advisory in cve2advisory.items():
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        
        # 统计当前CVE的信息
        cve_total_functions = 0
        cve_total_vfcs = 0
        cve_categories_used = set()
        cve_category_counts = defaultdict(int)
        cve_details = {
            'packages': {},
            'total_functions': 0,
            'total_vfcs': 0,
            'categories_used': set(),
            'category_counts': defaultdict(int)
        }
        
        for package_name, repo_url in all_unique_affected_projects:
            fixing_commits = advisory['fixing_commits'].get(package_name, [])
            if len(fixing_commits) == 0:
                continue
                
            repo_name = get_repo_name(repo_url)
            code_changes_path = data_dir / f'{cve_id}_{repo_name}.json'
            code_changes_dict_path = data_dir / f'{cve_id}_{repo_name}_dict.pkl'
            
            if not code_changes_path.exists() or not code_changes_dict_path.exists():
                continue
            
            try:
                # 读取函数信息
                with code_changes_path.open('r') as f:
                    commit2methods = json.load(f)
                
                # 读取详细的vulnerability类型信息
                with code_changes_dict_path.open('rb') as f:
                    commit2methods_dict = pickle.load(f)
                
                package_functions = 0
                package_vfcs = len(commit2methods)
                package_categories = set()
                
                for fixing_commit in commit2methods:
                    for file_path, methods in commit2methods[fixing_commit].items():
                        package_functions += len(methods)
                    
                    # 统计vulnerability类型
                    if fixing_commit in commit2methods_dict:
                        for file_path, vfs_dict in commit2methods_dict[fixing_commit].items():
                            for category, functions in vfs_dict.items():
                                if len(functions) > 0:
                                    package_categories.add(category)
                                    cve_categories_used.add(category)
                                    cve_category_counts[category] += len(functions)
                
                cve_total_functions += package_functions
                cve_total_vfcs += package_vfcs
                
                cve_details['packages'][package_name] = {
                    'functions': package_functions,
                    'vfcs': package_vfcs,
                    'categories': list(package_categories)
                }
                
            except Exception as e:
                print(f"Error processing {cve_id}_{repo_name}: {e}")
                continue
        
        # 更新CVE统计信息
        cve_details['total_functions'] = cve_total_functions
        cve_details['total_vfcs'] = cve_total_vfcs
        cve_details['categories_used'] = list(cve_categories_used)
        cve_details['category_counts'] = dict(cve_category_counts)
        
        cve_statistics[cve_id] = cve_details
        
        # 应用过滤条件
        should_include = True
        
        # 检查函数数量条件
        if min_functions is not None and cve_total_functions < min_functions:
            should_include = False
        if max_functions is not None and cve_total_functions > max_functions:
            should_include = False
            
        # 检查VFC数量条件
        if min_vfcs is not None and cve_total_vfcs < min_vfcs:
            should_include = False
        if max_vfcs is not None and cve_total_vfcs > max_vfcs:
            should_include = False
        
        # 检查必需的categories
        if require_specific_categories is not None:
            if not require_specific_categories.issubset(cve_categories_used):
                should_include = False
        
        # 检查排除的categories
        if exclude_categories is not None:
            if exclude_categories.intersection(cve_categories_used):
                should_include = False
        
        # 如果通过所有过滤条件，则包含该CVE
        if should_include:
            filtered_cves[cve_id] = advisory
    
    return filtered_cves, cve_statistics


def print_filter_statistics(original_cve2advisory, filtered_cve2advisory, cve_statistics):
    """
    打印过滤结果的统计信息
    
    Args:
        original_cve2advisory (dict): 原始CVE字典
        filtered_cve2advisory (dict): 过滤后的CVE字典
        cve_statistics (dict): CVE统计信息
    """
    print(f"\n=== CVE过滤结果统计 ===")
    print(f"原始CVE数量: {len(original_cve2advisory)}")
    print(f"过滤后CVE数量: {len(filtered_cve2advisory)}")
    print(f"保留比例: {len(filtered_cve2advisory)/len(original_cve2advisory)*100:.1f}%")
    
    # if len(filtered_cve2advisory) > 0:
    #     # 统计过滤后CVE的函数分布
    #     function_counts = [stats['total_functions'] for stats in cve_statistics.values() 
    #                       if stats['total_functions'] > 0]
    #     vfc_counts = [stats['total_vfcs'] for stats in cve_statistics.values() 
    #                  if stats['total_vfcs'] > 0]
        
    #     print(f"\n=== 过滤后CVE的函数分布 ===")
    #     if function_counts:
    #         print(f"总函数数: {sum(function_counts)}")
    #         print(f"平均函数数/CVE: {sum(function_counts)/len(function_counts):.2f}")
    #         print(f"函数数范围: {min(function_counts)} - {max(function_counts)}")
        
    #     if vfc_counts:
    #         print(f"总VFC数: {sum(vfc_counts)}")
    #         print(f"平均VFC数/CVE: {sum(vfc_counts)/len(vfc_counts):.2f}")
    #         print(f"VFC数范围: {min(vfc_counts)} - {max(vfc_counts)}")
        
    #     # 统计vulnerability categories分布
    #     all_categories = set()
    #     category_usage = defaultdict(int)
        
    #     for stats in cve_statistics.values():
    #         for category in stats['categories_used']:
    #             all_categories.add(category)
    #             category_usage[category] += 1
        
    #     print(f"\n=== Vulnerability Categories分布 ===")
    #     for category, count in sorted(category_usage.items(), key=lambda x: x[1], reverse=True):
    #         percentage = count / len(filtered_cve2advisory) * 100
    #         print(f"{category}: {count} CVEs ({percentage:.1f}%)")


# 使用示例
def example_usage():
    """
    使用示例
    """
    # 示例1: 过滤函数数量在5-50之间的CVE
    filtered_cves_1, stats_1 = filter_cves_by_vulnerable_functions(
        cve2advisory, 
        min_functions=1, 
        max_functions=1
    )
    print("示例1: 函数数量1")
    print_filter_statistics(cve2advisory, filtered_cves_1, stats_1)
    with open(DATA_DIR/SUFFIX/'cve2advisory_only_one_VF.pkl', 'wb') as f:
        pickle.dump(filtered_cves_1,f)
    assert False
    
    # 示例2: 只包含module变量影响的CVE
    filtered_cves_2, stats_2 = filter_cves_by_vulnerable_functions(
        cve2advisory,
        require_specific_categories=['module_vars_impact_functions']
    )
    print("\n示例2: 只包含module变量影响")
    print_filter_statistics(cve2advisory, filtered_cves_2, stats_2)
    
   
    # 示例4: 高影响CVE (多个VFC且函数数量较多)
    filtered_cves_4, stats_4 = filter_cves_by_vulnerable_functions(
        cve2advisory,
        min_functions=10,
        min_vfcs=2
    )
    print("\n示例4: 高影响CVE (>=10函数且>=2VFC)")
    print_filter_statistics(cve2advisory, filtered_cves_4, stats_4)
if __name__ == '__main__':


    # cve2advisory = read_cve2advisory(small=False)
    cve2advisory = read_cve2advisory(valid_py_cve=False,specific_date=True, cve_has_vfc=True)


    CASE = ['CVE-2023-34239']
    # cve2advisory = {cve_id:advisory for cve_id, advisory in cve2advisory.items() if cve_id in CASE}
    vfc_count = 0
    cve_count = 0
    for cve_id, advisory in cve2advisory.items():
        if len(advisory['fixing_commits'].items()):
            cve_count+=1
        for pkg,vfcs in advisory['fixing_commits'].items():
            vfc_count += len(vfcs)
    logger.info(f"vfc_count: {vfc_count}, cve_count: {cve_count}")

   
    samples = list(cve2advisory.keys())[:]
    cve2advisory = {k:v for k,v in cve2advisory.items() if k in samples}
    
    get_code_change_scope_for_all(cve2advisory)
    scoped_cves_file = SCOPE_CVE_CACHE_DIR_DATE/'scoped_cves.json'
    if not scoped_cves_file.parent.exists():
        scoped_cves_file.parent.mkdir(parents=True, exist_ok=True)
    if not scoped_cves_file.exists() or False:
        module_cves, class_cves, module_class_cves = evaluate_code_change_scope(cve2advisory)
        
        function_cves = set(cve2advisory.keys()) - (module_cves| class_cves| module_class_cves)
        
        scoped_cves = {
                'function': list(function_cves),
                'module':list(module_cves),
                'class':list(class_cves),
                'module_class':list(module_class_cves)
            }
            
        with open(scoped_cves_file,'w')  as f:
            json.dump(scoped_cves,f)
    else:
         with open(scoped_cves_file,'r')  as f:
            scoped_cves = json.load(f)
    module_cves, class_cves, module_class_cves, function_cves = scoped_cves['module'],scoped_cves['class'],scoped_cves['module_class'],scoped_cves['function']
    logger.info(f"ONLY module-scope:{len(module_cves)}, ONLYclass-scope:{len(class_cves)}, ONLYclass_module-scope:{len(module_class_cves)}, function-scope CVE cnt:{len(function_cves)}")


    # study_code_change_ast_type(cve2advisory, module_cves, class_cves, module_class_cves)

    # assert False
    # small = ['CVE-2023-2228']
    # cve2advisory = {k:v for k,v in cve2advisory.items() if k in small}
    get_vulnerable_functions_for_all(cve2advisory)
    # assert False
    cve_function_stats = evaluate_vulnerable_functions(cve2advisory)
    # valid_cves = cve_function_stats['cve_has_vfcs']
    # has_vf_cve2advisory = {cve_id:advisory for cve_id, advisory in cve2advisory.items() if cve_id in valid_cves}
    # with open(CVE2ADVISORY_VF_FILE_DATE,'wb') as f:
    #     pickle.dump(has_vf_cve2advisory, f)

        
    # ablation_study_vulnerable_functions(cve2advisory)
    # cumulative_strategy_analysis(cve2advisory)

    # 示例1: 过滤函数数量在5-50之间的CVE
    for max_functions in [1,3,5,7,9]:
        filtered_cves_1, stats_1 = filter_cves_by_vulnerable_functions(
            cve2advisory, 
            min_functions=1, 
            max_functions=max_functions
        )
        print(f"函数数量{max_functions}")
        print_filter_statistics(cve2advisory, filtered_cves_1, stats_1)
        if max_functions == 1:
            with open(DATA_DIR/SUFFIX/'cve2advisory_only_one_VF.pkl', 'wb') as f:
                pickle.dump(filtered_cves_1,f)



    
