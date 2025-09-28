# Copyright 2018 Davide Spadini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This module contains all the classes regarding a specific commit, such as
Commit, Modification,
ModificationType and Method.
"""

import tempfile
import json
import logging
from datetime import datetime
from enum import Enum
from pathlib import Path
from tkinter import Y
from typing import Any, List, Set, Dict, Tuple, Optional, Union
from types import SimpleNamespace
# import lizard
# import lizard_languages
import hashlib
import ast
import sys
import subprocess
from copy import deepcopy

from numpy.ma import var
sys.path.append('/Users/keviny/Desktop/Research/ANU/Projects/PyVul/')

from git import Diff, Git, NULL_TREE
from git.objects import Commit as GitCommit
from git.objects.base import IndexObject

from pydriller.domain.developer import Developer
import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Query
PY_LANGUAGE = Language(tspython.language())

from collections import defaultdict
from data_collection.constant import DIFF_CACHE_DIR, DIFF_CACHE_DIR_DATE


from data_collection.logger import logger
from data_collection.constant import exclude_dirs,exclude_suffixes


class ModificationType(Enum):
    """
    Type of Modification. Can be ADD, COPY, RENAME, DELETE, MODIFY or UNKNOWN.
    """

    ADD = 1
    COPY = 2
    RENAME = 3
    DELETE = 4
    MODIFY = 5
    UNKNOWN = 6

class Method:
    """
    This class represents a method in a class. Contains various information
    extracted through Tree-sitter.
    """

    def __init__(self, func: Any) -> None:
        """
        Initialize a method object. 
        """

        self.name: str = func.name
        self.long_name: str = func.long_name
        self.signature: str = func.signature
        self.parameters: List[str] = func.parameters

        self.code: str = func.code

        self.filename: str = func.filename
        self.start_line: int = func.start_line
        self.end_line: int = func.end_line
        self.before_change = func.before_change

        self.lang: str

        self.first_parent_class:str = func.first_parent_class

    def __eq__(self, other) -> bool:
        # return self.name == other.name and self.parameters == other.parameters
        return self.long_name == other.long_name

    def __hash__(self) -> int:
        # parameters are used in hashing in order to
        # prevent collisions when overloading method names
        return hash(
            (
                "name",
                self.name,
                "long_name",
                self.long_name,
                # "params",
                # self.parameters,
            )
        )

class Class:
    """
    This class represents a class in a file. Contains various information
    extracted through Tree-sitter.
    """

    def __init__(self, class_: Any) -> None:
        """
        Initialize a class object. This is calculated using Tree-sitter.
        """

        self.name: str = class_.name
        self.long_name: str = class_.long_name

        self.code: str = class_.code

        self.filename: str = class_.filename
        self.start_line: int = class_.start_line
        self.end_line: int = class_.end_line
        self.before_change = class_.before_change

        self.lang: str = class_.lang

        self.parameters: List[str] = class_.parameters
        self.parent_class: str = class_.parent_class
        self.superclasses = class_.superclasses

    def __eq__(self, other) -> bool:
        # return self.name == other.name and self.parameters == other.parameters
        return self.long_name == other.long_name

    def __hash__(self) -> int:
        # parameters are used in hashing in order to
        # prevent collisions when overloading method names
        return hash(
            (
                "name",
                self.name,
                "long_name",
                self.long_name,
                # "params",
                # self.parameters,
            )
        )
class Variable:
    """
    This class represents a variable in a file. Contains various information
    extracted through Tree-sitter.
    """

    def __init__(self, var: Any) -> None:
        """
        Initialize a variable object.
        """
        self.name: str = var.name
        self.long_name: str = var.long_name

        self.code: str = var.code

        self.start_line: int = var.start_line
        self.end_line: int = var.end_line
        self.before_change = var.before_change

        self.lang: str = var.lang

        self.parent_class: str = var.parent_class
        self.parent_class_namespace: str= var.parent_class_namespace

    def __eq__(self, other) -> bool:
        return self.long_name == other.long_name

    def __hash__(self) -> int:
        # parameters are used in hashing in order to
        # prevent collisions when overloading method names
        return hash(
            (
                "name",
                self.name,
                "long_name",
                self.long_name,
            )
        )

PATTERNS_FUNCTION_ROOT = """
    [
        (function_definition) @function.root
    ]
    """
PATTERNS_TOP_LEVEL_FUNCTION_CALL = """
[(module
(expression_statement
  (call
    function: (identifier) @top_level_called_function_name
    arguments: (argument_list)))

)
]
"""

PATTERNS_TOP_LEVEL_FUNCTION_DEF = """

[(module
(function_definition) @top_level_function_def

)

]
"""

PATTERNS_CLASS_ROOT = """
    [
        (class_definition) @class.root
    ]
    """
PATTERNS_LAMBDA_ASSIGNMENT = """
    [
        (lambda) @lambda.root
    ]
    """
PATTERNS_DECORATED_DEF = """
    [
        (decorated_definition) @decorated_def.root
    ]
        """
PATTERNS_GLOBAL_VARS="""
[
  (module
    (expression_statement
      (assignment
        left: (identifier) @global.name
        right: (_) @global.value)))
]
"""
PATTERNS_CLASS_VARS="""
[
  (class_definition
    body: (block
      (expression_statement
        (assignment
          left: (identifier) @class.name
          right: (_) @class.value))))
]
"""


PATTERNS_LOCAL_VARS="""
  (function_definition
    body: (block
      (expression_statement
        (assignment )@local_assign
          ))
          )
"""
func_query = PY_LANGUAGE.query(PATTERNS_FUNCTION_ROOT)
class_query = PY_LANGUAGE.query(PATTERNS_CLASS_ROOT)
lambda_query = PY_LANGUAGE.query(PATTERNS_LAMBDA_ASSIGNMENT)
dec_query = PY_LANGUAGE.query(PATTERNS_DECORATED_DEF)
top_call_query = PY_LANGUAGE.query(PATTERNS_TOP_LEVEL_FUNCTION_CALL)
top_def_query = PY_LANGUAGE.query(PATTERNS_TOP_LEVEL_FUNCTION_DEF)
global_var_query = PY_LANGUAGE.query(PATTERNS_GLOBAL_VARS)
class_var_query = PY_LANGUAGE.query(PATTERNS_CLASS_VARS)



class CodeChangeAnalyzer():
    """AST visitor for analyzing Python methods"""
    
    def __init__(self, source_code, commit_hash,file_path=None,change_before=False):
        self.parser = Parser(PY_LANGUAGE)


        self.functions = []
        self.functions_nodes = []
        self.global_functions=[]
        self.class_functions = {}

        self.classes = []

        self.current_class = None
        self.source_code = source_code
        self._filename = file_path
        # self.source_code = open(file_path,'r').read()
        self._lambda_counter = defaultdict(int)  # Add lambda counter
        self.before = change_before
        self.commit_hash=commit_hash

        self.cg = self.get_call_graph()

        tree = self.parser.parse(bytes(self.source_code, "utf8"))
        self.root_node = tree.root_node

    def get_lambda_name(self,namespace):
        """Generate unique name for lambda function"""
        self._lambda_counter[namespace] += 1
        return f"<lambda{self._lambda_counter[namespace]}>"
        
    def _get_module_name(self):
        """Get the module name from the filename"""
        if hasattr(self, '_filename'):
            path =  Path(self._filename)
            # 移除.py扩展名并获取所有路径部分
            parts = path.with_suffix('').parts
            # 将路径部分用点号连接成模块路径
            return '.'.join(parts)
        return ''

    def _get_namespace(self,node):
        if node.type != 'function_definition' and node.type != 'lambda' and node.type != 'identifier' and node.type != 'class_definition' and node.type!='assignment':
            assert False, f"current_node is not a function_definition/lambda/identifier/class_definition, {node.type}"

        # 处理嵌套的情况
        ns_hierarchy = []
        current_node = node.parent

        first_parent_class = None
        while current_node:
            # if current_node.type not in  ['module','function_definition', 'class_definition']: 
            #     print(current_node.type, current_node.text.decode('utf-8'),current_node.children,sep='\n')

            if current_node.type == 'class_definition' or current_node.type == 'function_definition':
                p_name = current_node.child_by_field_name('name')
                if p_name:
                    ns_hierarchy.insert(0, p_name.text.decode('utf-8'))

                if not first_parent_class:
                    first_parent_class=current_node
                
            current_node = current_node.parent
        
        # Get module name
        module_name = self._get_module_name()

        # Build complete namespace
        if len(ns_hierarchy):
            namespace = f"{module_name}.{'.'.join(ns_hierarchy)}"
        else:
            namespace = module_name
        
        return namespace, first_parent_class


    def _process_function(self, node):
        
        namespace,first_parent_class = self._get_namespace(node)
       

        start_line = node.start_point[0]+1
        end_line = node.end_point[0]+1

        if node.type =='lambda':
            name = self.get_lambda_name(namespace)
        else:
            name = node.child_by_field_name("name").text.decode('utf-8')

        parameters = node.child_by_field_name("parameters")
        if parameters:
            parameters = parameters.text.decode('utf-8')
        else:
            parameters = []


        # 处理装饰器
        decorators = []
        if node.parent and node.parent.type == 'decorated_definition':
            decorator_nodes = [child for child in node.parent.children if child.type == 'decorator']
            for dec in decorator_nodes:
                try:
                    decorators.append(dec.text.decode('utf-8'))
                except UnicodeDecodeError:
                    decorators.append(dec.text.decode('utf-8', errors='replace'))
                    assert False
        long_name = f"{namespace}.{name}"
        if first_parent_class:
            first_parent_class_namespace,_ = self._get_namespace(first_parent_class)
            first_parent_class_name = first_parent_class.child_by_field_name('name').text.decode('utf-8')
            first_parent_class = f"{first_parent_class_namespace}.{first_parent_class_name}"

        # else:
        #     logger.debug(f"long_name:{long_name}")
        #     assert False            
        func_info = {
            'name': name,
            'long_name': long_name,
            'signature': '',
            'parameters': parameters,
            'filename':self._filename,
            'start_line': start_line,
            'end_line': end_line,
            'code': node.text.decode('utf-8'),
            'before_change':self.before,
            'decorators': decorators,
            'first_parent_class': first_parent_class
        }
        return func_info
    
    def _process_variable(self, node, var_name):
        namespace,first_parent_class = self._get_namespace(node)

        # logger.debug(f"namespace for var {var_name} :{namespace}")
        start_line = node.start_point[0]+1
        end_line = node.end_point[0]+1
        long_name = f"{namespace}.{var_name}"

        code = node.text.decode('utf-8')

        if first_parent_class:
            first_parent_class_namespace,_ = self._get_namespace(first_parent_class)
            first_parent_class_name = first_parent_class.child_by_field_name('name').text.decode('utf-8')
            first_parent_class = f"{first_parent_class_namespace}.{first_parent_class_name}"

        var_info = {
            'name': var_name,
            'start_line': start_line,
            'end_line': end_line,
            'code': code,
            'long_name': long_name,
            'filename':self._filename,
            'before_change':self.before,
            'lang':'python',
            'parent_class':first_parent_class,
            'parent_class_namespace':namespace
        }
        return var_info
        
    def extract_global_vars(self,root_node=None):
        """提取所有全局变量名"""
        if not root_node:
            root_node = self.root_node
        captures = global_var_query.captures(root_node)

        global_vars = set()
        module_vars = []
        for node in captures.get('global.name',[]):
            node_name = node.text.decode('utf-8')
            if node_name.startswith('__') and node_name.endswith('__'):
                continue
            parent = node.parent
            assert parent.type == 'assignment'
            
            start_line = parent.start_point[0] + 1
            end_line = parent.end_point[0] + 1
            global_vars.add((node_name,(start_line,end_line)))
            var_info = self._process_variable(parent, var_name=node_name)
            var = SimpleNamespace(**var_info)
            module_vars.append(var)
        # 按start_line排序
        global_vars = sorted(list(global_vars), key=lambda x: x[1][0])
        logger.debug(f"global_vars:{[(var.name, var.long_name) for var in module_vars]}")

        
        return module_vars
    
    def extract_class_vars(self,root_node=None):
        """提取所有类变量名"""
        if not root_node:
            root_node = self.root_node
        # 处理类变量
        class_vars_ = set()
        class_vars = []
        class_nodes = class_query.captures(root_node)
        for class_node in class_nodes.get('class.root', []):
            captures = class_var_query.captures(class_node)
            for node in captures.get('class.name',[]):
                node_name = node.text.decode('utf-8')
                parent = node.parent
                assert parent.type == 'assignment'
                # ns = self._get_namespace(node)[0].replace(self._get_module_name()+'.','')
                # if ns:
                #     node_name = f"{ns}.{node_name}"
                # logger.debug(node_name)
                start_line = parent.start_point[0] + 1
                end_line = parent.end_point[0] + 1
                class_vars_.add((node_name,(start_line,end_line)))
                var_info = self._process_variable(parent, var_name=node_name)
                var = SimpleNamespace(**var_info)
                class_vars.append(var)
        # 按start_line排序
        class_vars_ = sorted(list(class_vars_), key=lambda x: x[1][0])
        logger.debug(f"class_vars:{[(var.name, var.long_name) for var in class_vars]}")

        return class_vars

    def extract_identifiers_in_function(self, function_node):
        """提取函数体内所有 identifier 引用"""
        QUERY_IDENTIFIERS_IN_FUNCTION = """
        (identifier) @var.ref
        """
        query = PY_LANGUAGE.query(QUERY_IDENTIFIERS_IN_FUNCTION)
        captures = query.captures(function_node)

        identifiers = set()
        for node in captures.get('var.ref',[]):
            node_name = node.text.decode('utf-8')
            identifiers.add(node_name)
        return identifiers
    def _process_class(self,node):

        class_name = node.child_by_field_name('name').text.decode('utf-8')
        namespace,first_parent_class = self._get_namespace(node)
        long_name = f"{namespace}.{class_name}"
        # print(node.child_by_field_name('superclasses'))
        # print(node.child_by_field_name('type_parameters'))
        # assert False
        superclasses = node.child_by_field_name('superclasses')
        superclass_list = []
        if superclasses:
            for child in superclasses.children:
                if child.type == 'identifier':
                    superclass_name = child.text.decode('utf-8')
                    superclass_list.append(superclass_name)
            logger.debug(f'superclass_list:{superclass_list}')
        params = node.child_by_field_name('type_parameters')
        if params:
            logger.debug(f'params:{params}')

        if first_parent_class:
            first_parent_class_namespace,_ = self._get_namespace(first_parent_class)
            first_parent_class_name = first_parent_class.child_by_field_name('name').text.decode('utf-8')
            first_parent_class = f"{first_parent_class_namespace}.{first_parent_class_name}"
        class_info = {
            'name': class_name,
            'start_line': node.start_point[0]+1,
            'end_line': node.end_point[0]+1,
            'code': '',
            'long_name': long_name,
            'filename':'',
            'before_change':self.before,
            'lang':'python',
            'parameters':params,
            'parent_class':first_parent_class,
            'superclasses':superclass_list,
        }
        return class_info
    def get_classes(self):
        root_node = self.root_node
        class_nodes = class_query.captures(root_node)
        classes = []
        for class_node in class_nodes.get('class.root', []):
            class_info = self._process_class(class_node)
            class_ = SimpleNamespace(**class_info)
            classes.append(class_)
            # print(class_info)

        return classes
    def get_functions(self):
        root_node = self.root_node
        
        # 初始化数据结构
        class_functions = defaultdict(list)
        global_functions = []


        # 获取所有的function node
        func_nodes = func_query.captures(root_node)
        for func_node in func_nodes.get('function.root', []):
            func_info = self._process_function(func_node)
            func = SimpleNamespace(**func_info)
            first_parent_class = func.first_parent_class
            if first_parent_class:
                class_functions[first_parent_class].append(func)
            else:
                global_functions.append(func)
            self.functions_nodes.append(func_node)
            self.functions.append(func)

        self.global_functions = global_functions
        self.class_functions = class_functions
        # print(class_functions)
        # assert False

        # 提取 Lambda 函数
        lambda_nodes = lambda_query.captures(root_node)
        lambda_functions = []

        for func_node in lambda_nodes.get("lambda.root", []):
            # 如果是nested lambda则不处理，保持和jarvis一致
            nested_lambda = False
            # 必须包含在某个非lambda函数内部
            inside_func = None
            if func_node.type == 'lambda':
                current_node = func_node.parent
                while current_node:
                    if current_node.type == 'lambda':
                        nested_lambda = True
                    elif current_node.type == 'function_definition':
                        inside_func = current_node
                    if inside_func and nested_lambda:
                        break
                    current_node = current_node.parent
            if nested_lambda or not inside_func:
                continue
            # 查找最近的赋值语句，找到变量名
            func_info = self._process_function(inside_func)
            func = SimpleNamespace(**func_info)
            first_parent_class = func.first_parent_class
            if first_parent_class:
                class_functions[first_parent_class].append(func)
            else:
                self.global_functions.append(func_node)
            self.functions.append(func)
        # 打印结果
        if False:
            print("Class Functions:", )
            for class_name, funcs in class_functions.items():
                print(f"Class: {class_name}")
                for func in funcs:
                   print(func.long_name)

            print('-'*100)
            
            print("Global Functions:", )
            for func in global_functions:
                print(func.long_name)


        return self.functions

    def get_top_level_called_functions(self, root_node=None):
        ""
        """
        Get the top-level call functions in the source code.
        Returns:
            list: A list of top-level call functions.
        """
        if not root_node:
            root_node = self.root_node
        # 提取所有的函数定义
        # top_def_func_nodes = top_def_query.captures(root_node)
        # top_def_func_nodes_long_names = set()
        # for node in top_def_func_nodes.get('top_level_function_def', []):
        #     name = node.text.decode('utf-8')
        #     ns = self._get_namespace(node)
        #     long_name = f"{ns}.{name}"
        #     top_def_func_nodes_long_names.add(long_name)

        # top_level_def_funcs = [func.long_name for func in self.global_functions]
        # print(top_level_def_funcs)

        top_called_func_nodes = top_call_query.captures(root_node)
        top_level_called_funcs = set()
        top_module_name = self._get_module_name()
        for node in top_called_func_nodes.get('top_level_called_function_name', []):
  
            name = node.text.decode('utf-8')
            long_name = f"{top_module_name}.{name}"
            top_level_called_funcs.add(long_name)
            
        return top_level_called_funcs


    def get_call_graph(self):
        """
        Get the call graph of the source code.
        Returns:
            dict: A dictionary representing the call graph.
        """
        #写入tmp目录下
        real_module=self._get_module_name()
        cg_file = DIFF_CACHE_DIR_DATE / f"{self.commit_hash}/{real_module.replace('.','_')}_cg.json"
        if not cg_file.parent.exists():
            cg_file.parent.mkdir(parents=True, exist_ok=True)
        if not cg_file.exists():
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_dir_path = Path(tmp_dir)
                # 保存文件到临时目录
                tmp_file_path = tmp_dir_path / 'temp.py'
                with open(tmp_file_path, 'w') as f:
                    f.write(self.source_code)
                # 运行jarvis-cli命令
                cmd = (
                        f"conda run -n jarvis jarvis-cli {tmp_file_path} "
                        f"--o {cg_file}"
                    )
                jarvis_cmd = subprocess.list2cmdline(cmd)
                if sys.platform == 'darwin':
                    jarvis_timeout = 60*3
                else:
                    jarvis_timeout = 60*20
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=jarvis_timeout, shell=True)
                

                tmp_module = (str(tmp_dir_path).replace('/','.') + '.temp').lstrip('.')
                try:
                    with open(cg_file, 'r') as f:
                        jarvis_output = json.load(f)
                except:
                # 解析jarvis-cli输出
                    jarvis_output = {}
                    if sys.platform == 'linux':
                        assert False
                
                #normalized cg
                new_cg = defaultdict(set)
                # print(tmp_module,real_module)
                for func, callees in jarvis_output.items():
                    func = func.lstrip('.').replace(tmp_module,real_module)
                    
                    for callee in callees:
                        new_cg[func].add(callee.lstrip('.').replace(tmp_module,real_module))
                new_cg = {k:list(v) for k,v in new_cg.items()}
                with open(cg_file, 'w') as f:
                    json.dump(new_cg, f)
        else:
            with open(cg_file, 'r') as f:
                new_cg = json.load(f)
            
        return new_cg

    def get_ddg(self):
        """
        Get the data dependency graph of the source code.
        Returns:
            dict: A dictionary representing the data dependency graph.
        """
        #写入tmp目录下

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dir_path = Path(tmp_dir)
            tmp_file_path = tmp_dir_path / 'temp.py'

            with open(tmp_file_path, 'w') as f:
                    f.write(self.source_code)
            joern_cmd = f"joern-parse -o {tmp_dir_path / 'cpg.bin'} --language PYTHONSRC {tmp_file_path}&&joern-export --repr ddg -o {tmp_dir_path / 'temp_dir'} --format dot {tmp_dir_path / 'cpg.bin'}"
            result = subprocess.run(joern_cmd, capture_output=True, text=True, shell=True)
            # 检查是否运行成功
            if result.returncode != 0:
                print(f"Error running joern-parse: {result.stderr}")
                assert False
            print(result)

            # 解析joern-export输出
            import networkx as nx
            ddg = {}
            file_paths = list((tmp_dir_path / 'temp_dir').glob('*.dot'))
            print(file_paths)
            graphs = [nx.nx_agraph.read_dot(f) for f in file_paths]
            combined_graph = nx.compose_all(graphs)
            node_labels = {}
            for node, attrs in combined_graph.nodes(data=True):
                info,name = attrs.get("label", "").split('<BR/>')
                type_, lineno = info.split(', ')
                print(type_, lineno, name)
                assert False
                # 提取冒号后的内容，并去掉引号
                meaningful_label = raw_label.split(":", 1)[1].strip(' "') if ":" in raw_label else raw_label.strip(' "\"')
                node_labels[node] = meaningful_label
            print(node_labels)


            assert False
    
    
    def get_changed_vars_called_functions(self,changed_global_vars,changed_class_vars,root_node=None):
        """
        Get the changed variables and called functions in the source code.
        Returns:
            dict: A dictionary representing the changed variables and called functions.
        """
        if not root_node:
            root_node = self.root_node
        # logger.info(f"changed_global_vars: {changed_global_vars}")
        # logger.info(f"changed_class_vars: {changed_class_vars}")
        changed_vars = changed_global_vars | changed_class_vars
        changed_vars = set([var[0] for var in changed_vars])
        


        global_vars=self.extract_global_vars()
        global_vars = set([var[0].split('.')[-1] for var in global_vars])

        # 1. 分析所有的global function
        all_changed_vars_called_funcs = []
        for func_node in self.global_functions:
            external_used = self.analyze_function_usage(func_node, global_vars)
            if len(external_used&changed_vars):
                func_info = self._process_function(func_node)
                func = Method(SimpleNamespace(**func_info))
                all_changed_vars_called_funcs.append(func)
                logger.debug(f"func_info: {func.long_name}")

        # 2. 获得所有的class root node
        class_nodes = class_query.captures(root_node)
        class2class_vars = {}
        for class_node in class_nodes.get('class.root', []):
            class_name = class_node.child_by_field_name('name').text.decode('utf-8')

            class_vars = self.extract_class_vars(class_node)
            class_vars = set([var[0] for var in class_vars])
            class2class_vars[class_name] = class_vars
        for class_node in class_nodes.get('class.root', []):
            class_name = class_node.child_by_field_name('name').text.decode('utf-8')
            # 处理继承
            superclasses = class_node.child_by_field_name('superclasses')
            changed_vars_ = changed_vars.copy()
            class_vars = class2class_vars[class_name].copy()
            if superclasses:
                for child in superclasses.children:
                    if child.type == 'identifier':
                        superclass_name = child.text.decode('utf-8')
                        # logger.info(f"superclasses:{superclass_name}")
                        if superclass_name in class2class_vars:
                            class_vars.update({var.replace(superclass_name,class_name) for var in class2class_vars[superclass_name]})
                            changed_vars_.update({var.replace(superclass_name,class_name) for var in changed_vars})
            # logger.info(f"class_name:{class_name}, class_vars:{class_vars}")

            
            #remove namespace
            
            all_external_vars = global_vars | class_vars

            # 3. 分析所有的class function
            class_function = func_query.captures(class_node)
            for func_node in class_function.get('function.root', []):
                external_used = self.analyze_function_usage(func_node, all_external_vars,class_name)
                # print('external_used:,',external_used)
                
                if len(external_used&changed_vars_):
                    
                    func_info = self._process_function(func_node)
                    func = Method(SimpleNamespace(**func_info))
                    all_changed_vars_called_funcs.append(func)
                    logger.debug(f"func_info: {func.long_name}")
                    logger.debug(f"func: {func_node.child_by_field_name('name').text.decode('utf-8')},  external_used: {external_used}\n")
                    
            # if class_name == 'UserForm':
            #     print(class2class_vars)
            #     assert False
        return all_changed_vars_called_funcs
        # 提取所有的函数定义
    def analyze_function_usage(self,func_node,func, all_external_vars):
        """
        Analyze the usage of global and class variables in a function.
        Returns:
            dict: A dictionary representing the usage of global and class variables.
        """
        # ! 1.collect local vars (params, assignment)
        # print('func_node:',{func_node.child_by_field_name('name').text.decode('utf-8')})
        local_vars = set()
        params_node = func_node.child_by_field_name('parameters')
        if params_node:
            for param_node in params_node.children:
                if param_node.type == 'identifier':
                    param_name = param_node.text.decode('utf-8')
                    local_vars.add(param_name)

                elif param_node.type == 'default_parameter':
                     param_name = param_node.child_by_field_name('name').text.decode('utf-8')
                     local_vars.add(param_name)
        # logger.debug(f"locals_vars from param_name: {local_vars}")
        # logger.debug(f"all_external_vars: {all_external_vars}")
        body = func_node.child_by_field_name('body')
        assignment = ['assignment', 'augmented_assignment', 'for_in_clause']
        assigned_vars = set(local_vars)
        used_vars = set()
        external_used = set()
        def walk(root_node, assigned_vars,external_used):
            # print(root_node.type)
            used_vars = set()
            if len(root_node.children) == 0 and root_node.type == 'identifier':
                var_name = root_node.text.decode('utf-8')
                if root_node.parent.type == 'attribute':
                    # print(root_node.parent.parent.type)
                    obj = root_node.parent.child_by_field_name('object')
                    obj_name = obj.text.decode('utf-8')
                    if (obj_name == 'self' or obj_name == 'cls') and func.first_parent_class:
                        # assert func.first_parent_class 
                        # edge case, python 2.3 https://github.com/httplib2/httplib2/blob/40cbdcc8586f2292fa0e76a3e8c012f0cc9ed919/python2/httplib2/__init__.py
                        obj_name = func.first_parent_class.split('.')[-1]
                        
                    attr = root_node.parent.child_by_field_name('attribute')
                    attr_name = attr.text.decode('utf-8')
                    # print(f"attr_name:{attr_name}")

                    var_names = {f"{obj_name}.{attr_name}"}
                    # print("var_names:",var_name)
                    # if func.first_parent_class:
                    #     assert False
                elif root_node.parent.type == 'call':
                    return {},assigned_vars,external_used
                else:
                    var_names = {root_node.text.decode('utf-8')}
                # print(f"{var_name}, assigned_vars: {assigned_vars}, used_vars: {used_vars}, all_external_vars: {all_external_vars} external_used: {external_used} {var_name in all_external_vars and var_name not in assigned_vars}")
                for var_name in var_names:
                    if var_name in all_external_vars and var_name not in assigned_vars:
                        external_used.add(var_name)
                return {}, var_names,external_used
            elif root_node.type in assignment:
                if root_node.type == 'for_in_clause':
                    right_nodes = [root_node.children[-1]]
                    left_nodes = [root_node.child_by_field_name('left')]
                else:
                    if root_node.child_by_field_name('right') is None:
                        return {},{}, external_used
                    left_nodes = [x for x in root_node.child_by_field_name('left').children if x.type != ',']
                    if root_node.child_by_field_name('right').type == 'string':
                        right_nodes = [root_node.child_by_field_name('right')]
                    else:
                        right_nodes = [x for x in root_node.child_by_field_name('right').children if x.type != ',']
                    if len(right_nodes) != len(left_nodes):
                        left_nodes = [root_node.child_by_field_name('left')]
                        right_nodes = [root_node.child_by_field_name('right')]
                    if len(left_nodes) == 0:
                        left_nodes = [root_node.child_by_field_name('left')]
                    if len(right_nodes) == 0:
                        right_nodes = [root_node.child_by_field_name('right')]
                        
                # logger.debug(f"left_nodes: {left_nodes}, right_nodes: {right_nodes}")
                # if func_node.child_by_field_name('name').text.decode('utf-8') == '__call__':
                #     for node in right_nodes:
                #         _, temp,external_used = walk(node,assigned_vars,external_used)
                #     assert False
                for node in right_nodes:
                    _, temp,external_used = walk(node,assigned_vars,external_used)
                    # print('used:',temp)
                    
                    used_vars.update(temp)

                
                for left_node in left_nodes:
                    if left_node.parent.type == 'attribute':
                        if left_node.parent.parent and left_node.parent.parent.type == 'call':
                            continue
                        obj = left_node.parent.child_by_field_name('object')
                        obj_name = obj.text.decode('utf-8')
                        attr = left_node.parent.child_by_field_name('attribute')
                        attr_name = attr.text.decode('utf-8')
                        var_name = f"{obj_name}.{attr_name}"
                        
                    elif left_node.parent.type == 'call':
                        continue
                    else:
                        var_name = left_node.text.decode('utf-8')
                    assigned_vars.add(var_name)
            
            for child in root_node.children:
                temp_assigned_vars, temp_used_vars,external_used = walk(child, assigned_vars,external_used)
                used_vars.update(temp_used_vars)
                assigned_vars.update(temp_assigned_vars)

            return assigned_vars, used_vars, external_used
            
        assigned_vars, used_vars,external_used = walk(body, assigned_vars,external_used)
        logger.debug(f"external_used: {external_used} ")
        # 检查external vars是否被使用
        return external_used

class GlobalVariableUsageAnalyzer:
    def __init__(self, root_node, all_vars,changed_vars=None):
        self.root_node = root_node
        self.changed_vars = changed_vars
        self.all_vars = all_vars
        self.used_vars = set()
        self.assigned_vars = set()
        self.local_vars_stack = []


    
    def analyze(self):
        root_node = self.root_node

        changed_vars = self.changed_vars

        # 遍历AST，查找全局变量的使用
        self.walk_and_analyze(root_node)


    def walk_and_analyze(self, node):
        if node.type == 'function_definition':
            # 进入函数时，将参数视为局部变量
            locals_vars = set()
            params_node = node.child_by_field_name('parameters')

            params_node.child_by_field_name('parameters')
            
            if params_node:
                for param_node in params_node.children:
                    if param_node.type == 'identifier':
                        param_name = param_node.text.decode('utf-8')
                        locals_vars.add(param_name)
                        logger.debug(f"param_name: {param_name}")
                # assert False
            
            self.collect_local_vars(node)

            self.local_vars_stack.append(locals_vars)
        elif node.type == 'attribute' and node.parent.type == 'assignment':
            # 处理属性access
            attr_name = node.child_by_field_name('name').text.decode('utf-8')
            obj_name  = node.child_by_field_name('object').text.decode('utf-8')
            logger.debug(f"attr_name: {attr_name}, obj_name: {obj_name}")
            if obj_name == 'self' or obj_name == self.current_class:
                if attr_name in self.all_vars:
                    self.var_used(attr_name)
        elif node.type == 'identifier':
            # 处理标识符
            identifier_name = node.text.decode('utf-8')
            if identifier_name in self.all_vars:
                current_locals = self.current_locals
                if identifier_name not in current_locals:
                    self.var_used.add(identifier_name)

                    if node.parent and node.parent.type == 'assignment' and node.parent.children[0] == node:
                        self.var_assigned(identifier_name)

        for child in node.children:
            self.walk_and_analyze(child)
        if node.type == 'function_definition':
            # 离开函数时，弹出局部变量
            self.local_vars_stack.pop()
    def DFG_python(self,root_node, states):
    

        assignment = ['assignment', 'augmented_assignment', 'for_in_clause']
        if_statement = ['if_statement']
        for_statement = ['for_statement']
        while_statement = ['while_statement']
        do_first_statement = ['for_in_clause']
        def_statement = ['default_parameter']
        states = states.copy()
        if ((len(root_node.children) == 0)) and root_node.type != 'comment':
            if 'string' in root_node.parent.type:
                return [], states
            code = root_node.text.decode('utf-8')
            if root_node.type == code:
                return [], states
            elif code in states:
                return [(code, 'comesFrom', [code], states[code].copy())], states
            else:
                if root_node.type == 'identifier':
                    states[code] = [code]
                return [(code, 'comesFrom', [], [])], states
                
        elif root_node.type in def_statement:
            name = root_node.child_by_field_name('name')
            value = root_node.child_by_field_name('value')
            DFG = []
            if value is None:
                code = name.text.decode('utf-8')
                DFG.append((code, 'comesFrom', [], []))
                states[code] = [code]
                return DFG, states
            else:
                name_code = name.text.decode('utf-8')
                value_code = value.text.decode('utf-8')
                temp, states = DFG_python(value, states)
                DFG += temp
                DFG.append((name_code, 'comesFrom', [value_code], [value_code]))
                states[name_code] = [name_code]
                return DFG, states
                
        elif root_node.type in assignment:
            if root_node.type == 'for_in_clause':
                right_nodes = [root_node.children[-1]]
                left_nodes = [root_node.child_by_field_name('left')]
            else:
                if root_node.child_by_field_name('right') is None:
                    return [], states
                left_nodes = [x for x in root_node.child_by_field_name('left').children if x.type != ',']
                if root_node.child_by_field_name('right').type == 'string':
                    right_nodes = [root_node.child_by_field_name('right')]
                else:
                    right_nodes = [x for x in root_node.child_by_field_name('right').children if x.type != ',']
                if len(right_nodes) != len(left_nodes):
                    left_nodes = [root_node.child_by_field_name('left')]
                    right_nodes = [root_node.child_by_field_name('right')]
                if len(left_nodes) == 0:
                    left_nodes = [root_node.child_by_field_name('left')]
                if len(right_nodes) == 0:
                    right_nodes = [root_node.child_by_field_name('right')]
                    
            DFG = []
            for node in right_nodes:
                temp, states = DFG_python(node, states)
                DFG += temp
                
            for left_node, right_node in zip(left_nodes, right_nodes):
                left_code = left_node.text.decode('utf-8')
                right_code = right_node.text.decode('utf-8')
                DFG.append((left_code, 'computedFrom', [right_code], [right_code]))
                states[left_code] = [left_code]
            return DFG, states
            
        elif root_node.type in if_statement:
            DFG = []
            current_states = states.copy()
            others_states = []
            tag = False
            if 'else' in root_node.type:
                tag = True
            for child in root_node.children:
                if 'else' in child.type:
                    tag = True
                if child.type not in ['elif_clause', 'else_clause']:
                    temp, current_states = DFG_python(child, current_states)
                    DFG += temp
                else:
                    temp, new_states = DFG_python(child, states)
                    DFG += temp
                    others_states.append(new_states)
            others_states.append(current_states)
            if tag is False:
                others_states.append(states)
            new_states = {}
            for dic in others_states:
                for key in dic:
                    if key not in new_states:
                        new_states[key] = dic[key].copy()
                    else:
                        new_states[key] += dic[key]
            for key in new_states:
                new_states[key] = sorted(list(set(new_states[key])))
            return DFG, new_states
            
        elif root_node.type in for_statement:
            DFG = []
            for i in range(2):
                for child in root_node.children:
                    temp, states = DFG_python(child, states)
                    DFG += temp
            return DFG, states
            
        elif root_node.type in while_statement:
            DFG = []
            for i in range(2):
                for child in root_node.children:
                    temp, states = DFG_python(child, states)
                    DFG += temp
            return DFG, states
            
        else:
            DFG = []
            for child in root_node.children:
                if child.type in do_first_statement:
                    temp, states = DFG_python(child, states)
                    DFG += temp
            for child in root_node.children:
                if child.type not in do_first_statement:
                    temp, states = DFG_python(child, states)
                    DFG += temp
            return DFG, states

    def collect_local_vars(self, node):
        from my_parser.utils import remove_comments_and_docstrings

        print(node.text.decode('utf-8'))
        source_code = node.text.decode('utf-8')
        source_code = remove_comments_and_docstrings(source_code, 'python')
        print(source_code)
        tree =  Parser(PY_LANGUAGE).parse(bytes(source_code, "utf8"))
        print(node)
        dfg = self.DFG_python(tree.root_node,{})
        print(dfg)
        DFG,_ = self.DFG_python(node,{})
        print(DFG)
        # DFG = sorted(DFG, key=lambda x: x[1])
        indexs = set()

        for d in DFG:
            if len(d[-1]) != 0:
                indexs.add(d[1])
            for x in d[-1]:
                indexs.add(x)
        new_DFG = []
        for d in DFG:
            if d[1] in indexs:
                new_DFG.append(d)
        dfg = new_DFG
        print(dfg)
        # assert False
                    


class ModifiedFile:
    """
    This class contains information regarding a modified file in a commit.
    """

    def __init__(
            self,
            diff: Diff,
            commit_hash: str
    ):
        """
        Initialize a modified file. A modified file carries on information
        regarding the changed file. Normally, you shouldn't initialize a new
        one.
        """
        self._c_diff = diff

        self._function_list: List[Method] = []
        self._function_list_before: List[Method] = []
        self._class_list: List[Class] = []
        self._class_list_before: List[Class] = []
        self._module_vars = []
        self._module_vars_before = []
        self._class_vars = []
        self._class_vars_before= []

        self.deleted_line_scopes= {'function':[],'class':[],'module':[]}
        self.added_line_scopes={'function':[],'class':[],'module':[]}
        self.global_deleted_lines = []
        self.global_added_lines = []

        self.changed_module_vars = []
        self.changed_class_vars = []

        self.commit_hash = commit_hash
        # if self.language_supported and self._is_source_code_file():
        #     # 1. get all class,functions list
        #     self._get_class_and_function_and_var_list()
    def get_class_and_function_and_var_list(self):

        if self.language_supported and self._is_source_code_file():
            # 1. get all class,functions list
            self._get_class_and_function_and_var_list()
        else:
            logger.warning(f"no supported file/language")
    def get_code_changes_scopes(self):
        

        if self.language_supported and self._is_source_code_file():
            
            # 1. get all class,functions list
            self._get_class_and_function_and_var_list()
            print(self.filename, self._function_list_before_called_top_level)

            # assert False

            # 2. classify code changes
            self.deleted_line_scopes = self._classify_code_changes(self.cleaned_deleted_lines, self._function_list_before, self._class_list_before)
            self.added_line_scopes = self._classify_code_changes(self.cleaned_added_lines, self._function_list, self._class_list)
            # 3. get var related changed for module/class
            # var existed in old_file
            # var may modified by both deleted and added lines
            # ! Functions that use any deleted or added variables should be captured by function_scope_lines.
            module_scope_lines = (self.deleted_line_scopes['module'], self.added_line_scopes['module'])
            self.changed_module_vars = self._get_changed_vars(module_scope_lines, scope='module')
            class_scope_lines = (self.deleted_line_scopes['class'], self.added_line_scopes['class'])
            self.changed_class_vars = self._get_changed_vars(class_scope_lines, scope='class')
            logger.debug(f'changed_module_vars:{[(var.long_name) for var in self.changed_module_vars]}, changed_class_vars:{[(var.long_name) for var in self.changed_class_vars]}')
        
        return [self.deleted_line_scopes, self.added_line_scopes]

            # 3. get vulnerable methods
    def get_vulnerable_functions(self):
        ...
            # self.vulnerable_methods = self._get_vulnerable_methods()
    def _is_special_method(self,method):
        return method.name.startswith('__') and method.name.endswith('__')

    def _get_vulnerable_methods(self):
        """
        Return the list of methods that were changed. This analysis
        is more complex because Lizard runs twice: for methods before
        and after the change

        :return: list of methods
        """
        vul_dict = {
            'old_method_direct_modified_by_deleted_lines':set(),
            'old_method_only_modified_by_added_lines':set(),
            'special_method_only_existed_in_new_file':set(),
            'call_added_funcs_vulnerable_methods':set(),
            'added_funcs_called_by_vulnerable_methods':set(),
        }
        # 1. function-scope 
        # 1.1 functions modified by deleted lines (may modified by added lines  simultaneously)
        old_methods_changed = self.methods_changed_old
        old_methods_changed_long_names = {
            y.long_name
            for y in old_methods_changed
        }
        vul_dict['old_method_direct_modified_by_deleted_lines'] = {method.long_name for method in old_methods_changed}

        # 1.2 functions explicitly declared in old file, ONLY modified by added lines.
        methods_changed_new = self.methods_changed_new
        new_changed_method_long_names = {
            y.long_name
            for y in methods_changed_new
        }
        for old_method in self.methods_before:
            # if only modified by by added lines.
            if old_method.long_name in new_changed_method_long_names and old_method.long_name not in old_methods_changed_long_names:
                # vulnerable_methods.add(method)
                # vulnerable_methods_long_names.add(method.long_name)
                vul_dict['old_method_only_modified_by_added_lines'].add(method.long_name)
        
        # 1.3 functions implicitly declared in old file, such as special methods (which ONLY explicitly be declared only in new file), for a class existed in old file.
        # classes existed in old file.
        classes_before = self._class_list_before
        logger.debug(f"classes_before:{classes_before}")

        # methods changed by added lines->modified special methods.
        for method in methods_changed_new:
            if not self._is_special_method(method):
                continue
            
            # ONLY focus the classes existed in old file
            first_parent_class = method.first_parent_class
            if not first_parent_class or first_parent_class not in classes_before:
                continue
            
            # vulnerable_methods_long_names.add(method.long_name)
            # vulnerable_methods.add(method)
            vul_dict['special_method_only_existed_in_new_file'].add(method.long_name)

        # 1.4 functions existed in old file calls added functions
        old_method_long_names = {
            y.long_name
            for y in old_methods
        }
        # get the added functions
        added_methods = []
        for method_long_name in new_changed_method_long_names:
            if method_long_name not in old_method_long_names:
                added_methods.append(method_long_name)
        # search the caller in old_file for added_methods based on the CG for new_file
        for new_method in self.methods:
            caller = new_method.long_name
            # check if method with the same long name as new_method exists in old_file
            if caller not in old_method_long_names or caller in added_methods:
                continue
            callees = self.cg.get(caller,[])
            inter = set(callees)&set(added_methods)
            if inter:
                # vulnerable_methods_long_names.add(caller)
                # vulnerable_methods.add(method)
                vul_dict['old_method_called_new_added_methods'].add(method.long_name)
        
       
        # 2. class-scope
        # 3. module-scope
        for method in function_list_before_called_changed_vars:
            vul_dict['old_method_called_changed_vars'].add(method.long_name)


        # 4. 基于body判断是否真正有修改，减少FP (refactoring, docs, multi-line comments)
        vulnerable_methods = self._filter_vulnerable_methods(vulnerable_methods)

         # 1.5 functions called at top/module-level and belong to vulnerable functions
         # TODO: relax the top_level_function definition
        for long_name in self._function_list_before_called_top_level:
            if long_name in vulnerable_methods_long_names:
                main_func = self._generate_module_main()
                vulnerable_methods.add(main_func)
                vulnerable_methods_long_names.add(main_func.long_name)
                vul_dict['top_level_vulnerable_call'].add(method.long_name)
        return self.vulnerable_methods

    def _is_source_code_file(self):

        # ! must same with from data_collection.vul_analyze import is_source_code_file
        if self.change_type == ModificationType.ADD or not self.old_path:
            return False
        elif  any(f"{dir_}" in self.old_path.lower().split('/')[:-1]  for dir_ in exclude_dirs):
         
            return False
        elif 'test'  in self.filename.lower():
            return False
        elif self.filename.lower() == 'setup.py'  or self.filename.lower() == 'setup.cfg':
            return False
        return True

    def _find_minimal_enclosing_scope(self,line_no, functions, classes):
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
    
    def _classify_code_changes(self,lines, functions, classes):

        #1. method scope

        # 2. class scope


        # 3. module scope (var, import, and other)
        line_scopes = {'function':[],'class':[],'module':[]}
        for line in lines:
            line_no, content = line
            scope = self._find_minimal_enclosing_scope(line_no, functions, classes)
            line_scopes[scope].append(line)
           
        logger.info(f"line_scopes:{line_scopes}")
        return line_scopes


        
        ...

    def _get_class_and_function_and_var_list(self, include_before=True):
        if self.source_code and not self._function_list:
            analyzer = CodeChangeAnalyzer(source_code=self.source_code,commit_hash=self.commit_hash,file_path=self.new_path,change_before=False)
            self._function_list = [Method(func) for func in analyzer.get_functions()]
            self._class_list = [Class(cls) for cls in analyzer.get_classes()]


            self._module_vars =  [Variable(var) for var in analyzer.extract_global_vars()]
            self._class_vars =  [Variable(var) for var in analyzer.extract_class_vars()]
            # assert False
          
            # !. if has added method
            self.cg = analyzer.cg
        if include_before and self.source_code_before and not self._function_list_before:
            analyzer = CodeChangeAnalyzer(source_code=self.source_code_before,commit_hash=self.commit_hash,file_path=self.old_path,change_before=True)
            self._function_list_before = [Method(func) for func in analyzer.get_functions()]
            self._class_list_before = [Class(cls) for cls in analyzer.get_classes()]

            self._module_vars_before =  [Variable(var) for var in analyzer.extract_global_vars()]
            self._class_vars_before =  [Variable(var) for var in analyzer.extract_class_vars()]

            # ONLY for old_file if possible
            self._function_list_before_called_top_level = analyzer.get_top_level_called_functions()
            # print(self._function_list_before_called_top_level)
            # assert False

            # !. if has added method
            self.cg_before = analyzer.cg

    def __hash__(self) -> int:
        # 使用commit_hash、文件路径和变更类型作为唯一标识
        key_components = (
            getattr(self, '_commit_hash', ''),  # commit hash
            self.change_type.name,              # 变更类型
            self.old_path or '',                # 旧路径
            self.new_path or '',                # 新路径
        )
        return hash(key_components)
    
    def _get_module_name(self):
        """Get the module name from the filename"""
        if hasattr(self, 'new_path'):
            path =  Path(self.new_path)
            # 移除.py扩展名并获取所有路径部分
            parts = path.with_suffix('').parts
            # 将路径部分用点号连接成模块路径
            return '.'.join(parts)
        return ''
    @property
    def change_type(self) -> ModificationType:
        return self._from_change_to_modification_type(self._c_diff)

    @staticmethod
    def _from_change_to_modification_type(diff: Diff) -> ModificationType:
        if diff.new_file:
            return ModificationType.ADD
        if diff.deleted_file:
            return ModificationType.DELETE
        if diff.renamed_file:
            return ModificationType.RENAME
        if diff.a_blob and diff.b_blob and diff.a_blob != diff.b_blob:
            return ModificationType.MODIFY

        return ModificationType.UNKNOWN

    @property
    def diff(self) -> str:
        return self._get_decoded_str(self._c_diff.diff) or ''

    def _get_decoded_str(self, diff: Union[str, bytes, None]) -> Optional[str]:
        try:
            if isinstance(diff, bytes):
                return diff.decode("utf-8", "ignore")
            if isinstance(diff, str):
                return diff
            return None
        except (AttributeError, ValueError):
            logger.debug(f"Could not load the diff of file {self.filename}")
            return None

    @property
    def content(self) -> Optional[bytes]:
        return self._get_undecoded_content(self._c_diff.b_blob)

    @property
    def content_before(self) -> Optional[bytes]:
        return self._get_undecoded_content(self._c_diff.a_blob)

    def _get_undecoded_content(self, blob: Optional[IndexObject]) -> Optional[bytes]:
        return blob.data_stream.read() if blob is not None else None

    @property
    def source_code(self) -> Optional[str]:
        if self.content and isinstance(self.content, bytes):
            return self._get_decoded_content(self.content)

        return None

    @property
    def source_code_before(self) -> Optional[str]:
        if self.content_before and isinstance(self.content_before, bytes):
            return self._get_decoded_content(self.content_before)

        return None

    @property
    def added_lines(self) -> int:
        """
        Return the total number of added lines in the file.

        :return: int lines_added
        """
        added_lines = 0
        for line in self.diff.replace("\r", "").split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                added_lines += 1
        return added_lines

    @property
    def deleted_lines(self) -> int:
        """
        Return the total number of deleted lines in the file.

        :return: int lines_deleted
        """
        deleted_lines = 0
        for line in self.diff.replace("\r", "").split("\n"):
            if line.startswith("-") and not line.startswith("---"):
                deleted_lines += 1
        return deleted_lines

    @property
    def old_path(self) -> Optional[str]:
        """
        Old path of the file. Can be None if the file is added.

        :return: str old_path
        """
        if self._c_diff.a_path:
            return str(Path(self._c_diff.a_path))
        return None

    @property
    def new_path(self) -> Optional[str]:
        """
        New path of the file. Can be None if the file is deleted.

        :return: str new_path
        """
        if self._c_diff.b_path:
            return str(Path(self._c_diff.b_path))
        return None

    @property
    def filename(self) -> str:
        """
        Return the filename. Given a path-like-string (e.g.
        "/Users/dspadini/pydriller/myfile.py") returns only the filename
        (e.g. "myfile.py")

        :return: str filename
        """
        if self.new_path is not None and self.new_path != "/dev/null":
            path = self.new_path
        else:
            assert self.old_path
            path = self.old_path

        return Path(path).name

    @property
    def language_supported(self) -> bool:
        """
        Return whether the language used in the modification can be analyzed by Pydriller.
        Currently only supports Python files.

        :return: True iff language of this Modification can be analyzed.
        """
        return self.filename.endswith('.py')

    @property
    def diff_parsed(self) -> Dict[str, List[Tuple[int, str]]]:
        """
        Returns a dictionary with the added and deleted lines.
        The dictionary has 2 keys: "added" and "deleted", each containing the
        corresponding added or deleted lines. For both keys, the value is a
        list of Tuple (int, str), corresponding to (number of line in the file,
        actual line).

        :return: Dictionary
        """
        lines = self.diff.split("\n")
        # print(self.diff)
        modified_lines = {
            "added": [],
            "deleted": [],
        }  # type: Dict[str, List[Tuple[int, str]]]

        count_deletions = 0
        count_additions = 0

        for line in lines:
            line = line.rstrip()
            count_deletions += 1
            count_additions += 1

            if line.startswith("@@"):
                count_deletions, count_additions = self._get_line_numbers(line)

            if line.startswith("-"):
                modified_lines["deleted"].append((count_deletions, line[1:]))
                count_additions -= 1

            if line.startswith("+"):
                modified_lines["added"].append((count_additions, line[1:]))
                count_deletions -= 1

            if line == r"\ No newline at end of file":
                count_deletions -= 1
                count_additions -= 1

        # assert False
        return modified_lines

    @staticmethod
    def _get_line_numbers(line: str) -> Tuple[int, int]:
        token = line.split(" ")
        numbers_old_file = token[1]
        numbers_new_file = token[2]
        delete_line_number = (
                int(numbers_old_file.split(",")[0].replace("-", "")) - 1
        )
        additions_line_number = int(numbers_new_file.split(",")[0]) - 1
        return delete_line_number, additions_line_number

    @property
    def methods(self) -> List[Method]:
        """
        Return the list of methods in the file. Every method
        contains various information like complexity, loc, name,
        number of parameters, etc.

        :return: list of methods
        """        

        return self._function_list

    @property
    def methods_before(self) -> List[Method]:
        """
        Return the list of methods in the file before the
        change happened. Each method will have all specific
        info, e.g. complexity, loc, name, etc.

        :return: list of methods
        """
        return self._function_list_before
    @property
    def classes(self)-> List[Class]:
        return self._class_list
    
    @property
    def classes_before(self)-> List[Class]:
        return self._class_list_before
    
    @property
    def module_vars(self)-> List[Variable]:
        return self._module_vars

    @property
    def module_vars_before(self)-> List[Variable]:
        return self._module_vars_before

    @property
    def class_vars(self)-> List[Variable]:
        return self._class_vars

    @property
    def class_vars_before(self)-> List[Variable]:
        return self._class_vars_before
    

    @property
    def changed_methods(self) -> List[Method]:
        """
        Return the list of methods that were changed. This analysis
        is more complex because Lizard runs twice: for methods before
        and after the change

        :return: list of methods
        """
        new_methods = self.methods
        old_methods = self.methods_before
        added = self.diff_parsed["added"]
        deleted = self.diff_parsed["deleted"]
        # print(new_methods[0].__dict__)
        # print('deleted',deleted)
        # print('added',added)
        methods_changed_new = {
            y
            for x in added
            for y in new_methods
            if y.start_line <= x[0] <= y.end_line
        }
        methods_changed_old = {
            y
            for x in deleted
            for y in old_methods
            if y.start_line <= x[0] <= y.end_line
        }
        return list(methods_changed_new.union(methods_changed_old))
        # return list(methods_changed_old)

    def _clean_changed_lines(self, changed_lines):
        """
        清理 changed_lines 列表，去除注释、重复行、空行和log/print
        """
        # [(line_num, content) for line_num, content in deleted 
                #   if not content.strip().startswith('#') and content.strip()]
        cleaned_lines = []
        for line_num, content in changed_lines:
            content = content.strip()
            if not len(content):
                continue
            if content.startswith('#'):
                # we will further using regexp to remove the comments of each function
                continue
            if content.startswith('print(') or content.startswith('logger.info('):
                continue  
            cleaned_lines.append((line_num, content))
        return cleaned_lines

    @property
    def cleaned_deleted_lines(self):
        deleted = self.diff_parsed["deleted"]
        return self._clean_changed_lines(deleted)
    
    @property
    def cleaned_added_lines(self):
        added = self.diff_parsed["added"]
        return self._clean_changed_lines(added)

    def find_minimal_enclosing_method(self,line_no, methods):
        """
        查找包含指定行号的最小（最具体）的方法
        处理嵌套函数的情况
        """
        # 收集所有包含该行的methods
        containing_methods = []
        
        for method in methods:
            if method.start_line <= line_no <= method.end_line:
                containing_methods.append(method)
        
        if not containing_methods:
            return None
        
        # 找到最小的包含范围（最内层的嵌套方法）
        # 使用start_line最大的方法，因为嵌套函数的start_line会更大
        min_method = max(containing_methods, key=lambda x: x.start_line)
        
        return min_method
    @property
    def methods_changed_old(self) -> List[Method]:
        """获取在删除行中发生变化的旧方法"""
        old_methods = self.methods_before
        methods_changed_old = set()
        
        for deleted_lines in self.cleaned_deleted_lines:
            line_no = deleted_lines[0]  # 取行号
            enclosing_method = self.find_minimal_enclosing_method(line_no, old_methods)
            if enclosing_method:
                methods_changed_old.add(enclosing_method)
        
        return list(methods_changed_old)

    @property 
    def methods_changed_new(self) -> List[Method]:
        """获取在添加行中发生变化的新方法"""
        new_methods = self.methods
        methods_changed_new = set()
        
        for added_line in self.cleaned_added_lines:
            line_no = added_line[0]  # 取行号
            enclosing_method = self.find_minimal_enclosing_method(line_no, new_methods)
            if enclosing_method:
                methods_changed_new.add(enclosing_method)
        
        return list(methods_changed_new)

    def _get_changed_vars(self, scope_changed_lines, scope='module'):
        """
        获取修改的变量
        """

        # get changed module/class vars
        # changed_module_vars, changed_module_global_vars_lines = self.get_changed_vars(global_added_lines,global_vars)
        # self.changed_global_vars, self.changed_global_vars_lines = self.get_changed_vars(global_added_lines,global_vars)
        # self.changed_class_vars, self.changed_class_vars_lines = self.get_changed_vars(global_added_lines,class_vars)
        # self.changed_vars_called_funcs = analyzer.get_changed_vars_called_functions(changed_global_vars=self.changed_global_vars,changed_class_vars=self.changed_class_vars)
        deleted_lines, added_lines = scope_changed_lines
        if scope =='module':
            scope_vars = self._module_vars
            
            scope_vars_before = self._module_vars_before
        elif scope == 'class':
            scope_vars = self._class_vars
            scope_vars_before = self._class_vars_before
        else:
            assert False
        changed_old_vars = {
            var
            for deleted_line in deleted_lines
            for var in scope_vars_before
            if var.start_line <=deleted_line[0] <= var.end_line
        }

        changed_new_vars = {
            var
            for added_line in added_lines
            for var in scope_vars
            if var.start_line <=added_line[0] <= var.end_line
        }
        changed_vars = list(changed_old_vars.union(changed_new_vars))

        return changed_vars


    def vulnerable_methods(self) -> List[Method]:
        """
        Return the list of methods that were changed. This analysis
        is more complex because Lizard runs twice: for methods before
        and after the change

        :return: list of methods
        """
        old_methods = self.methods_before
        new_methods = self.methods
        deleted = self.cleaned_deleted_lines
 
        methods_changed_old = self.methods_changed_old
        # print("deleted:",deleted)

        added = self.cleaned_added_lines
        # print("added:",added)
        
        # TODO: 对于nested method, 均作保留
        # reason: 外部无法绕开 outer() 直接访问 inner() 
        vul_dict = defaultdict(set)
        # 1. 直接修改的old method
        vulnerable_methods = methods_changed_old
        vulnerable_methods_long_names = {
            y.long_name
            for y in vulnerable_methods
        }
        vul_dict['direct_modified'] = {method.long_name for method in vulnerable_methods}
        

        methods_changed_new = self.methods_changed_new


        vulnerable_methods = list(vulnerable_methods)
        vulnerable_methods = self._filter_vulnerable_methods(vulnerable_methods)

        vulnerable_methods = set(vulnerable_methods)



        # 2. 处理added lines的patch,对old file中的方法,如果只通过added line修复
        new_changed_method_long_names = {
            y.long_name
            for y in methods_changed_new
        }
        
        
        # print('new_changed_method_long_names',new_changed_method_long_names)
        # print('vulnerable_methods_long_names:',vulnerable_methods_long_names)
        # 
        for method in old_methods:
            #同多added lines修改method
            # print(method.long_name)
            if method.long_name in new_changed_method_long_names and method.long_name not in vulnerable_methods_long_names:

                vulnerable_methods.add(method)
                vulnerable_methods_long_names.add(method.long_name)
                vul_dict['only_added_lines_func_exist_in_old_file'].add(method.long_name)
        
                # print('special method:',method.long_name)

        

        
        # check for only comment-changes
        
        
        




        # 3. 处理special methods （新添加的一些方法）
        class_before = {method.first_parent_class for method in old_methods}
        for method in methods_changed_new:
            # class是否存在于old file
            first_parent_class = method.first_parent_class
            # print('first_parent_class',first_parent_class)
            if not first_parent_class or first_parent_class not in class_before:
                continue
            if method.long_name in vulnerable_methods_long_names:
                continue
            if method.name.startswith('__') and method.name.endswith('__'):
                vulnerable_methods_long_names.add(method.long_name)
                vulnerable_methods.add(method)
                vul_dict['special_methods_modified_in_new_file'].add(method.long_name)
                with open('special_methods.txt', 'a') as f:
                    f.write(f"{self.new_path} {self.commit_hash} {method.long_name}\n")


        # 4. funcs (in old_file) calls added funcs 
        old_method_long_names = {
            y.long_name
            for y in old_methods
        }
        added_methods = []
        for method in new_changed_method_long_names:
            if method not in old_method_long_names:
                added_methods.append(method)
        # print(old_method_long_names)
        for method in new_methods:
            caller = method.long_name
            # old method是否存在于old file
            if caller not in old_method_long_names and caller in vulnerable_methods_long_names:
                # skip this method
                continue
            # 如果 caller 不是 changed_methods 中的任何一个，且 caller 调用了 added_methods 中的任何一个
            # print(caller)
            if caller not in new_changed_method_long_names and caller not in added_methods:
                callees = self.cg.get(caller,[])
                # print(f"callees:{callees}")

                inter = set(callees)&set(added_methods)
                if inter:
                    logger.debug(f"vulnerable_methods_long_names:{vulnerable_methods_long_names}")
                    logger.debug(f"added_methods:{added_methods}")
                    logger.debug(f"inter:{inter}")
                
                    # store local
                    # with open('call_added_funcs_vulnerable_methods.txt', 'a') as f:
                    #     f.write(f"{self.new_path} {self.commit_hash} {caller} {inter}\n")
                    vulnerable_methods_long_names.add(caller)
                    vulnerable_methods.add(method)
                    vul_dict['call_added_funcs_vulnerable_methods'].add(method.long_name)
                    # assert False

        # 5. top-level methods
        for long_name in self.top_level_called_funcs_long_names_before:
            if long_name in vulnerable_methods_long_names:
                main_func = self._generate_module_main()
                vulnerable_methods.add(main_func)
                vulnerable_methods_long_names.add(main_func.long_name)
                vul_dict['top_level_vulnerable_call'].add(method.long_name)
                # break
        
        # 6. global var CVE-2024-27351
        # get changed global vars
        vulnerable_methods_cnt = len(vulnerable_methods)
        if self.changed_vars_called_funcs_before:
            for func in self.changed_vars_called_funcs_before:
                # func.first class in class_before
                if vulnerable_methods_cnt == 0:
                    vulnerable_methods.add(func)
                    vulnerable_methods_long_names.add(func.long_name)
                vul_dict['funcs_call_direct_modified_changed_vars'].add(func.long_name)
        if self.changed_vars_called_funcs:
            new_changed_vars_called_funcs_long_names = set()
            for func in self.changed_vars_called_funcs:
                # func.first class in class_before
                new_changed_vars_called_funcs_long_names.add(func.long_name)
            if len(new_changed_vars_called_funcs_long_names):
                logger.warning(f"new_changed_vars_called_funcs_long_names: {new_changed_vars_called_funcs_long_names}")
            for method in old_methods:
                #同多added lines修改method
                # print(method.long_name)
                if method.long_name in new_changed_vars_called_funcs_long_names and method.long_name not in vulnerable_methods_long_names:
                    if vulnerable_methods_cnt == 0:
                        vulnerable_methods.add(method)
                        vulnerable_methods_long_names.add(method.long_name)
                    vul_dict['funcs_call_only_added_lines_changed_vars'].add(method.long_name)
        
   



        self.vul_dict = vul_dict
        return list(vulnerable_methods)

    # def _get_changed_methods(self,changed_lines):

    def _generate_module_main(self):
        func_info = {
            'name': '<main>',
            'long_name': self._get_module_name() + '.<main>',
            'signature': '',
            'filename': '',  # Will be set externally
            'parameters': '',
            'start_line': 0,
            'end_line': -1,
            'code': '',
            'before_change':None,
            'decorators': '',
            'first_parent_class': None
        }
        
        return Method(SimpleNamespace(**func_info))
    def _filter_vulnerable_methods(self,vulnerable_methods):
        filtered_methods = []

        old_methods = self.methods_before
        deleted = self.diff_parsed["deleted"]
        new_methods = self.methods
        added = self.diff_parsed["added"]
        added = self._clean_changed_lines(added)
        deleted = self._clean_changed_lines(deleted)
        methods_changed_new = {
            new_method.long_name:new_method
            for new_method in  self.methods_changed_new
        }
        methods_changed_old = {
            old_method.long_name:old_method
            for old_method in  self.methods_changed_old
        }
        # 去除空白字符后判断是否完全一样
        
        for method in vulnerable_methods:
            if not method.long_name:  # Handle empty name case
                continue
                
            old_method = methods_changed_old.get(method.long_name)
            new_method = methods_changed_new.get(method.long_name)
            
            if old_method and new_method:  # Ensure both methods exist
                try:
                    # Use regex to handle all whitespace characters
                    import re
                    old_code = old_method.code or ''
                    new_code = new_method.code or ''
                    old_method_source_code = re.sub(r'\s+', '', old_code)
                    new_method_source_code = re.sub(r'\s+', '', new_code)
                    
                    if old_method_source_code != new_method_source_code:
                        filtered_methods.append(method)
                except Exception as e:
                    logger.warning(f"Error comparing methods {method.long_name}: {e}")
                    filtered_methods.append(method)  # Conservative handling on error
            else:
                filtered_methods.append(method)
        return filtered_methods
    
    
    def _get_direct_method_changes(self):
        old_methods = self.methods_before
        deleted = self.diff_parsed["deleted"]
 
        methods_changed_old = {
            old_method
            for deleted_lines in deleted
            for old_method in old_methods
            if old_method.start_line <= deleted_lines[0] <= old_method.end_line
        }

        vulnerable_methods = methods_changed_old
        new_methods = self.methods
        added = self.diff_parsed["added"]
        methods_changed_new = {
            new_method
            for added_line in added
            for new_method in new_methods
            if new_method.start_line <= added_line[0] <= new_method.end_line
        }
        new_changed_method_long_names = {
            y.long_name
            for y in methods_changed_new
        }
        vulnerable_methods_long_names = {
            y.long_name
            for y in vulnerable_methods
        }
        # print(new_changed_method_long_names)
        for method in old_methods:
            #同多added lines修改method
            if method.long_name in new_changed_method_long_names and method.long_name not in vulnerable_methods_long_names:
                vulnerable_methods.add(method)
        return list(vulnerable_methods)
    
    def _get_global_code_changes(self,changed_lines,changed_methods):
        global_changes = []
        method_changes = []
        for line in changed_lines:
            if not any(method.start_line <= line[0] <= method.end_line for method in changed_methods):
                global_changes.append(line)
            else:
                method_changes.append(line)
        return global_changes, method_changes
        
    def get_vulnerable_methods(self):
        affected_methods = set()
        
        # 获取直接修改的方法
        direct_changes = self._get_direct_method_changes()
        affected_methods.update(direct_changes)

        # 查找方法外部的修改的类型
        global_deleted, global_added = self._get_global_code_changes()
        
        

        # 检查导入依赖
        import_deps = self.find_import_dependent_methods(self.modified_imports)
        affected_methods.update(import_deps)

        assert False
        
        # 获取受变量和装饰器影响的方法
        var_decorator_deps = self.find_affected_methods(self.modified_lines)
        affected_methods.update(var_decorator_deps)
    
        
        # 检查类属性依赖
        class_deps = self.find_affected_class_methods(self.modified_lines)
        affected_methods.update(class_deps)
        
        # 检查全局配置依赖
        global_deps = self.find_global_config_dependents(self.modified_globals)
        affected_methods.update(global_deps)
        
        # 检查上下文依赖
        context_deps = self.find_context_dependent_methods(self.modified_lines)
        affected_methods.update(context_deps)
        
        
        return affected_methods
    
    
    def find_affected_class_methods(self, modified_lines):
        affected_methods = set()
        
        # 获取修改行所在的类
        modified_class = self._get_containing_class(modified_lines)
        if not modified_class:
            return affected_methods
            
        # 分析修改是否涉及类属性
        modified_attrs = self._get_modified_class_attrs(modified_lines)
        
        # 检查类中的所有方法是否使用了这些属性
        for method in modified_class.methods:
            if self._method_uses_attrs(method, modified_attrs):
                affected_methods.add(method)
                
        return affected_methods
    def find_import_dependent_methods(self, modified_imports):
        affected_methods = set()
        
        # 解析修改的导入
        import_changes = self._parse_import_changes(modified_imports)
        
        # 遍历所有方法，检查是否使用了修改的导入
        for method in self.methods:
            method_content = self._get_method_content(method)
            if any(imp in method_content for imp in import_changes):
                affected_methods.add(method)
                
        return affected_methods
    def find_context_dependent_methods(self, modified_lines):
        affected_methods = set()
        
        # 分析修改是否涉及上下文管理
        context_changes = self._analyze_context_changes(modified_lines)
        if not context_changes:
            return affected_methods
            
        # 检查哪些方法依赖于这些上下文
        for method in self.methods:
            if self._method_depends_on_context(method, context_changes):
                affected_methods.add(method)
                
        return affected_methods
    def find_global_config_dependents(self, modified_globals):
        affected_methods = set()
        
        # 解析修改的全局配置
        global_changes = self._parse_global_changes(modified_globals)
        
        # 使用AST分析器遍历所有方法
        for method in self.methods:
            ast_tree = self._parse_method_to_ast(method)
            if self._ast_uses_globals(ast_tree, global_changes):
                affected_methods.add(method)
                
        return affected_methods
    # 添加对修改的变量和装饰器的处理
    
    def find_affected_methods(modified_line: Tuple[int, str], methods: List[Method]) -> Set[Method]:
        affected = set()
        # 1. 检查是否是变量定义
        if '=' in modified_line[1] and not modified_line[1].strip().startswith('def'):
            var_name = modified_line[1].split('=')[0].strip()
            # 遍历所有方法的代码，查找使用了这个变量的方法
            for method in methods:
                if var_name in method.code:
                    affected.add(method)
        # 对类属性的修改

        # 对import语句的修改
        
        # 2. 检查是否是装饰器
        if modified_line[1].strip().startswith('@'):
            print('modified_line:',modified_line)
            decorator_name = modified_line[1].strip('@').split('(')[0].strip()
            # 查找下一个方法定义
            for method in methods:
                if method.start_line > modified_line[0] and decorator_name in method.code:
                    affected.add(method)
        
        return affected
    

    def get_changed_vars(self, global_changed_lines, global_vars):
        """
        获取修改的变量
        """
        changed_vars = set()
        changed_vars_lines = []
        for var in global_vars:
            for line in global_changed_lines:
                if var[1][0] <= line[0] <= var[1][1]:
                    changed_vars.add(var)
                    changed_vars_lines.append(line)
        return changed_vars, changed_vars_lines


    def _get_function_list(self,include_before: bool = False) -> None:
        if not self.language_supported:
            assert False
            return
        if self.source_code and not self._function_list:
            try:
                analyzer = CodeChangeAnalyzer(source_code=self.source_code,commit_hash=self.commit_hash,file_path=self.new_path,change_before=False)
                self._function_list = [Method(func) for func in analyzer.get_functions()]
            except:
                assert False
                ...
        if (
                include_before
                and self.source_code_before
                and not self._function_list_before
        ):
            try:

                analyzer = CodeChangeAnalyzer(source_code=self.source_code_before,commit_hash=self.commit_hash,file_path=self.old_path,change_before=True)
                self._function_list_before = [Method(func) for func in analyzer.get_functions()]
            except:
                assert False
                ...
    def _calculate_metrics(self, include_before: bool = False) -> None:
        """
        :param include_before: either to compute the metrics
        for source_code_before, i.e. before the change happened
        """
        if not self.language_supported:
            assert False
            return
            
        # Use tree-sitter to parse code

        if self.source_code and not self._function_list:
            try:
                analyzer = CodeChangeAnalyzer(source_code=self.source_code,commit_hash=self.commit_hash,file_path=self.new_path,change_before=False)
                self._function_list = [Method(func) for func in analyzer.get_functions()]
                # classifying the code changes
                # 1. Belongs to method
                # 2. Belongs to class
                # 3. Belongs to module
                
                
                
                #获取global code changes
                global_added_lines,self.method_added_lines = self._get_global_code_changes(self.cleaned_added_lines,self._function_list)
                #获取global_vars
                global_vars, class_vars = analyzer.extract_global_vars(), analyzer.extract_class_vars()
                # logger.debug(f'global_vars: {global_vars}, class_vars: {class_vars}, global_added_lines: {global_added_lines}')
                self.changed_global_vars, self.changed_global_vars_lines = self.get_changed_vars(global_added_lines,global_vars)
                self.changed_class_vars, self.changed_class_vars_lines = self.get_changed_vars(global_added_lines,class_vars)
                logger.debug(f'changed_global_vars: {self.changed_global_vars}, changed_class_vars: {self.changed_class_vars}')
                logger.debug(f'changed_global_vars_lines: {self.changed_global_vars_lines}, changed_class_vars_lines: {self.changed_class_vars_lines}')
                self.other_added_lines = []
                for line in global_added_lines:
                    if line not in self.changed_global_vars_lines and line not in self.changed_class_vars_lines:
                        self.other_added_lines.append(line)
                
                

                self.top_level_called_funcs_long_names = analyzer.get_top_level_called_functions()
                self.changed_vars_called_funcs = analyzer.get_changed_vars_called_functions(changed_global_vars=self.changed_global_vars,changed_class_vars=self.changed_class_vars)
                self.cg = analyzer.cg

            except Exception as e:
                logger.debug(f"Could not parse {self.filename} using tree-sitter: {str(e)}")
                assert False
                return
        elif not self.source_code:
            self.cg = None
            self.top_level_called_funcs_long_names = []
            self.changed_class_vars = []
            self.changed_global_vars = []
            self.changed_vars_called_funcs = []
            self.method_added_lines = []
            self.changed_global_vars_lines = []
            self.changed_class_vars_lines = []
            self.other_added_lines=[]



        if (
                include_before
                and self.source_code_before
                and not self._function_list_before
        ):
            try:

                analyzer = CodeChangeAnalyzer(source_code=self.source_code_before,commit_hash=self.commit_hash,file_path=self.old_path,change_before=True)
                self._function_list_before = [Method(func) for func in analyzer.get_functions()]

         
                global_deleted_lines,self.method_deleted_lines = self._get_global_code_changes(self.cleaned_deleted_lines,self._function_list_before)
                #获取global_vars

                global_vars, class_vars = analyzer.extract_global_vars(), analyzer.extract_class_vars()
                # logger.debug(f'global_vars: {self.global_vars_before}')

                # print('self.global_deleted_lines:',self.global_added_lines)
                # print('self.global_vars_before:',self.global_vars_before)

                global_vars_before, class_vars_before = analyzer.extract_global_vars(), analyzer.extract_class_vars()
                self.changed_global_vars_before, self.changed_global_vars_lines_before = self.get_changed_vars(global_deleted_lines,global_vars_before)
                self.changed_class_vars_before, self.changed_class_vars_lines_before = self.get_changed_vars(global_deleted_lines,class_vars_before)

                logger.info(f"changed_global_vars_before: {self.changed_global_vars_before}, changed_class_vars_before: {self.changed_class_vars_before}")
                logger.info(f"changed_global_vars_lines_before: {self.changed_global_vars_lines_before}, changed_class_vars_lines_before: {self.changed_class_vars_lines_before}")
                self.other_deleted_lines = []
                for line in global_deleted_lines:
                    if line not in self.changed_global_vars_lines_before and line not in self.changed_class_vars_lines_before:
                        self.other_deleted_lines.append(line)

                

                self.top_level_called_funcs_long_names_before = analyzer.get_top_level_called_functions()


                self.changed_vars_called_funcs_before = analyzer.get_changed_vars_called_functions(self.changed_global_vars_before,self.changed_class_vars_before )
                self.cg_before = analyzer.cg

                # TODO:处理调用added methods
            except SyntaxError:
                logger.debug(f"Could not parse {self.filename} before version using tree-sitter")
                assert False
                return
        elif not self.source_code_before:
            self.cg_before = None
            self.top_level_called_funcs_long_names_before = []
            self.changed_vars_called_funcs_before = []
            self.changed_class_vars_before = []
            self.changed_global_vars_before = []
            self.method_deleted_lines = []
            self.changed_global_vars_lines_before = []
            self.changed_class_vars_lines_before = []
            self.other_deleted_lines=[]


        def classify_code_changes():
            type_dict = {
                'module': 0,
                'class': 0,
                'function': 0
            }             
            type_dict['method'] = len(self.method_added_lines) + len(self.method_deleted_lines)
            type_dict['global_var'] = len(self.changed_global_vars_lines) + len(self.changed_global_vars_lines_before)
            type_dict['class_var'] = len(self.changed_class_vars_lines) + len(self.changed_class_vars_lines_before)
            type_dict['other'] = len(self.other_added_lines) + len(self.other_deleted_lines)
            return type_dict
        self.type_dict = classify_changes()
        print(self.type_dict)
        # assert False

            

    def _get_decoded_content(self, content: bytes) -> Optional[str]:
        try:
            return content.decode("utf-8", "ignore")
        except (AttributeError, ValueError):
            logger.debug("Could not load the content for file %s", self.filename)
            return None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ModifiedFile):
            return NotImplemented
        if self is other:
            return True
        return self.__dict__ == other.__dict__


class Commit:
    """
    Class representing a Commit. Contains all the important information such
    as hash, author, dates, and modified files.
    """

    def __init__(self, commit: GitCommit, conf) -> None:
        """
        Create a commit object.

        :param commit: GitPython Commit object
        :param conf: Configuration class
        """
        self._c_object = commit
        self._conf = conf
        self._stats_cache = None

    def __hash__(self) -> int:
        """
        Since already used in Git for identification use the SHA of the commit
        as hash value.

        :return: int hash
        """
        # Unfortunately, the Git hash cannot be used for the Python object
        # directly. The documentation says it "should" return an integer
        # https://docs.python.org/3/reference/datamodel.html#object.__hash__
        # but I just learned it **has** to return one.
        return hash(self._c_object.hexsha)

    @property
    def hash(self) -> str:
        """
        Return the SHA of the commit.

        :return: str hash
        """
        return self._c_object.hexsha

    @property
    def author(self) -> Developer:
        """
        Return the author of the commit as a Developer object.

        :return: author
        """
        return self._conf.get("developer_factory").get_developer(
            self._c_object.author.name, self._c_object.author.email
        )

    @property
    def co_authors(self) -> List[Developer]:
        """
        Return the co-authors of the commit as a list of Developer objects.

        :return: List[Developer] author
        """
        co_authors = []
        for co_author in self._c_object.co_authors:
            d = self._conf.get("developer_factory").get_developer(
                co_author.name, co_author.email
            )
            co_authors.append(d)

        return co_authors

    @property
    def committer(self) -> Developer:
        """
        Return the committer of the commit as a Developer object.

        :return: committer
        """
        return self._conf.get("developer_factory").get_developer(
            self._c_object.committer.name, self._c_object.committer.email
        )

    @property
    def project_name(self) -> str:
        """
        Return the project name.

        :return: project name
        """
        return Path(self._conf.get("path_to_repo")).name

    @property
    def project_path(self) -> str:
        """
        Return the absolute path of the project.

        :return: project path
        """
        return str(Path(self._conf.get("path_to_repo")))

    @property
    def author_date(self) -> datetime:
        """
        Return the authored datetime.

        :return: datetime author_datetime
        """
        return self._c_object.authored_datetime

    @property
    def committer_date(self) -> datetime:
        """
        Return the committed datetime.

        :return: datetime committer_datetime
        """
        return self._c_object.committed_datetime

    @property
    def author_timezone(self) -> int:
        """
        Author timezone expressed in seconds from epoch.

        :return: int timezone
        """
        return int(self._c_object.author_tz_offset)

    @property
    def committer_timezone(self) -> int:
        """
        Author timezone expressed in seconds from epoch.

        :return: int timezone
        """
        return int(self._c_object.committer_tz_offset)

    @property
    def msg(self) -> str:
        """
        Return commit message.

        :return: str commit_message
        """
        return str(self._c_object.message.strip())

    @property
    def parents(self) -> List[str]:
        """
        Return the list of parents SHAs.

        :return: List[str] parents
        """
        parents = []
        for p in self._c_object.parents:
            parents.append(p.hexsha)
        return parents

    @property
    def merge(self) -> bool:
        """
        Return True if the commit is a merge, False otherwise.

        :return: bool merge
        """
        return len(self._c_object.parents) > 1

    def _stats(self):
        if self._stats_cache is not None:
            return self._stats_cache

        if len(self.parents) == 0:
            text = self._conf.get('git').repo.git.diff_tree(self.hash, "--", numstat=True, root=True)
            text2 = ""
            for line in text.splitlines()[1:]:
                (insertions, deletions, filename) = line.split("\t")
                text2 += "%s\t%s\t%s\n" % (insertions, deletions, filename)
            text = text2
        else:
            text = self._conf.get('git').repo.git.diff(self._c_object.parents[0].hexsha, self._c_object.hexsha, "--", numstat=True, root=True)
        print('text:', text)
        self._stats_cache = self._list_from_string(text)
        return self._stats_cache

    def _list_from_string(self, text: str):
        total = {"insertions": 0, "deletions": 0, "lines": 0, "files": 0}

        for line in text.splitlines():
            (raw_insertions, raw_deletions, _) = line.split("\t")
            insertions = raw_insertions != "-" and int(raw_insertions) or 0
            deletions = raw_deletions != "-" and int(raw_deletions) or 0
            total["insertions"] += insertions
            total["deletions"] += deletions
            total["lines"] += insertions + deletions
            total["files"] += 1

        return total

    @property
    def insertions(self) -> int:
        """
        Return the number of added lines in the commit (as shown from --shortstat).

        :return: int insertion lines
        """
        return self._stats()["insertions"]

    @property
    def deletions(self) -> int:
        """
        Return the number of deleted lines in the commit (as shown from --shortstat).

        :return: int deletion lines
        """
        return self._stats()["deletions"]

    @property
    def lines(self) -> int:
        """
        Return the number of modified lines in the commit (as shown from --shortstat).

        :return: int insertion + deletion lines
        """
        return self._stats()["lines"]

    @property
    def files(self) -> int:
        """
        Return the number of modified files of the commit (as shown from --shortstat).

        :return: int modified files number
        """
        return self._stats()["files"]

    @property
    def modified_files(self) -> List[ModifiedFile]:
        """
        Return a list of modified files. The list is empty if the commit is
        a merge commit. For more info on this, see
        https://haacked.com/archive/2014/02/21/reviewing-merge-commits/ or
        https://github.com/ishepard/pydriller/issues/89#issuecomment-590243707

        :return: List[Modification] modifications
        """
        options = {}
        if self._conf.get("histogram"):
            options["histogram"] = True

        if self._conf.get("skip_whitespaces"):
            options["w"] = True
            options['ignore-blank-lines'] = True
        
        #忽略上下文
        options["unified"] = 0

        if len(self.parents) == 1:
            # the commit has a parent
            diff_index: Any = self._c_object.parents[0].diff(
                other=self._c_object, paths=None, create_patch=True, **options
            )
        elif len(self.parents) > 1:
            # if it's a merge commit, the modified files of the commit are the
            # conflicts. This because if the file is not in conflict,
            # pydriller will visit the modification in one of the previous
            # commits. However, parsing the output of a combined diff (that
            # returns the list of conflicts) is challenging: so, right now,
            # I will return an empty array, in the meanwhile I will try to
            # find a way to parse the output.
            # return []
            # 修改了原pydriller的逻辑
            # diff_index = []
            # diff_index = self._c_object.diff(paths=None, create_patch=True, **options)
            # print('self._c_object.diff():',self._c_object.diff())
            # modified_files_a = self._parse_diff(self._c_object.parents[0].diff(
            #     other=self._c_object, paths=None, create_patch=True, **options
            # ))
            # modified_files_b = self._parse_diff(self._c_object.parents[0].diff(
            #     other=self._c_object, paths=None, create_patch=True, **options
            # ))
            # modified_files = set(modified_files_a).union(set(modified_files_b))
            # # print(modified_files)
            # # print('parents:', self._c_object.parents)
            # # print(self._c_object.diff(
            # #     NULL_TREE, paths=None, create_patch=True, **options
            # # ))
            # print('modified_files:', [file.filename for file in modified_files])
            # return  modified_files

            # 对https://github.com/SignalR/SignalR/commit/cc5b002a5140e2d60184de42554a8737981c846c不适用
            # diff_index: Any = self._c_object.parents[0].diff(
            #     other=self._c_object.parents[1], paths=None, create_patch=True, **options
            # )
            return []
        else:
            # this is the first commit of the repo. Comparing it with git
            # NULL TREE
            diff_index = self._c_object.diff(
                NULL_TREE, paths=None, create_patch=True, **options
            )

        return self._parse_diff(diff_index)

    def _parse_diff(self, diff_index: List[Diff]) -> List[ModifiedFile]:
        modified_files_list = []
        for diff in diff_index:
            modified_files_list.append(
                ModifiedFile(diff=diff,commit_hash=self.hash)
            )
        return modified_files_list

    @property
    def in_main_branch(self) -> bool:
        """
        Return True if the commit is in the main branch, False otherwise.

        :return: bool in_main_branch
        """
        return self._conf.get("main_branch") in self.branches

    @property
    def branches(self) -> Set[str]:
        """
        Return the set of branches that contain the commit.

        :return: set(str) branches
        """
        c_git = Git(str(self._conf.get("path_to_repo")))
        branches = set()
        args = ["--contains", self.hash]
        if self._conf.get("include_remotes"):
            args = ["-r"] + args
        if self._conf.get("include_refs"):
            args = ["-a"] + args
        for branch in set(c_git.branch(*args).split("\n")):
            branches.add(branch.strip().replace("* ", ""))
        return branches

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Commit):
            return NotImplemented
        if self is other:
            return True

        return self.__dict__ == other.__dict__
