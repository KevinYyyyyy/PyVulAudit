#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python Call Chain Constraint Analysis Module

专门针对Python项目的CVE漏洞call chain路径约束收集和验证框架
实现Python AST解析、静态分析、LLM分析和混合验证策略
"""

import json
import ast
import re
import inspect
import types
from typing import List, Dict, Any, Optional, Tuple, Union, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConstraintType(Enum):
    """约束类型枚举"""
    VALIDATION = "validation"
    SANITIZATION = "sanitization" 
    REACHABILITY = "reachability"
    EXPLOITABILITY = "exploitability"
    TYPE_CHECK = "type_check"
    NULL_CHECK = "null_check"
    RANGE_CHECK = "range_check"
    PRECONDITION = "precondition"
    IMPORT_CHECK = "import_check"
    EXCEPTION_HANDLING = "exception_handling"
    ATTRIBUTE_ACCESS = "attribute_access"

@dataclass
class PathConstraint:
    """路径约束数据结构"""
    type: ConstraintType
    condition: str
    variables: List[str]
    location: str
    bypassable: Optional[bool] = None
    confidence: float = 0.0
    ast_node_type: Optional[str] = None
    line_number: Optional[int] = None
    
@dataclass
class PythonFunctionInfo:
    """Python函数信息"""
    name: str
    file_path: str
    line_number: int
    source_code: str
    ast_node: Optional[ast.FunctionDef] = None
    parameters: List[Dict] = field(default_factory=list)
    return_type: Optional[str] = None
    decorators: List[str] = field(default_factory=list)
    docstring: Optional[str] = None
    imports: List[str] = field(default_factory=list)
    
class PythonASTAnalyzer(ast.NodeVisitor):
    """Python AST分析器"""
    
    def __init__(self):
        self.functions = {}
        self.imports = []
        self.calls = []
        self.conditions = []
        self.exceptions = []
        self.current_function = None
        
    def visit_Import(self, node):
        """访问import语句"""
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)
        
    def visit_ImportFrom(self, node):
        """访问from...import语句"""
        module = node.module or ''
        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.imports.append(full_name)
        self.generic_visit(node)
        
    def visit_FunctionDef(self, node):
        """访问函数定义"""
        self.current_function = node.name
        
        # 提取函数信息
        func_info = {
            'name': node.name,
            'line_number': node.lineno,
            'parameters': self._extract_parameters(node),
            'decorators': [self._get_decorator_name(d) for d in node.decorator_list],
            'docstring': ast.get_docstring(node),
            'ast_node': node
        }
        
        self.functions[node.name] = func_info
        self.generic_visit(node)
        self.current_function = None
        
    def visit_Call(self, node):
        """访问函数调用"""
        call_info = {
            'function': self._get_call_name(node),
            'line_number': node.lineno,
            'args': len(node.args),
            'keywords': [kw.arg for kw in node.keywords],
            'in_function': self.current_function
        }
        self.calls.append(call_info)
        self.generic_visit(node)
        
    def visit_If(self, node):
        """访问if语句"""
        condition_info = {
            'type': 'if',
            'line_number': node.lineno,
            'condition': self._ast_to_string(node.test),
            'in_function': self.current_function
        }
        self.conditions.append(condition_info)
        self.generic_visit(node)
        
    def visit_Try(self, node):
        """访问try语句"""
        exception_info = {
            'line_number': node.lineno,
            'handlers': [self._get_exception_type(handler) for handler in node.handlers],
            'in_function': self.current_function
        }
        self.exceptions.append(exception_info)
        self.generic_visit(node)
        
    def _extract_parameters(self, func_node):
        """提取函数参数信息"""
        params = []
        
        # 普通参数
        for arg in func_node.args.args:
            param_info = {
                'name': arg.arg,
                'type': self._get_annotation_string(arg.annotation) if arg.annotation else None,
                'kind': 'positional'
            }
            params.append(param_info)
            
        # 默认参数
        defaults = func_node.args.defaults
        if defaults:
            default_offset = len(func_node.args.args) - len(defaults)
            for i, default in enumerate(defaults):
                if default_offset + i < len(params):
                    params[default_offset + i]['default'] = self._ast_to_string(default)
                    
        # *args
        if func_node.args.vararg:
            params.append({
                'name': func_node.args.vararg.arg,
                'type': self._get_annotation_string(func_node.args.vararg.annotation) if func_node.args.vararg.annotation else None,
                'kind': 'vararg'
            })
            
        # **kwargs
        if func_node.args.kwarg:
            params.append({
                'name': func_node.args.kwarg.arg,
                'type': self._get_annotation_string(func_node.args.kwarg.annotation) if func_node.args.kwarg.annotation else None,
                'kind': 'kwarg'
            })
            
        return params
        
    def _get_call_name(self, call_node):
        """获取函数调用名称"""
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            return f"{self._ast_to_string(call_node.func.value)}.{call_node.func.attr}"
        else:
            return self._ast_to_string(call_node.func)
            
    def _get_decorator_name(self, decorator):
        """获取装饰器名称"""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            return f"{self._ast_to_string(decorator.value)}.{decorator.attr}"
        else:
            return self._ast_to_string(decorator)
            
    def _get_annotation_string(self, annotation):
        """获取类型注解字符串"""
        if annotation:
            return self._ast_to_string(annotation)
        return None
        
    def _get_exception_type(self, handler):
        """获取异常处理类型"""
        if handler.type:
            return self._ast_to_string(handler.type)
        return 'Exception'
        
    def _ast_to_string(self, node):
        """将AST节点转换为字符串"""
        try:
            return ast.unparse(node)
        except:
            # 兼容旧版本Python
            return str(node)
            
class PythonCallChainAnalyzer:
    """Python专用Call Chain约束分析器"""
    
    def __init__(self):
        self.python_sanitizers = [
            # 输入验证
            'validate', 'check', 'verify', 'assert',
            # 字符串处理
            'escape', 'quote', 'encode', 'decode', 'strip', 'clean',
            # 类型转换
            'int', 'float', 'str', 'bool', 'list', 'dict',
            # 安全函数
            'safe_eval', 'literal_eval', 'sanitize',
            # 正则表达式
            'match', 'search', 'findall', 'sub',
            # HTML/XML处理
            'escape_html', 'escape_xml', 'bleach',
            # SQL处理
            'escape_sql', 'quote_sql'
        ]
        
        self.dangerous_functions = [
            'eval', 'exec', 'compile', '__import__',
            'open', 'file', 'input', 'raw_input',
            'subprocess.call', 'subprocess.run', 'os.system',
            'pickle.loads', 'yaml.load', 'marshal.loads'
        ]
        
    def analyze_python_call_chain(self, call_chain: List[PythonFunctionInfo], cve_info: Dict) -> Dict:
        """
        分析Python call chain的主入口函数
        
        Args:
            call_chain: Python函数调用链
            cve_info: CVE漏洞信息
            
        Returns:
            分析结果字典
        """
        logger.info(f"开始分析Python call chain，长度: {len(call_chain)}")
        
        # 1. Python特定的静态分析
        static_result = self.python_static_analysis(call_chain)
        
        # 2. AST深度分析
        ast_result = self.ast_deep_analysis(call_chain)
        
        # 3. 合并分析结果
        combined_result = self.combine_analysis_results(static_result, ast_result)
        
        # 4. LLM分析（如果需要）
        llm_result = self.llm_analyze_python_constraints(call_chain, combined_result, cve_info)
        
        # 5. 最终验证
        final_result = self.python_hybrid_validation(combined_result, llm_result)
        
        return final_result
        
    def python_static_analysis(self, call_chain: List[PythonFunctionInfo]) -> Dict:
        """
        Python特定的静态分析
        """
        analysis_result = {
            'reachability': None,
            'constraints': [],
            'sanitization_points': [],
            'dangerous_calls': [],
            'import_risks': [],
            'type_hints': [],
            'exception_handling': [],
            'confidence': 0.0
        }
        
        try:
            # 1. 可达性分析
            analysis_result['reachability'] = self.analyze_python_reachability(call_chain)
            
            # 2. 约束收集
            analysis_result['constraints'] = self.collect_python_constraints(call_chain)
            
            # 3. 危险函数检测
            analysis_result['dangerous_calls'] = self.detect_dangerous_calls(call_chain)
            
            # 4. 防护机制检测
            analysis_result['sanitization_points'] = self.detect_python_sanitization(call_chain)
            
            # 5. 导入风险分析
            analysis_result['import_risks'] = self.analyze_import_risks(call_chain)
            
            # 6. 类型提示分析
            analysis_result['type_hints'] = self.analyze_type_hints(call_chain)
            
            # 7. 异常处理分析
            analysis_result['exception_handling'] = self.analyze_exception_handling(call_chain)
            
            # 8. 计算置信度
            analysis_result['confidence'] = self.calculate_python_confidence(analysis_result)
            
        except Exception as e:
            logger.error(f"Python静态分析出错: {e}")
            analysis_result['error'] = str(e)
            
        return analysis_result
        
    def ast_deep_analysis(self, call_chain: List[PythonFunctionInfo]) -> Dict:
        """
        基于AST的深度分析
        """
        ast_results = {
            'function_calls': [],
            'control_flows': [],
            'data_flows': [],
            'variable_usage': {},
            'scope_analysis': {}
        }
        
        for func_info in call_chain:
            if func_info.ast_node:
                analyzer = PythonASTAnalyzer()
                analyzer.visit(func_info.ast_node)
                
                ast_results['function_calls'].extend(analyzer.calls)
                ast_results['control_flows'].extend(analyzer.conditions)
                
                # 变量使用分析
                variables = self.extract_variables_from_ast(func_info.ast_node)
                ast_results['variable_usage'][func_info.name] = variables
                
        return ast_results
        
    def extract_variables_from_ast(self, ast_node) -> Dict:
        """
        从AST中提取变量信息
        """
        variables = {
            'assignments': [],
            'references': [],
            'parameters': [],
            'globals': [],
            'nonlocals': []
        }
        
        class VariableVisitor(ast.NodeVisitor):
            def visit_Assign(self, node):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        variables['assignments'].append({
                            'name': target.id,
                            'line': node.lineno,
                            'value': ast.unparse(node.value) if hasattr(ast, 'unparse') else str(node.value)
                        })
                self.generic_visit(node)
                
            def visit_Name(self, node):
                if isinstance(node.ctx, ast.Load):
                    variables['references'].append({
                        'name': node.id,
                        'line': node.lineno
                    })
                self.generic_visit(node)
                
            def visit_Global(self, node):
                variables['globals'].extend(node.names)
                self.generic_visit(node)
                
            def visit_Nonlocal(self, node):
                variables['nonlocals'].extend(node.names)
                self.generic_visit(node)
                
        visitor = VariableVisitor()
        visitor.visit(ast_node)
        
        return variables
        
    def detect_dangerous_calls(self, call_chain: List[PythonFunctionInfo]) -> List[Dict]:
        """
        检测危险函数调用
        """
        dangerous_calls = []
        
        for func_info in call_chain:
            source_code = func_info.source_code
            
            for dangerous_func in self.dangerous_functions:
                if dangerous_func in source_code:
                    # 更精确的检测
                    pattern = rf'\b{re.escape(dangerous_func)}\s*\('
                    matches = re.finditer(pattern, source_code)
                    
                    for match in matches:
                        dangerous_calls.append({
                            'function': dangerous_func,
                            'location': func_info.name,
                            'line_estimate': source_code[:match.start()].count('\n') + func_info.line_number,
                            'risk_level': self.assess_function_risk(dangerous_func),
                            'context': source_code[max(0, match.start()-50):match.end()+50]
                        })
                        
        return dangerous_calls
        
    def detect_python_sanitization(self, call_chain: List[PythonFunctionInfo]) -> List[Dict]:
        """
        检测Python特定的防护机制
        """
        sanitization_points = []
        
        for func_info in call_chain:
            source_code = func_info.source_code
            
            # 1. 检测输入验证
            validation_patterns = [
                r'isinstance\s*\(',
                r'hasattr\s*\(',
                r'len\s*\([^)]+\)\s*[<>=]',
                r'assert\s+',
                r'raise\s+\w+Error',
                r'if\s+not\s+\w+:'
            ]
            
            for pattern in validation_patterns:
                matches = re.finditer(pattern, source_code)
                for match in matches:
                    sanitization_points.append({
                        'type': 'validation',
                        'pattern': pattern,
                        'location': func_info.name,
                        'line_estimate': source_code[:match.start()].count('\n') + func_info.line_number,
                        'effectiveness': 0.7,
                        'context': source_code[max(0, match.start()-30):match.end()+30]
                    })
            
            # 2. 检测字符串处理
            for sanitizer in self.python_sanitizers:
                if sanitizer in source_code:
                    pattern = rf'\b{re.escape(sanitizer)}\s*\('
                    matches = re.finditer(pattern, source_code)
                    
                    for match in matches:
                        sanitization_points.append({
                            'type': 'sanitization',
                            'function': sanitizer,
                            'location': func_info.name,
                            'line_estimate': source_code[:match.start()].count('\n') + func_info.line_number,
                            'effectiveness': self.estimate_python_sanitizer_effectiveness(sanitizer),
                            'context': source_code[max(0, match.start()-30):match.end()+30]
                        })
                        
        return sanitization_points
        
    def analyze_import_risks(self, call_chain: List[PythonFunctionInfo]) -> List[Dict]:
        """
        分析导入相关的风险
        """
        import_risks = []
        risky_modules = [
            'pickle', 'marshal', 'shelve', 'dill',
            'subprocess', 'os', 'sys', 'importlib',
            'eval', 'exec', '__builtin__', 'builtins'
        ]
        
        for func_info in call_chain:
            for import_name in func_info.imports:
                for risky_module in risky_modules:
                    if risky_module in import_name:
                        import_risks.append({
                            'module': import_name,
                            'risk_type': risky_module,
                            'location': func_info.name,
                            'risk_level': self.assess_import_risk(risky_module)
                        })
                        
        return import_risks
        
    def analyze_type_hints(self, call_chain: List[PythonFunctionInfo]) -> List[Dict]:
        """
        分析类型提示信息
        """
        type_hints = []
        
        for func_info in call_chain:
            for param in func_info.parameters:
                if param.get('type'):
                    type_hints.append({
                        'function': func_info.name,
                        'parameter': param['name'],
                        'type': param['type'],
                        'has_default': 'default' in param,
                        'constraint_strength': self.assess_type_constraint_strength(param['type'])
                    })
                    
        return type_hints
        
    def analyze_exception_handling(self, call_chain: List[PythonFunctionInfo]) -> List[Dict]:
        """
        分析异常处理
        """
        exception_handling = []
        
        for func_info in call_chain:
            source_code = func_info.source_code
            
            # 检测try-except块
            try_pattern = r'try\s*:'
            except_pattern = r'except\s+(\w+)?.*:'
            
            try_matches = list(re.finditer(try_pattern, source_code))
            except_matches = list(re.finditer(except_pattern, source_code))
            
            for try_match in try_matches:
                exception_handling.append({
                    'type': 'try_block',
                    'location': func_info.name,
                    'line_estimate': source_code[:try_match.start()].count('\n') + func_info.line_number,
                    'has_specific_except': len(except_matches) > 0,
                    'protection_level': 0.6 if except_matches else 0.3
                })
                
        return exception_handling
        
    def assess_function_risk(self, function_name: str) -> str:
        """
        评估函数风险等级
        """
        high_risk = ['eval', 'exec', 'compile', '__import__', 'pickle.loads']
        medium_risk = ['subprocess.call', 'os.system', 'open']
        
        if function_name in high_risk:
            return 'HIGH'
        elif function_name in medium_risk:
            return 'MEDIUM'
        else:
            return 'LOW'
            
    def assess_import_risk(self, module_name: str) -> str:
        """
        评估导入模块风险等级
        """
        high_risk = ['pickle', 'marshal', 'eval', 'exec']
        medium_risk = ['subprocess', 'os', 'sys']
        
        if module_name in high_risk:
            return 'HIGH'
        elif module_name in medium_risk:
            return 'MEDIUM'
        else:
            return 'LOW'
            
    def assess_type_constraint_strength(self, type_hint: str) -> float:
        """
        评估类型约束强度
        """
        if 'Union' in type_hint or 'Any' in type_hint:
            return 0.3
        elif 'Optional' in type_hint:
            return 0.5
        elif type_hint in ['str', 'int', 'float', 'bool']:
            return 0.8
        else:
            return 0.6
            
    def estimate_python_sanitizer_effectiveness(self, sanitizer: str) -> float:
        """
        估计Python防护机制的有效性
        """
        effectiveness_map = {
            # 高效防护
            'literal_eval': 0.9,
            'escape_html': 0.9,
            'quote_sql': 0.9,
            'bleach': 0.9,
            
            # 中等防护
            'escape': 0.7,
            'encode': 0.7,
            'validate': 0.7,
            'isinstance': 0.7,
            
            # 基础防护
            'strip': 0.4,
            'replace': 0.4,
            'int': 0.5,
            'str': 0.3
        }
        return effectiveness_map.get(sanitizer.lower(), 0.5)
        
    def analyze_python_reachability(self, call_chain: List[PythonFunctionInfo]) -> bool:
        """
        Python特定的可达性分析
        """
        for i in range(len(call_chain) - 1):
            caller = call_chain[i]
            callee = call_chain[i + 1]
            
            # 检查函数调用关系
            if not self.has_python_call_relationship(caller, callee):
                logger.warning(f"未找到Python调用关系: {caller.name} -> {callee.name}")
                return False
                
        return True
        
    def has_python_call_relationship(self, caller: PythonFunctionInfo, callee: PythonFunctionInfo) -> bool:
        """
        检查Python函数间的调用关系
        """
        # 1. 直接函数名调用
        if callee.name in caller.source_code:
            return True
            
        # 2. 模块调用
        for import_name in caller.imports:
            if callee.name in import_name:
                return True
                
        # 3. 属性调用
        attr_pattern = rf'\w+\.{re.escape(callee.name)}\s*\('
        if re.search(attr_pattern, caller.source_code):
            return True
            
        return False
        
    def collect_python_constraints(self, call_chain: List[PythonFunctionInfo]) -> List[PathConstraint]:
        """
        收集Python特定的路径约束
        """
        all_constraints = []
        
        for i in range(len(call_chain) - 1):
            caller = call_chain[i]
            callee = call_chain[i + 1]
            
            # 提取Python特定约束
            constraints = self.extract_python_constraints(caller, callee)
            all_constraints.extend(constraints)
            
        return self.deduplicate_constraints(all_constraints)
        
    def extract_python_constraints(self, caller: PythonFunctionInfo, callee: PythonFunctionInfo) -> List[PathConstraint]:
        """
        提取Python特定约束
        """
        constraints = []
        
        # 1. 参数类型约束
        type_constraints = self.extract_python_type_constraints(caller, callee)
        constraints.extend(type_constraints)
        
        # 2. 异常处理约束
        exception_constraints = self.extract_exception_constraints(caller, callee)
        constraints.extend(exception_constraints)
        
        # 3. 导入约束
        import_constraints = self.extract_import_constraints(caller, callee)
        constraints.extend(import_constraints)
        
        # 4. 属性访问约束
        attribute_constraints = self.extract_attribute_constraints(caller, callee)
        constraints.extend(attribute_constraints)
        
        return constraints
        
    def extract_python_type_constraints(self, caller: PythonFunctionInfo, callee: PythonFunctionInfo) -> List[PathConstraint]:
        """
        提取Python类型约束
        """
        constraints = []
        
        for param in callee.parameters:
            if param.get('type'):
                constraint = PathConstraint(
                    type=ConstraintType.TYPE_CHECK,
                    condition=f"isinstance(arg, {param['type']})",
                    variables=[param['name']],
                    location=f"{callee.file_path}:{callee.line_number}",
                    confidence=0.8,
                    line_number=callee.line_number
                )
                constraints.append(constraint)
                
        return constraints
        
    def extract_exception_constraints(self, caller: PythonFunctionInfo, callee: PythonFunctionInfo) -> List[PathConstraint]:
        """
        提取异常处理约束
        """
        constraints = []
        
        # 检查try-except块
        try_pattern = r'try\s*:.*?except\s+(\w+).*?:'
        matches = re.finditer(try_pattern, caller.source_code, re.DOTALL)
        
        for match in matches:
            exception_type = match.group(1) if match.group(1) else 'Exception'
            constraint = PathConstraint(
                type=ConstraintType.EXCEPTION_HANDLING,
                condition=f"handle_{exception_type}",
                variables=[],
                location=f"{caller.file_path}:{caller.line_number}",
                confidence=0.6,
                line_number=caller.line_number
            )
            constraints.append(constraint)
            
        return constraints
        
    def extract_import_constraints(self, caller: PythonFunctionInfo, callee: PythonFunctionInfo) -> List[PathConstraint]:
        """
        提取导入约束
        """
        constraints = []
        
        # 检查是否需要特定导入
        for import_name in callee.imports:
            if import_name not in caller.imports:
                constraint = PathConstraint(
                    type=ConstraintType.IMPORT_CHECK,
                    condition=f"import_{import_name.replace('.', '_')}_required",
                    variables=[],
                    location=f"{caller.file_path}:{caller.line_number}",
                    confidence=0.9,
                    line_number=caller.line_number
                )
                constraints.append(constraint)
                
        return constraints
        
    def extract_attribute_constraints(self, caller: PythonFunctionInfo, callee: PythonFunctionInfo) -> List[PathConstraint]:
        """
        提取属性访问约束
        """
        constraints = []
        
        # 检查属性访问模式
        attr_pattern = r'(\w+)\.(\w+)'
        matches = re.finditer(attr_pattern, caller.source_code)
        
        for match in matches:
            obj_name, attr_name = match.groups()
            constraint = PathConstraint(
                type=ConstraintType.ATTRIBUTE_ACCESS,
                condition=f"hasattr({obj_name}, '{attr_name}')",
                variables=[obj_name],
                location=f"{caller.file_path}:{caller.line_number}",
                confidence=0.5,
                line_number=caller.line_number
            )
            constraints.append(constraint)
            
        return constraints
        
    def combine_analysis_results(self, static_result: Dict, ast_result: Dict) -> Dict:
        """
        合并静态分析和AST分析结果
        """
        combined = static_result.copy()
        combined['ast_analysis'] = ast_result
        
        # 增强置信度
        if ast_result['function_calls']:
            combined['confidence'] = min(1.0, combined['confidence'] + 0.1)
            
        return combined
        
    def llm_analyze_python_constraints(self, call_chain: List[PythonFunctionInfo], static_result: Dict, cve_info: Dict) -> Dict:
        """
        针对Python的LLM约束分析
        """
        # 构造Python特定的提示
        prompt = self.construct_python_analysis_prompt(call_chain, static_result, cve_info)
        
        # 模拟LLM响应（实际使用时替换为真实LLM API）
        mock_response = {
            'reachable': static_result.get('reachability', False),
            'python_specific_risks': len(static_result.get('dangerous_calls', [])) > 0,
            'type_safety': len(static_result.get('type_hints', [])) > 0,
            'exception_handling': len(static_result.get('exception_handling', [])) > 0,
            'exploitable': self.assess_python_exploitability(static_result),
            'confidence': 0.8,
            'reasoning': 'Based on Python-specific static analysis and AST parsing'
        }
        
        return mock_response
        
    def construct_python_analysis_prompt(self, call_chain: List[PythonFunctionInfo], static_result: Dict, cve_info: Dict) -> str:
        """
        构造Python特定的LLM分析提示
        """
        prompt_template = """
        You are a Python security expert. Analyze the following Python call chain for vulnerability exploitability.

        CVE Information:
        {cve_description}

        Python Call Chain:
        {call_chain_info}

        Static Analysis Results:
        - Dangerous calls: {dangerous_calls}
        - Sanitization points: {sanitization_points}
        - Import risks: {import_risks}
        - Type hints: {type_hints}
        - Exception handling: {exception_handling}

        Please analyze:
        1. Python-specific vulnerability patterns
        2. Type safety and input validation
        3. Exception handling effectiveness
        4. Import-related security risks
        5. Overall exploitability in Python context
        """
        
        return prompt_template.format(
            cve_description=cve_info.get('description', 'Unknown CVE'),
            call_chain_info=self.format_python_call_chain(call_chain),
            dangerous_calls=len(static_result.get('dangerous_calls', [])),
            sanitization_points=len(static_result.get('sanitization_points', [])),
            import_risks=len(static_result.get('import_risks', [])),
            type_hints=len(static_result.get('type_hints', [])),
            exception_handling=len(static_result.get('exception_handling', []))
        )
        
    def format_python_call_chain(self, call_chain: List[PythonFunctionInfo]) -> str:
        """
        格式化Python调用链信息
        """
        formatted = []
        for i, func in enumerate(call_chain):
            func_info = f"Step {i+1}: {func.name}() in {func.file_path}:{func.line_number}"
            if func.parameters:
                params = ', '.join([f"{p['name']}: {p.get('type', 'Any')}" for p in func.parameters])
                func_info += f" ({params})"
            formatted.append(func_info)
        return '\n'.join(formatted)
        
    def assess_python_exploitability(self, static_result: Dict) -> bool:
        """
        评估Python特定的可利用性
        """
        risk_score = 0.0
        
        # 危险函数调用
        dangerous_calls = static_result.get('dangerous_calls', [])
        high_risk_calls = [call for call in dangerous_calls if call.get('risk_level') == 'HIGH']
        if high_risk_calls:
            risk_score += 0.4
            
        # 缺乏有效防护
        sanitization_points = static_result.get('sanitization_points', [])
        effective_sanitizers = [s for s in sanitization_points if s.get('effectiveness', 0) > 0.7]
        if len(effective_sanitizers) == 0 and dangerous_calls:
            risk_score += 0.3
            
        # 导入风险
        import_risks = static_result.get('import_risks', [])
        high_risk_imports = [imp for imp in import_risks if imp.get('risk_level') == 'HIGH']
        if high_risk_imports:
            risk_score += 0.2
            
        # 缺乏类型检查
        type_hints = static_result.get('type_hints', [])
        if len(type_hints) == 0:
            risk_score += 0.1
            
        return risk_score > 0.6
        
    def python_hybrid_validation(self, static_result: Dict, llm_result: Dict) -> Dict:
        """
        Python特定的混合验证策略
        """
        static_weight = 0.7  # Python静态分析相对可靠
        llm_weight = 0.3
        
        static_exploitable = self.assess_python_exploitability(static_result)
        llm_exploitable = llm_result.get('exploitable', False)
        
        if static_exploitable == llm_exploitable:
            final_exploitable = static_exploitable
            confidence = min(0.95, static_result.get('confidence', 0) * static_weight + 
                           llm_result.get('confidence', 0) * llm_weight + 0.15)
        else:
            # 不一致时，倾向于静态分析结果
            final_exploitable = static_exploitable
            confidence = static_result.get('confidence', 0) * 0.8
            
        return {
            'final_decision': final_exploitable,
            'confidence': confidence,
            'static_result': static_result,
            'llm_result': llm_result,
            'python_specific_summary': self.generate_python_summary(static_result, final_exploitable),
            'recommendations': self.generate_python_recommendations(static_result)
        }
        
    def generate_python_summary(self, static_result: Dict, final_decision: bool) -> str:
        """
        生成Python特定的分析摘要
        """
        summary_parts = []
        
        # 危险函数
        dangerous_count = len(static_result.get('dangerous_calls', []))
        if dangerous_count > 0:
            summary_parts.append(f"发现 {dangerous_count} 个危险函数调用")
            
        # 防护机制
        sanitization_count = len(static_result.get('sanitization_points', []))
        if sanitization_count > 0:
            summary_parts.append(f"检测到 {sanitization_count} 个防护点")
        else:
            summary_parts.append("缺乏有效的输入验证")
            
        # 类型安全
        type_hints_count = len(static_result.get('type_hints', []))
        if type_hints_count > 0:
            summary_parts.append(f"具有 {type_hints_count} 个类型提示")
        else:
            summary_parts.append("缺乏类型安全检查")
            
        # 异常处理
        exception_count = len(static_result.get('exception_handling', []))
        if exception_count > 0:
            summary_parts.append(f"包含 {exception_count} 个异常处理")
            
        # 最终结论
        if final_decision:
            summary_parts.append("⚠️ 调用链可能存在安全风险")
        else:
            summary_parts.append("✅ 调用链相对安全")
            
        return "; ".join(summary_parts)
        
    def generate_python_recommendations(self, static_result: Dict) -> List[str]:
        """
        生成Python特定的安全建议
        """
        recommendations = []
        
        # 基于危险函数的建议
        dangerous_calls = static_result.get('dangerous_calls', [])
        if dangerous_calls:
            recommendations.append("避免使用eval()、exec()等危险函数，考虑使用ast.literal_eval()")
            
        # 基于类型检查的建议
        type_hints = static_result.get('type_hints', [])
        if len(type_hints) == 0:
            recommendations.append("添加类型提示和运行时类型检查")
            
        # 基于输入验证的建议
        sanitization_points = static_result.get('sanitization_points', [])
        if len(sanitization_points) == 0:
            recommendations.append("实现输入验证和数据清理机制")
            
        # 基于异常处理的建议
        exception_handling = static_result.get('exception_handling', [])
        if len(exception_handling) == 0:
            recommendations.append("添加适当的异常处理机制")
            
        # 基于导入的建议
        import_risks = static_result.get('import_risks', [])
        if import_risks:
            recommendations.append("审查高风险模块的使用，考虑更安全的替代方案")
            
        return recommendations
        
    def calculate_python_confidence(self, analysis_result: Dict) -> float:
        """
        计算Python分析的置信度
        """
        base_confidence = 0.6
        
        # 基于AST分析调整
        if analysis_result.get('dangerous_calls'):
            base_confidence += 0.2
            
        # 基于类型提示调整
        if analysis_result.get('type_hints'):
            base_confidence += 0.1
            
        # 基于异常处理调整
        if analysis_result.get('exception_handling'):
            base_confidence += 0.1
            
        return min(1.0, base_confidence)
        
    def deduplicate_constraints(self, constraints: List[PathConstraint]) -> List[PathConstraint]:
        """
        约束去重
        """
        seen = set()
        unique_constraints = []
        
        for constraint in constraints:
            key = (constraint.type, constraint.condition, constraint.location)
            if key not in seen:
                seen.add(key)
                unique_constraints.append(constraint)
                
        return unique_constraints


def create_python_function_info_from_source(file_path: str, source_code: str) -> List[PythonFunctionInfo]:
    """
    从源代码创建Python函数信息
    """
    functions = []
    
    try:
        tree = ast.parse(source_code)
        analyzer = PythonASTAnalyzer()
        analyzer.visit(tree)
        
        for func_name, func_data in analyzer.functions.items():
            func_info = PythonFunctionInfo(
                name=func_name,
                file_path=file_path,
                line_number=func_data['line_number'],
                source_code=ast.unparse(func_data['ast_node']) if hasattr(ast, 'unparse') else source_code,
                ast_node=func_data['ast_node'],
                parameters=func_data['parameters'],
                decorators=func_data['decorators'],
                docstring=func_data['docstring'],
                imports=analyzer.imports
            )
            functions.append(func_info)
            
    except SyntaxError as e:
        logger.error(f"解析Python代码出错: {e}")
        
    return functions



def print_detailed_results(result: Dict):
    """
    详细打印分析结果
    """
    print("\n" + "="*60)
    print("           PYTHON CALL CHAIN ANALYSIS REPORT")
    print("="*60)
    
    # 1. 基本信息
    print("\n📊 ANALYSIS OVERVIEW")
    print("-" * 30)
    final_decision = result.get('final_decision', False)
    confidence = result.get('confidence', 0.0)
    status = "🔴 EXPLOITABLE" if final_decision else "🟢 SAFE"
    print(f"Status: {status}")
    print(f"Confidence: {confidence:.2%}")
    
    if 'python_specific_summary' in result:
        print(f"Summary: {result['python_specific_summary']}")
    
    # 2. 静态分析结果
    static_result = result.get('static_result', {})
    if static_result:
        print("\n🔍 STATIC ANALYSIS RESULTS")
        print("-" * 30)
        
        # 可达性
        reachability = static_result.get('reachability', False)
        reach_status = "✅ Reachable" if reachability else "❌ Not Reachable"
        print(f"Reachability: {reach_status}")
        
        # 危险函数调用
        dangerous_calls = static_result.get('dangerous_calls', [])
        print(f"\n🚨 Dangerous Function Calls: {len(dangerous_calls)}")
        for i, call in enumerate(dangerous_calls, 1):
            risk_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(call.get('risk_level', 'LOW'), "⚪")
            print(f"  {i}. {risk_emoji} {call.get('function', 'Unknown')} in {call.get('location', 'Unknown')}")
            print(f"     Risk Level: {call.get('risk_level', 'Unknown')}")
            if call.get('context'):
                context = call.get('context', '')[:100] + '...' if len(call.get('context', '')) > 100 else call.get('context', '')
                print(f"     Context: {context}")
        
        # 防护机制
        sanitization_points = static_result.get('sanitization_points', [])
        print(f"\n🛡️ Sanitization Points: {len(sanitization_points)}")
        for i, point in enumerate(sanitization_points, 1):
            effectiveness = point.get('effectiveness', 0.0)
            eff_emoji = "🟢" if effectiveness > 0.7 else "🟡" if effectiveness > 0.4 else "🔴"
            print(f"  {i}. {eff_emoji} {point.get('type', 'Unknown')} - {point.get('function', point.get('pattern', 'Unknown'))}")
            print(f"     Location: {point.get('location', 'Unknown')}")
            print(f"     Effectiveness: {effectiveness:.1%}")
        
        # 导入风险
        import_risks = static_result.get('import_risks', [])
        if import_risks:
            print(f"\n📦 Import Risks: {len(import_risks)}")
            for i, risk in enumerate(import_risks, 1):
                risk_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk.get('risk_level', 'LOW'), "⚪")
                print(f"  {i}. {risk_emoji} {risk.get('module', 'Unknown')} ({risk.get('risk_type', 'Unknown')})")
                print(f"     Risk Level: {risk.get('risk_level', 'Unknown')}")
        
        # 类型提示
        type_hints = static_result.get('type_hints', [])
        if type_hints:
            print(f"\n🏷️ Type Hints: {len(type_hints)}")
            for i, hint in enumerate(type_hints, 1):
                strength = hint.get('constraint_strength', 0.0)
                strength_emoji = "🟢" if strength > 0.7 else "🟡" if strength > 0.4 else "🔴"
                print(f"  {i}. {strength_emoji} {hint.get('function', 'Unknown')}.{hint.get('parameter', 'Unknown')}: {hint.get('type', 'Any')}")
                print(f"     Constraint Strength: {strength:.1%}")
        
        # 异常处理
        exception_handling = static_result.get('exception_handling', [])
        if exception_handling:
            print(f"\n⚠️ Exception Handling: {len(exception_handling)}")
            for i, exc in enumerate(exception_handling, 1):
                protection = exc.get('protection_level', 0.0)
                prot_emoji = "🟢" if protection > 0.6 else "🟡" if protection > 0.3 else "🔴"
                print(f"  {i}. {prot_emoji} {exc.get('type', 'Unknown')} in {exc.get('location', 'Unknown')}")
                print(f"     Protection Level: {protection:.1%}")
        
        # 约束条件
        constraints = static_result.get('constraints', [])
        if constraints:
            print(f"\n🔗 Path Constraints: {len(constraints)}")
            constraint_types = {}
            for constraint in constraints:
                constraint_type = constraint.type.value if hasattr(constraint.type, 'value') else str(constraint.type)
                constraint_types[constraint_type] = constraint_types.get(constraint_type, 0) + 1
            
            for constraint_type, count in constraint_types.items():
                print(f"  • {constraint_type}: {count}")
    
    # 3. LLM分析结果
    llm_result = result.get('llm_result', {})
    if llm_result:
        print("\n🤖 LLM ANALYSIS RESULTS")
        print("-" * 30)
        print(f"Reachable: {'✅ Yes' if llm_result.get('reachable', False) else '❌ No'}")
        print(f"Python Specific Risks: {'🔴 Detected' if llm_result.get('python_specific_risks', False) else '🟢 None'}")
        print(f"Type Safety: {'🟢 Good' if llm_result.get('type_safety', False) else '🔴 Poor'}")
        print(f"Exception Handling: {'🟢 Present' if llm_result.get('exception_handling', False) else '🔴 Missing'}")
        print(f"Exploitable: {'🔴 Yes' if llm_result.get('exploitable', False) else '🟢 No'}")
        print(f"LLM Confidence: {llm_result.get('confidence', 0.0):.2%}")
        
        if llm_result.get('reasoning'):
            print(f"Reasoning: {llm_result.get('reasoning')}")
    
    # 4. 安全建议
    recommendations = result.get('recommendations', [])
    if recommendations:
        print("\n💡 SECURITY RECOMMENDATIONS")
        print("-" * 30)
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
    
    # 5. 详细的JSON输出（可选）
    print("\n📋 DETAILED JSON OUTPUT")
    print("-" * 30)
    print("(Use the following for programmatic access)")
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
    
    print("\n" + "="*60)
    print("                    END OF REPORT")
    print("="*60)


def main():
    """
    主函数，用于测试Python特定的分析功能
    """
    # 示例Python代码
    sample_code = '''
def user_input_handler(data: str) -> str:
    """处理用户输入"""
    if not isinstance(data, str):
        raise TypeError("Input must be string")
    return process_data(data)

def process_data(input_data: str) -> str:
    """处理数据"""
    try:
        cleaned_data = input_data.strip()
        return vulnerable_function(cleaned_data)
    except Exception as e:
        logger.error(f"Processing error: {e}")
        raise

def vulnerable_function(user_input: str) -> Any:
    """存在漏洞的函数"""
    # 危险：直接执行用户输入
    return eval(user_input)
'''
    
    # 创建函数信息
    functions = create_python_function_info_from_source("example.py", sample_code)
    
    # 示例CVE信息
    sample_cve = {
        'id': 'CVE-2023-XXXX',
        'description': 'Code injection vulnerability in eval() function',
        'severity': 'HIGH',
        'language': 'Python'
    }
    
    # 创建分析器并运行分析
    analyzer = PythonCallChainAnalyzer()
    result = analyzer.analyze_python_call_chain(functions, sample_cve)
    print(result)
    print("=== Python Call Chain Analysis Result ===")
    # print(json.dumps(result, indent=2, default=str))
    
    print_detailed_results(result)

if __name__ == '__main__':
    main()