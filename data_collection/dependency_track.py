from ast import Mod
from collections import defaultdict
from pathlib import Path
import sys
import pickle
from urllib.parse import urlparse
from types import SimpleNamespace

from git import repo
sys.path.append(Path(__file__).parent.parent.as_posix())
from pydriller.domain.commit import Method, Class, ModifiedFile, Variable, CodeChangeAnalyzer
from typing import Set, Dict, Tuple, List, Any, Optional
from data_collection.logger import logger


class ScopeAwareDependencyTracker():
    def __init__(self, file:ModifiedFile):
        self.file = file
        
        self.global_variables, self.class_variables = file.module_vars_before, file.class_vars_before
        

        self.changed_module_vars = file.changed_module_vars
        self.changed_class_vars = file.changed_class_vars
        self.global_functions, self.non_global_functions = self.divide_function_into_global_and_class(file)

        self.analyzer = self._create_analyzer_from_file()
        # Build enhanced tracking structures using tree-sitter
        self.function_variable_usage = self._build_function_variable_usage()
        # self.class_method_mapping = self._build_class_method_mapping()
        
        # Additional analysis structures
        self.variable_to_functions = self._build_variable_to_functions_mapping()
        # for var, methods in self.variable_to_functions.items():
        #     print(var, [method.long_name for method in methods])
        self.function_scope_hierarchy = self._build_function_scope_hierarchy()
    
    def analyze_variable_impact_functions(self):
        class_impact_functions = self._analyze_variable_impact_functions(self.changed_class_vars)
        module_impact_functions = self._analyze_variable_impact_functions(self.changed_module_vars)
        return module_impact_functions,class_impact_functions
    def _analyze_variable_impact_functions(self,changed_vars=None):
        # Use the variable-to-functions mapping for efficient lookup
        impact_functions = set()
        logger.info(f"changed_vars:{[var.name for var in changed_vars]}")
        
        for changed_var in changed_vars:
            if changed_var.name in self.variable_to_functions:
                dependent_functions = list(self.variable_to_functions[changed_var.name])
                impact_functions.update(dependent_functions)
                logger.debug(f"changed_var:{changed_var.long_name} dependent_functions:{[func.long_name for func in dependent_functions]}")
        return impact_functions
            

    def _extract_variable_usage_from_code(self, code: str) -> Set[str]:
        """
        Extract variable names used in the given code.
        This is a simplified implementation - you should replace this with
        proper tree-sitter or AST parsing.
        """
        import re
        
        # TODO:Simple regex-based extraction (replace with proper parsing)
        # This is just a placeholder
        var_patterns = [
            r'\b(\w+)\s*=\s*',  # assignments
            r'\b(\w+)\.',       # attribute access
            r'\b(\w+)\[',       # indexing
            r'\b(\w+)\(',       # function calls
        ]
        
        used_vars = set()
        for pattern in var_patterns:
            matches = re.findall(pattern, code)
            used_vars.update(matches)
        
        # Filter out keywords and common built-ins
        keywords = {'if', 'else', 'for', 'while', 'def', 'class', 'import', 'from', 'return', 'try', 'except'}
        used_vars = {var for var in used_vars if var not in keywords and not var.startswith('__')}
        
        return used_vars
        
    def _build_function_variable_usage(self) -> Dict[str, Set[str]]:
        """
        Build detailed variable usage mapping using tree-sitter analysis.
        """
        # Create analyzer for the source code
        analyzer = self.analyzer
        if not analyzer:
            return {}
        
        # Extract global and class variables for context
        global_vars_set = {var.name for var in self.global_variables}
        class_vars_dict = defaultdict(set)

        # Build class hierarchy and variable inheritance
        class_vars_dict, class_hierarchy = self._build_class_inheritance_mapping()
        analyzer.get_functions()
        all_functions_nodes = analyzer.functions_nodes
        all_functions = self.file.methods_before
        func2node = {}
        for func_node in all_functions_nodes:
            func_info = analyzer._process_function(func_node)
            func = Method(SimpleNamespace(**func_info))
            func2node[func]=func_node
        function_usage=defaultdict(dict)
        for func, func_node in func2node.items():
            logger.info(f"func info: {func.__dict__}")
            # Determine the scope context for this function
            if func.first_parent_class:
                # This is a class method
                class_name = func.first_parent_class.split('.')[-1]
                # Get all accessible variables including inherited ones
                accessible_vars = self._get_all_accessible_class_vars(class_name, class_vars_dict, class_hierarchy)
                
                all_external_vars = global_vars_set | accessible_vars

                # TODO:
                # TODO: Use the existing analyze_function_usage method
                logger.debug(f"all_external_vars:{all_external_vars}")

                external_used = analyzer.analyze_function_usage(func_node, func,
                all_external_vars)
                # if len(accessible_vars) and len(external_used):
                #     assert False
            else:
                # This is a global function
                all_external_vars = global_vars_set
                logger.debug(f"all_external_vars:{all_external_vars}")
                
                external_used = analyzer.analyze_function_usage(func_node, func,all_external_vars)
            
            # Store detailed usage information
            usage_info = {
                'global_vars': external_used & global_vars_set,
                'class_vars': external_used - global_vars_set,
                'all_used': external_used,
                'inherited_vars': external_used & self._get_inherited_vars(func.first_parent_class, class_vars_dict, class_hierarchy) if func.first_parent_class else set()
            }
            function_usage[func.long_name] = usage_info
        return function_usage

    def _get_inherited_vars(self, class_long_name: Optional[str], class_vars_dict: Dict[str, Set[str]], 
                          class_hierarchy: Dict[str, List[str]]) -> Set[str]:
        """Get variables that are inherited (not defined in the current class)."""
        if not class_long_name:
            return set()
        
        class_name = class_long_name.split('.')[-1]
        own_vars = class_vars_dict.get(class_name, set())
        all_accessible = self._get_all_accessible_class_vars(class_name, class_vars_dict, class_hierarchy)
        
        return all_accessible - own_vars
    def _build_class_inheritance_mapping(self) -> Tuple[Dict[str, Set[str]], Dict[str, List[str]]]:
        """
        Build class variable mapping and inheritance hierarchy.
        Returns: (class_vars_dict, class_hierarchy)
        """
        class_vars_dict = defaultdict(set)
        class_hierarchy = {}  # class_name -> [parent_class_names]
        
        # Build basic class variable mapping
        
        for var in self.class_variables:
            class_name = var.parent_class.split('.')[-1]
            if var.parent_class:
                class_vars_dict[class_name].add(f"{var.name}")
        for class_name, vars in class_vars_dict.items():
            logger.info(f"class_vars_dict:{class_name}, {[var for var in vars]}")
        
        # Build inheritance hierarchy from class information
        # We need to get class information from the file
        for cls in self.file.classes_before:
            class_short_name = cls.name
            if hasattr(cls, 'superclasses') and cls.superclasses:
                class_hierarchy[class_short_name] = cls.superclasses
            else:
                class_hierarchy[class_short_name] = []
        # logger.info(f"class_vars_dict: {class_vars_dict}")
        logger.info(f"class_hierarchy: {class_hierarchy}")
        return dict(class_vars_dict), class_hierarchy
   

    def _get_all_accessible_class_vars(self, class_name: str, class_vars_dict: Dict[str, Set[str]], class_hierarchy: Dict[str, List[str]]) -> Set[str]:
        """
        Get all variables accessible to a class, including inherited ones.
        Similar to your existing inheritance handling logic.
        """
        # class_name = func.first_parent_class.split('.')[-1]

        accessible_vars = set()
        
        # # Add own class variables
        # accessible_vars.update(class_vars_dict.get(class_name, set()))
        
        # Add inherited variables from parent classes
        visited = set()
        to_visit = [class_name]
        
        while to_visit:
            current_class = to_visit.pop(0)
            if current_class in visited:
                continue
            visited.add(current_class)
            
            # Add current class variables
            logger.debug(f'current cls:{current_class} vars:{class_vars_dict.get(current_class, set())}')
            class_vars = class_vars_dict.get(current_class, set())
            class_vars = [var for var in class_vars]
            accessible_vars.update(class_vars)
            
            # Add parent classes to visit
            parent_classes = class_hierarchy.get(current_class, [])
            for parent in parent_classes:
                if parent not in visited:
                    to_visit.append(parent)
                    # Add parent class variables (similar to your logic)
                    # parent_vars = class_vars_dict.get(parent, set())
                    # Transform variable names to current class context if needed
                    # accessible_vars.update(parent_vars)
        logger.info(f"accessible_vars:{accessible_vars}")
        return accessible_vars
    
    def _build_variable_to_functions_mapping(self) -> Dict[str, Set['Method']]:
        """Build reverse mapping from variables to functions that use them."""
        var_to_funcs = defaultdict(set)
        
        for func_name, usage_info in self.function_variable_usage.items():
            # Find the corresponding Method object
            func_obj = None
            for func in self.file.methods_before:
                if func.long_name == func_name:
                    func_obj = func
                    break
            
            if func_obj:
                for var_name in usage_info['all_used']:
                    var_to_funcs[var_name].add(func_obj)
        
        return dict(var_to_funcs)

    def _build_function_scope_hierarchy(self) -> Dict[str, Dict[str, Any]]:
        """Build function scope hierarchy information."""
        hierarchy = {}
        
        for func in self.file.methods_before:
            hierarchy[func.long_name] = {
                'is_global': func.first_parent_class is None,
                'parent_class': func.first_parent_class,
                'accessible_vars': self._get_accessible_variables_for_function(func)
            }
        
        return hierarchy
    
    def _get_accessible_variables_for_function(self, func: 'Method') -> Set[str]:
        """Get all variables accessible to a function based on scope rules."""
        accessible_vars = set()
        
        # Global variables are accessible to all functions
        accessible_vars.update(var.name for var in self.global_variables)
        
        # Class variables are accessible to class methods
        if func.first_parent_class:
            for var in self.class_variables:
                if var.parent_class == func.first_parent_class:
                    accessible_vars.add(var.name)
        
        return accessible_vars
    def divide_function_into_global_and_class(self,file:ModifiedFile, before_change=True):
        if before_change:
            functions = file.methods_before
        else:
            functions = file.methods
        global_functions = []
        class_functions = defaultdict(list)
        for func in functions:
            # first_parent_class = first_parent (class or function)
            first_parent = func.first_parent_class
            if first_parent:
                class_functions[first_parent].append(func)
            else:
                global_functions.append(func)
        return global_functions, class_functions

    def _create_analyzer_from_file(self) -> Optional['CodeChangeAnalyzer']:
        """Create a CodeChangeAnalyzer from the current file."""
        try:
            if not self.file.source_code_before:
                assert False
            source_code = self.file.source_code_before
            
            analyzer = CodeChangeAnalyzer(
                source_code=source_code,
                commit_hash=getattr(self.file, 'commit_hash', ''),
                file_path=self.file.old_path,
                change_before=True
            )
            return analyzer
        except Exception as e:
            logger.error(f"Could not create analyzer: {e}")
            return None