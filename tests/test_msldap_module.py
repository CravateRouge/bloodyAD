import unittest
import inspect
from bloodyAD.cli_modules import msldap


class MSLDAPModuleTests(unittest.TestCase):
    """Tests for the msldap module that exposes MSLDAPClientConsole methods"""
    
    def test_module_has_functions(self):
        """Test that the msldap module has exposed functions"""
        functions = [name for name, obj in inspect.getmembers(msldap, inspect.isfunction)]
        # Should have many functions (around 80+)
        # Note: 7 methods are filtered (ls, cd, rm, nullcb, nocb, bindtree, cat) plus 6 interactive methods
        self.assertGreater(len(functions), 75)
    
    def test_no_interactive_methods_exposed(self):
        """Test that interactive methods are not exposed"""
        functions = [name for name, obj in inspect.getmembers(msldap, inspect.isfunction)]
        
        # These interactive methods should NOT be exposed
        interactive_methods = ['login', 'nosig', 'help', 'quit', 'test', 'plugin']
        for method in interactive_methods:
            self.assertNotIn(method, functions, 
                            f"Interactive method '{method}' should not be exposed")
    
    def test_functions_have_proper_signature(self):
        """Test that exposed functions have proper signatures with 'conn' parameter"""
        # Test a few sample functions
        sample_functions = ['whoami', 'query', 'ldapinfo']
        
        for func_name in sample_functions:
            if not hasattr(msldap, func_name):
                self.fail(f"Function '{func_name}' not found in msldap module")
            
            func = getattr(msldap, func_name)
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
            
            # First parameter should be 'conn'
            self.assertEqual(params[0], 'conn', 
                           f"First parameter of '{func_name}' should be 'conn'")
    
    def test_functions_have_docstrings(self):
        """Test that exposed functions have docstrings"""
        sample_functions = ['whoami', 'query', 'ldapinfo']
        
        for func_name in sample_functions:
            if not hasattr(msldap, func_name):
                self.fail(f"Function '{func_name}' not found in msldap module")
            
            func = getattr(msldap, func_name)
            self.assertIsNotNone(func.__doc__, 
                               f"Function '{func_name}' should have a docstring")
            self.assertGreater(len(func.__doc__), 0, 
                             f"Function '{func_name}' docstring should not be empty")
    
    def test_functions_have_annotations(self):
        """Test that exposed functions have proper type annotations"""
        sample_functions = ['whoami', 'query']
        
        for func_name in sample_functions:
            if not hasattr(msldap, func_name):
                self.fail(f"Function '{func_name}' not found in msldap module")
            
            func = getattr(msldap, func_name)
            self.assertIn('conn', func.__annotations__, 
                        f"Function '{func_name}' should have 'conn' annotation")
    
    def test_specific_methods_exposed(self):
        """Test that specific important methods are exposed"""
        important_methods = [
            'whoami',
            'query',
            'ldapinfo',
            'user',
            'groupmembers',
            'adduser',
            'deluser',
            'dnsdump'
        ]
        
        for method in important_methods:
            self.assertTrue(hasattr(msldap, method), 
                          f"Method '{method}' should be exposed in msldap module")
    
    def test_parameter_extraction(self):
        """Test that parameters can be extracted correctly for main.py"""
        # This tests the fix for the parameter passing issue
        # main.py extracts parameters using: func.__code__.co_varnames[1:func.__code__.co_argcount]
        
        # Test function with parameters (to_print is now hidden)
        func = getattr(msldap, 'user')
        param_names = func.__code__.co_varnames[1:func.__code__.co_argcount]
        self.assertEqual(param_names, ('samaccountname',),
                        "user function should have samaccountname parameter (to_print is hidden)")
        
        # Test function with no parameters (other than conn)
        func = getattr(msldap, 'whoami')
        param_names = func.__code__.co_varnames[1:func.__code__.co_argcount]
        self.assertEqual(param_names, (),
                        "whoami function should have no parameters")
        
        # Test function with multiple parameters
        func = getattr(msldap, 'query')
        param_names = func.__code__.co_varnames[1:func.__code__.co_argcount]
        self.assertIn('query', param_names,
                     "query function should have query parameter")
        self.assertIn('attributes', param_names,
                     "query function should have attributes parameter")
    
    def test_hidden_parameters_not_exposed(self):
        """Test that show and to_print parameters are not exposed"""
        # Test functions that would normally have these parameters
        test_cases = {
            'user': ['show', 'to_print'],
            'ldapinfo': ['show'],
            'adinfo': ['show'],
        }
        
        for func_name, hidden_params in test_cases.items():
            if hasattr(msldap, func_name):
                func = getattr(msldap, func_name)
                sig = inspect.signature(func)
                param_names = list(sig.parameters.keys())
                
                for hidden_param in hidden_params:
                    self.assertNotIn(hidden_param, param_names,
                                   f"{func_name} should not expose {hidden_param} parameter")
    
    def test_suppressed_methods_not_exposed(self):
        """Test that ls, cd, rm, nullcb, nocb, bindtree, cat are not exposed"""
        suppressed = ['ls', 'cd', 'rm', 'nullcb', 'nocb', 'bindtree', 'cat']
        functions = [name for name, obj in inspect.getmembers(msldap, inspect.isfunction)]
        
        for method in suppressed:
            self.assertNotIn(method, functions,
                           f"{method} should not be exposed in msldap module")


if __name__ == '__main__':
    unittest.main()
