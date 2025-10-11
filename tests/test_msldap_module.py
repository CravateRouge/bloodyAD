import unittest
import inspect
from bloodyAD.cli_modules import msldap


class MSLDAPModuleTests(unittest.TestCase):
    """Tests for the msldap module that exposes MSLDAPClientConsole methods"""
    
    def test_module_has_functions(self):
        """Test that the msldap module has exposed functions"""
        functions = [name for name, obj in inspect.getmembers(msldap, inspect.isfunction)]
        # Should have many functions (around 87+)
        self.assertGreater(len(functions), 80)
    
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


if __name__ == '__main__':
    unittest.main()
