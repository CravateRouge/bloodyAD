"""
This module exposes methods from badldap.examples.msldapclient.MSLDAPClientConsole
as bloodyAD CLI commands. Users can call them like:
bloodyAD <connection_arguments> msldap <method_name> <arguments>
"""

from badldap.examples.msldapclient import MSLDAPClientConsole
import inspect


# Use a class to encapsulate helper functions and avoid exposing them at module level
class _MSLDAPWrapper:
    """Internal wrapper class to manage MSLDAPClientConsole method execution"""
    
    # Interactive methods and methods that should not be exposed
    INTERACTIVE_METHODS = {
        'do_login',
        'do_nosig',
        'do_help',
        'do_quit',
        'do_test',  # Might be interactive
        'do_plugin',  # Might be interactive
        'do_ls',  # File system navigation
        'do_cd',  # File system navigation
        'do_rm',  # File system operation
        'do_nullcb',  # Channel binding option
        'do_nocb',  # Channel binding option
        'do_bindtree',  # Tree binding operation
        'do_cat',  # File system operation
    }
    
    # Parameters that should not be exposed
    HIDDEN_PARAMETERS = {'show', 'to_print'}
    
    @staticmethod
    def get_msldap_methods():
        """
        Get all non-interactive do_ methods from MSLDAPClientConsole.
        Returns a dict mapping method names (without 'do_' prefix) to the method objects.
        """
        methods = {}
        for attr_name in dir(MSLDAPClientConsole):
            if not attr_name.startswith('do_'):
                continue
            if attr_name in _MSLDAPWrapper.INTERACTIVE_METHODS:
                continue
            
            method = getattr(MSLDAPClientConsole, attr_name)
            if not callable(method):
                continue
            
            # Strip 'do_' prefix to get the command name
            command_name = attr_name[3:]
            methods[command_name] = method
        
        return methods
    
    @staticmethod
    async def execute_msldap_method(conn, method_name: str, original_method, **kwargs):
        """
        Execute an MSLDAPClientConsole method with the given arguments.
        
        :param conn: ConnectionHandler instance
        :param method_name: Name of the method to execute (without 'do_' prefix)
        :param original_method: The original method object (to get signature for hidden params)
        :param kwargs: Arguments to pass to the method
        """
        # Initialize MSLDAPClientConsole without URL (non-interactive mode)
        msldapcc = MSLDAPClientConsole()
        
        # Get the LDAP connection and set it as the connection attribute
        ldap = await conn.getLdap()
        msldapcc.connection = ldap
        
        # Also initialize some attributes that might be used by methods
        msldapcc.ldapinfo = None
        msldapcc.adinfo = None
        msldapcc._disable_channel_binding = False
        msldapcc._disable_signing = False
        msldapcc._null_channel_binding = False
        
        # Get the method with 'do_' prefix
        full_method_name = f'do_{method_name}'
        method = getattr(msldapcc, full_method_name)
        
        # Add hidden parameters with their default values
        sig = inspect.signature(original_method)
        for param_name, param in sig.parameters.items():
            if param_name in _MSLDAPWrapper.HIDDEN_PARAMETERS and param_name not in kwargs:
                if param.default is not None and param.default != inspect.Parameter.empty:
                    # Use the original default value
                    kwargs[param_name] = param.default
        
        # Call the method with provided arguments
        # Note: We don't return the result as requested - the method will print its output
        await method(**kwargs)
        
        # Return None to indicate success without returning actual results
        return None
    
    @staticmethod
    def create_wrapper_function(method_name, original_method):
        """
        Create a wrapper function for an MSLDAPClientConsole method.
        This wrapper handles connection setup and method execution.
        """
        # Get the method signature
        sig = inspect.signature(original_method)
        params = list(sig.parameters.values())
        
        # Remove 'self' parameter
        if params and params[0].name == 'self':
            params = params[1:]
        
        # Filter out hidden parameters (show, to_print)
        params = [p for p in params if p.name not in _MSLDAPWrapper.HIDDEN_PARAMETERS]
        
        # Get docstring and format it for argparse
        raw_docstring = inspect.getdoc(original_method) or f"Execute {method_name} from MSLDAPClientConsole"
        
        # Format docstring as expected by bloodyAD's doc_parser
        # First line is the description, then blank line, then :param lines
        docstring_lines = [raw_docstring, ""]
        for param in params:
            docstring_lines.append(f":param {param.name}: {param.name}")
        docstring = "\n".join(docstring_lines)
        
        # Build the function dynamically with proper parameter names
        # This is necessary because bloodyAD's main.py extracts parameter names from __code__.co_varnames
        param_names = [p.name for p in params]
        param_str = ', '.join(param_names)
        
        # Create function code that calls execute_msldap_method with all parameters as kwargs
        func_code = f'''async def wrapper(conn, {param_str}):
    kwargs = {{{', '.join(f"'{name}': {name}" for name in param_names)}}}
    return await _MSLDAPWrapper.execute_msldap_method(conn, method_name, original_method, **kwargs)
'''
        
        # Execute the code to create the function
        local_vars = {
            '_MSLDAPWrapper': _MSLDAPWrapper,
            'method_name': method_name,
            'original_method': original_method
        }
        exec(func_code, local_vars)
        wrapper = local_vars['wrapper']
        
        # Set the wrapper's name and docstring
        wrapper.__name__ = method_name
        wrapper.__doc__ = docstring
        
        # Build annotations with proper types
        annotations = {'conn': object}
        for param in params:
            if param.annotation != inspect.Parameter.empty:
                annotations[param.name] = param.annotation
            else:
                # Infer type from default value if available, otherwise default to str
                if param.default is not None and param.default != inspect.Parameter.empty:
                    annotations[param.name] = type(param.default)
                else:
                    annotations[param.name] = str
        wrapper.__annotations__ = annotations
        
        # Build signature with proper defaults
        new_params = [inspect.Parameter('conn', inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=object)]
        for param in params:
            # Preserve the default value and annotation
            if param.annotation != inspect.Parameter.empty:
                new_param = inspect.Parameter(
                    param.name,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default=param.default,
                    annotation=param.annotation
                )
            else:
                # Infer type from default value if available, otherwise default to str
                if param.default is not None and param.default != inspect.Parameter.empty:
                    inferred_type = type(param.default)
                else:
                    inferred_type = str
                new_param = inspect.Parameter(
                    param.name,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    default=param.default,
                    annotation=inferred_type
                )
            new_params.append(new_param)
        
        wrapper.__signature__ = inspect.Signature(new_params)
        
        return wrapper


# Dynamically create all wrapper functions and add them to this module's namespace
def _initialize_module():
    """Initialize module by creating all wrapper functions"""
    methods = _MSLDAPWrapper.get_msldap_methods()
    for method_name, method_obj in methods.items():
        wrapper_func = _MSLDAPWrapper.create_wrapper_function(method_name, method_obj)
        # Add to module namespace
        globals()[method_name] = wrapper_func

_initialize_module()
# Clean up the initialization function from module namespace
del _initialize_module
