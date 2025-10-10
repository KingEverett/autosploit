import importlib.util
import inspect
from pathlib import Path
from typing import Dict, List, Type, Optional
from .plugin_base import PluginBase, ModuleInfo

class ModuleManager:
    """
    This will automatically scan directories 
    for python files containing classes inheriting from
    PluginBase and make them available for use in the
    framework
    """
    def __init__(self):
        self.modules: Dict[str, Type[PluginBase]] = {}
        self.module_paths: List[Path] = []

    def add_module_path(self, path: Path):
        #adds directory to module search path
        # Convert string to Path
        if isinstance(path, str):
            path = Path(path)
        
        # Validate path exists and is a directory
        if not path.exists():
            raise ValueError(f"Path does not exist: {path}")
        
        if not path.is_dir():
            raise ValueError(f"Path is not a directory: {path}")
        
        # Add to search paths if not already
        if path not in self.module_paths:
            self.module_paths.append(path)
            print(f"[*] Added module path: {path}")

    def discover_modules(self) -> int:
        """
        1. Clears Existing Module Registry
        2. Scans all Directories in module_paths
        3. Loads each valid module file
        4. Returns count of discovered modules
        """
        self.modules.clear()
        print("[*] Scanning for Modules...")

        for module_path in self.module_paths:
            self._scan_directory(module_path, module_path)

        print(f"[+] Discovered {len(self.modules)} modules")
        return len(self.modules)
    
    def _scan_directory(self, base_path: Path, current_path: Path):
        """
        1. Iterates through all items in current_path
        2. For directories: reclusively scans them
        3. for .py files: attempts  to load as modules
        """
        try:
            for item in current_path.iterdir():
                if item.name.startswith('.') or item.name.startswith('_'):
                    continue

                if item.is_dir():
                    self._scan_directory(base_path, item)

                elif item.suffix == '.py':
                    self._load_module(base_path, item)

        except PermissionError as e:
            print(f"[-] Permission denied scanning {current_path}: {e}")
        except Exception as e:
            print(f"[-] Error scanning {current_path}: {e}")

    def _load_module(self, base_path: Path, module_file: Path):
        """
        1. Calculates module's relative path
        2. Dynamically imports python file
        3. Searches for a class named Module that inherits
        from PluginBase
        4. Registers the module in self.modules
        5. Handles errors gracefully
        """

        try:
            relative_path = module_file.relative_to(base_path)
            
            module_parts = list(relative_path.parent.parts) + [relative_path.stem]
            module_path = '/'.join(module_parts)
            
            import_path = str(relative_path.with_suffix('')).replace('/', '.')

            spec = importlib.util.spec_from_file_location(
                import_path,
                module_file
            )
            
            if spec is None or spec.loader is None:
                print(f"[-] Could not load spec for {module_file}")
                return
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            module_class = None
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # Look for a class named 'Module' that inherits from PluginBase
                if (name == 'Module' and 
                    issubclass(obj, PluginBase) and 
                    obj is not PluginBase):
                    module_class = obj
                    break
            
            if module_class is None:
                print(f"[-] No Module class found in {module_file}")
                return
            
            try:
                test_instance = module_class()
                info = test_instance.get_info()
                
                self.modules[module_path] = module_class
                print(f"[+] Loaded module: {module_path} ({info.name})")
            
            except Exception as e:
                print(f"[-] Module validation failed for {module_file}: {e}")
                return
        
        except Exception as e:
            print(f"[-] Error loading {module_file}: {e}")

    def get_module(self, path: str) -> Optional[Type[PluginBase]]:
        return self.modules.get(path)
    
    def list_modules(self, category: Optional[str] = None) -> List[str]:
        if category is None:
            return sorted(self.modules.keys())
        
        filtered = [
            path for path in self.modules.keys()
            if path.startswith(f"{category}/")
        ]
        return sorted(filtered)

    def search_modules(self, query: str) -> List[str]:
        query_lower = query.lower()
        results = []
        
        for path, module_class in self.modules.items():
            # Check if query matches path
            if query_lower in path.lower():
                results.append(path)
                continue
            
            # Check module metadata
            try:
                # Create temporary instance to get info
                temp_instance = module_class()
                info = temp_instance.get_info()
                
                # Search in name and description
                if (query_lower in info.name.lower() or
                    query_lower in info.description.lower()):
                    results.append(path)
            
            except Exception:
                # If module fails to instantiate, skip it
                continue
        
        return sorted(results)
