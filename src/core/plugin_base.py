from enum import Enum
from dataclasses import dataclass
from typing import Any, Optional, List, Dict
from abc import ABC, abstractmethod

class RiskLevel(Enum):
    LOW = "low" #passive operations (scanning, monitoring)
    MEDIUM = "medium" #active testing but minimal risks
    HIGH = "high" #will modify state (fuzzing, writing data)
    CRITICAL = "critical" #potentially dangerous

class ModuleType(Enum):
    SCANNER = "scanner"
    DIAGNOSTIC = "diagnostics"
    ANALYZER = "analyzer"
    EXPLOIT = "exploit"
    AUXILIARY = "auxiliary"

@dataclass
class ModuleOption:
    value: Any #Current Value (can be any type)
    required: bool 
    description: str
    default: Any = None #default value if not set
    choices: Optional[List[Any]] = None

    def __post_init__(self):
        if self.value is None and self.default is not None:
            self.value = self.default

@dataclass
class ModuleInfo:
    name: str #display name
    description: str
    author: List[str]
    version: str
    module_type: ModuleType
    risk_level: RiskLevel
    references: List[str] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []

class PluginBase(ABC):
    """
    Abstract base class for all Autosploit modules.
    
    This class provides the foundation for all modules. 
    Modules must implement the abstract methods to define
    their behavior.
    
    Attributes:
        session: Optional Session object for hardware access
        options: Dict of ModuleOption objects
        logger: Logger instance for this module
    
    Example:
        class MyScanner(PluginBase):
            def get_info(self):
                return ModuleInfo(...)
            
            def _setup_options(self):
                self.options = {
                    'INTERFACE': ModuleOption(...)
                }
            
            def run(self):
                interface = self.get_option('INTERFACE')
                # ... scanning logic
                return {'status': 'success'}
    """

    def __init__(self, session: Optional['Session'] = None): #will make Session in a moment
        self.session = session
        self.options: Dict[str, ModuleOption] = {}
        self.logger = None #make sure to set up properly when we add logging

        self._setup_options()

#These need to be implemented by subclass

    @abstractmethod
    def get_info(self) -> ModuleInfo:
        pass

    @abstractmethod
    def _setup_options(self):
        """
        Example:
            self.options = {
                'INTERFACE': ModuleOption(
                value=None,
                required=True,
                Description='Im Batman'
                )
            }
        """
        pass

    @abstractmethod
    def run(self) -> Dict[str, Any]:
        pass

    def validate_options(self) -> bool:
        #validate all required options are set
        missing = []
        for name, option in self.options.items():
            if option.required and option.value is None:
                missing.append(name)

        if missing:
            raise ValueError(
                f"Missing required options: {','.join(missing)}"
            )
        return True

    def set_option(self, name: str, value: Any):
        #set the value of a module option
        if name not in self.options:
            raise KeyError(f"Unknown option: {name}")
        option = self.options[name]
        if option.choices is not None and value not in option.choices:
            #validating against choices if defined
            raise ValueError(
                f"Invalid value '{value}' for {name}. "
                f"Must be one of: {option.choices}"
            )
        option.value = value
        self.log_info(f"Set {name} = {value}")
        
    def get_option(self, name:str) -> Any:
        #retrieves the current value of an option
        if name not in self.options:
            raise KeyError(f"Unknown option: {name}")
        
        return self.options[name].value
        

    def log_info(self, msg: str):
        #informational message
        print(f"[*] {msg}")

    def log_success(self, msg: str):
        #success message
        print(f"[+] {msg}")

    def log_error(self, msg: str):
        #error message
        print(f"[-] {msg}")

    def log_warning(self, msg: str):
        print(f"[!] {msg}")