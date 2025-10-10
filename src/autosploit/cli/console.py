"""
AutoSploit CLI Console - Interactive command-line interface
"""

import cmd2
import tomli
from pathlib import Path
from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ..core.module_manager import ModuleManager


class AutoSploitConsole(cmd2.Cmd):
    """Interactive CLI console for AutoSploit framework."""

    def __init__(self, *args, **kwargs):
        """Initialize the console."""
        super().__init__(*args, **kwargs)

        # Core components
        self.module_manager = ModuleManager()
        self.current_module = None
        self.session = None
        self.console = Console()

        # Initial prompt
        self.prompt = "autosploit > "

        # Set up command aliases
        self.abbrev = True  # Enable command abbreviation

    def _generate_banner(self) -> str:
        """Generate ASCII art banner."""
        # Read version from pyproject.toml
        try:
            pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
            with open(pyproject_path, "rb") as f:
                data = tomli.load(f)
            version = data.get("project", {}).get("version", "unknown")
        except Exception:
            version = "unknown"

        return f"""
    _         _        ____        _       _ _
   / \\  _   _| |_ ___ / ___| _ __ | | ___ (_) |_
  / _ \\| | | | __/ _ \\\\___ \\| '_ \\| |/ _ \\| | __|
 / ___ \\ |_| | || (_) |___) | |_) | | (_) | | |_
/_/   \\_\\__,_|\\__\\___/|____/| .__/|_|\\___/|_|\\__|
                           |_|

Automotive Security Testing Framework v{version}
Type 'help' for available commands
"""

    def preloop(self):
        """Display banner before starting command loop."""
        if not hasattr(self, 'quiet') or not self.quiet:
            self.console.print(self._generate_banner(), style="cyan")

    def _update_prompt(self):
        """Update prompt to show current session and module state."""
        prompt = "autosploit"

        # Add session info
        if self.session:
            prompt += f"[{getattr(self.session, 'interface', 'connected')}]"

        # Add module info
        if self.current_module:
            module_name = getattr(self.current_module, 'module_path', 'unknown')
            prompt += f"({module_name})"

        prompt += " > "
        self.prompt = prompt

    # Module Listing Commands
    def do_list(self, args: cmd2.Statement):
        """List available modules."""
        try:
            if not args:
                # List categories with counts
                categories = {}
                for module_path in self.module_manager.list_modules():
                    category = module_path.split('/')[0] if '/' in module_path else 'misc'
                    categories[category] = categories.get(category, 0) + 1

                table = Table(title="Module Categories")
                table.add_column("Category", style="cyan")
                table.add_column("Count", style="green")

                for category, count in sorted(categories.items()):
                    table.add_row(category, str(count))

                self.console.print(table)
            else:
                # List modules in category
                modules = self.module_manager.list_modules(category=str(args))

                if not modules:
                    self._print_error(f"No modules found in category: {args}")
                    return

                table = Table(title=f"Modules in '{args}' Category")
                table.add_column("Name", style="cyan")
                table.add_column("Category", style="yellow")
                table.add_column("Description")

                for module_path in modules:
                    name = module_path.split('/')[-1]
                    category = module_path.split('/')[0] if '/' in module_path else 'misc'

                    # Try to get description from module
                    try:
                        module_class = self.module_manager.get_module(module_path)
                        if module_class:
                            instance = module_class()
                            info = instance.get_info()
                            description = info.description
                        else:
                            description = "No description available"
                    except Exception:
                        description = "No description available"

                    table.add_row(name, category, description)

                self.console.print(table)

        except Exception as e:
            self._print_error(f"Failed to list modules: {e}")

    def do_search(self, args: cmd2.Statement):
        """Search for modules by keyword."""
        if not args:
            self._print_error("Usage: search <keyword>")
            return

        try:
            results = self.module_manager.search_modules(str(args))

            if not results:
                self._print_info("No modules found matching your search")
                return

            table = Table(title=f"Search Results for '{args}'")
            table.add_column("Name", style="cyan")
            table.add_column("Category", style="yellow")
            table.add_column("Description")

            for module_path in results:
                parts = module_path.split('/')
                category = parts[0] if len(parts) > 1 else 'misc'
                name = parts[-1]

                # Try to get description from module
                try:
                    module_class = self.module_manager.get_module(module_path)
                    if module_class:
                        instance = module_class()
                        info = instance.get_info()
                        description = info.description
                    else:
                        description = "No description available"
                except Exception:
                    description = "No description available"

                table.add_row(name, category, description)

            self.console.print(table)

        except Exception as e:
            self._print_error(f"Search failed: {e}")

    # Module Management Commands
    def do_use(self, args: cmd2.Statement):
        """Load a module for use."""
        if not args:
            self._print_error("Usage: use <module_path>")
            return

        try:
            module_class = self.module_manager.get_module(str(args))
            if not module_class:
                self._print_error(f"Module not found: {args}")
                return

            self.current_module = module_class()
            self.current_module.module_path = str(args)
            self._update_prompt()
            self._print_success(f"Loaded module: {args}")

        except Exception as e:
            self._print_error(f"Failed to load module: {e}")

    def do_back(self, args: cmd2.Statement):
        """Unload current module."""
        self.current_module = None
        self._update_prompt()
        self._print_info("Module unloaded")

    # Module Information Commands
    def do_show_info(self, args: cmd2.Statement):
        """Show information about current module."""
        if not self.current_module:
            self._print_error("No module loaded. Use 'use <module>' first")
            return

        try:
            info = self.current_module.get_info()

            # Create info panel
            content = f"""[bold]{info.name}[/bold]

[yellow]Description:[/yellow]
{info.description}

[yellow]Author:[/yellow] {info.author}
[yellow]Category:[/yellow] {info.category}
[yellow]Risk Level:[/yellow] {self._format_risk_level(info.risk_level)}
"""

            panel = Panel(content, title="Module Information", border_style="blue")
            self.console.print(panel)

        except Exception as e:
            self._print_error(f"Failed to get module info: {e}")

    def do_show_options(self, args: cmd2.Statement):
        """Show current module options."""
        if not self.current_module:
            self._print_error("No module loaded. Use 'use <module>' first")
            return

        try:
            options = self.current_module.get_options()

            table = Table(title="Module Options")
            table.add_column("Option", style="cyan")
            table.add_column("Current Value", style="green")
            table.add_column("Required", style="yellow")
            table.add_column("Description")

            for name, option in options.items():
                required = "[yellow]Yes[/yellow]" if option.required else "No"
                value = str(option.value) if option.value is not None else "[dim]<not set>[/dim]"
                table.add_row(name, value, required, option.description)

            self.console.print(table)

        except Exception as e:
            self._print_error(f"Failed to get options: {e}")

    # Option Setting Commands
    def do_set(self, args: cmd2.Statement):
        """Set module option value."""
        if not self.current_module:
            self._print_error("No module loaded. Use 'use <module>' first")
            return

        if not args or ' ' not in str(args):
            self._print_error("Usage: set <option> <value>")
            return

        try:
            parts = str(args).split(' ', 1)
            option_name = parts[0]
            option_value = parts[1]

            self.current_module.set_option(option_name, option_value)
            self._print_success(f"{option_name} => {option_value}")

        except Exception as e:
            self._print_error(f"Failed to set option: {e}")

    def do_unset(self, args: cmd2.Statement):
        """Clear module option value."""
        if not self.current_module:
            self._print_error("No module loaded. Use 'use <module>' first")
            return

        if not args:
            self._print_error("Usage: unset <option>")
            return

        try:
            self.current_module.unset_option(str(args))
            self._print_info(f"Cleared {args}")

        except Exception as e:
            self._print_error(f"Failed to unset option: {e}")

    # Module Execution Command
    def do_run(self, args: cmd2.Statement):
        """Execute current module."""
        if not self.current_module:
            self._print_error("No module loaded. Use 'use <module>' first")
            return

        try:
            if not self.current_module.validate_options():
                missing = []
                for name, option in self.current_module.get_options().items():
                    if option.required and option.value is None:
                        missing.append(name)

                self._print_error(f"Missing required options: {', '.join(missing)}")
                return

            self._print_info("Executing module...")
            results = self.current_module.run()

            # Format and display results
            if results:
                self.console.print("\n[bold green]Results:[/bold green]")
                if isinstance(results, dict):
                    for key, value in results.items():
                        self.console.print(f"  {key}: {value}")
                elif isinstance(results, list):
                    for item in results:
                        self.console.print(f"  - {item}")
                else:
                    self.console.print(str(results))

            self._print_success("Module completed successfully")

        except Exception as e:
            self._print_error(f"Module execution failed: {e}")

    # Session Management Commands
    def do_connect(self, args: cmd2.Statement):
        """Connect to hardware interface."""
        if not args:
            self._print_error("Usage: connect <interface>")
            return

        try:
            # For now, simulate connection
            interface_name = str(args)
            self.session = type('Session', (), {'interface': interface_name})()
            self._update_prompt()
            self._print_success(f"Connected to {interface_name}")

        except Exception as e:
            self._print_error(f"Connection failed: {e}")

    def do_disconnect(self, args: cmd2.Statement):
        """Disconnect from hardware."""
        if self.session:
            self.session = None
            self._update_prompt()
            self._print_info("Disconnected")
        else:
            self._print_info("Not connected")

    # Exit Command
    def do_exit(self, args: cmd2.Statement):
        """Exit AutoSploit."""
        self._print_info("Goodbye!")
        return True

    # Tab Completion
    def complete_use(self, text, line, begidx, endidx):
        """Tab completion for use command."""
        try:
            modules = self.module_manager.list_modules()
            return [m for m in modules if m.startswith(text)]
        except:
            return []

    def complete_set(self, text, line, begidx, endidx):
        """Tab completion for set command."""
        if not self.current_module:
            return []

        try:
            options = self.current_module.get_options()
            return [opt for opt in options.keys() if opt.startswith(text)]
        except:
            return []

    def complete_list(self, text, line, begidx, endidx):
        """Tab completion for list command."""
        try:
            # Get dynamic categories from available modules
            modules = self.module_manager.list_modules()
            categories = set()
            for module_path in modules:
                category = module_path.split('/')[0] if '/' in module_path else 'misc'
                categories.add(category)
            return [cat for cat in sorted(categories) if cat.startswith(text)]
        except:
            # Fallback to static categories
            categories = ['scanner', 'diagnostics', 'analyzer', 'exploit']
            return [cat for cat in categories if cat.startswith(text)]

    # Rich Formatting Helpers
    def _format_table(self, headers: List[str], rows: List[List[str]], title: str = None) -> Table:
        """Create a formatted Rich table."""
        table = Table(title=title)
        for header in headers:
            table.add_column(header)
        for row in rows:
            table.add_row(*row)
        return table

    def _print_success(self, message: str):
        """Print success message with green prefix."""
        self.console.print(f"[green][+][/green] {message}")

    def _print_error(self, message: str):
        """Print error message with red prefix."""
        self.console.print(f"[red][-][/red] {message}")

    def _print_info(self, message: str):
        """Print info message with cyan prefix."""
        self.console.print(f"[cyan][*][/cyan] {message}")

    def _format_risk_level(self, risk_level: str) -> str:
        """Format risk level with appropriate color."""
        colors = {
            'safe': 'green',
            'low': 'green',
            'medium': 'yellow',
            'high': 'red',
            'critical': 'red bold'
        }
        color = colors.get(risk_level.lower(), 'white')
        return f"[{color}]{risk_level.upper()}[/{color}]"

    # Command aliases
    def do_ls(self, args):
        """Alias for list command."""
        return self.do_list(args)

    def do_quit(self, args):
        """Alias for exit command."""
        return self.do_exit(args)

    def do_info(self, args):
        """Alias for show_info command."""
        return self.do_show_info(args)

    def do_options(self, args):
        """Alias for show_options command."""
        return self.do_show_options(args)

    def _convert_to_statement(self, text: str) -> cmd2.Statement:
        """Convert string to cmd2.Statement object."""
        return cmd2.Statement(text)