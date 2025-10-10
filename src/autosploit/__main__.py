"""
AutoSploit - Automotive Security Testing Framework
Entry point and command-line interface
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

import structlog
import tomli
from rich.console import Console

# Import our console class
from .cli.console import AutoSploitConsole


def init_logging() -> structlog.stdlib.BoundLogger:
    """
    Initialize structured logging with console and file outputs.

    Returns:
        Configured logger instance
    """
    # Create log directory
    log_dir = Path.home() / ".autosploit" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    # Create log file with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"autosploit_{timestamp}.log"

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Set up file logging
    import logging
    logging.basicConfig(
        filename=str(log_file),
        level=logging.INFO,
        format='%(message)s'
    )

    return structlog.get_logger()


def execute_script(console: AutoSploitConsole, script_path: str, logger: structlog.stdlib.BoundLogger) -> bool:
    """
    Execute commands from a script file.

    Args:
        console: AutoSploit console instance
        script_path: Path to script file
        logger: Logger instance

    Returns:
        True if script executed successfully, False otherwise
    """
    script_file = Path(script_path)

    if not script_file.exists():
        console._print_error(f"Script file not found: {script_path}")
        logger.error("Script file not found", path=script_path)
        return False

    try:
        logger.info("Executing script", path=script_path)
        console._print_info(f"Executing script: {script_path}")

        with open(script_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, 1):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            logger.info("Executing command", line_num=line_num, command=line)
            console._print_info(f"[{line_num}] {line}")

            # Execute the command
            try:
                console.onecmd(line)
            except Exception as e:
                console._print_error(f"Error executing line {line_num}: {e}")
                logger.error("Command execution failed", line_num=line_num, command=line, error=str(e))
                return False

        console._print_success(f"Script completed successfully ({len([l for l in lines if l.strip() and not l.strip().startswith('#')])} commands)")
        logger.info("Script completed successfully")
        return True

    except Exception as e:
        console._print_error(f"Failed to execute script: {e}")
        logger.error("Script execution failed", error=str(e))
        return False


def load_resource_file(console: AutoSploitConsole, resource_path: str, logger: structlog.stdlib.BoundLogger) -> bool:
    """
    Load resource file with module configurations.

    Args:
        console: AutoSploit console instance
        resource_path: Path to resource file
        logger: Logger instance

    Returns:
        True if resource loaded successfully, False otherwise
    """
    resource_file = Path(resource_path)

    if not resource_file.exists():
        console._print_error(f"Resource file not found: {resource_path}")
        logger.error("Resource file not found", path=resource_path)
        return False

    try:
        logger.info("Loading resource file", path=resource_path)
        console._print_info(f"Loading resource file: {resource_path}")

        with open(resource_file, 'rb') as f:
            config = tomli.load(f)

        # Apply configurations
        if 'modules' in config:
            for module_config in config['modules']:
                module_path = module_config.get('path')
                if module_path:
                    console._print_info(f"Loading module: {module_path}")
                    console.onecmd(f"use {module_path}")

                    # Set module options
                    options = module_config.get('options', {})
                    for option_name, option_value in options.items():
                        console.onecmd(f"set {option_name} {option_value}")

        if 'interface' in config:
            interface = config['interface']
            console._print_info(f"Auto-connecting to interface: {interface}")
            console.onecmd(f"connect {interface}")

        console._print_success("Resource file loaded successfully")
        logger.info("Resource file loaded successfully")
        return True

    except Exception as e:
        console._print_error(f"Failed to load resource file: {e}")
        logger.error("Resource file loading failed", error=str(e))
        return False


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        description="AutoSploit - Automotive Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  autosploit                           # Start interactive console
  autosploit --quiet                   # Start without banner
  autosploit --interface can0          # Auto-connect to can0
  autosploit --script commands.txt     # Execute script file
  autosploit --resource config.toml    # Load resource configuration
        """
    )

    parser.add_argument(
        '--script',
        type=str,
        metavar='FILE',
        help='Execute commands from a script file'
    )

    parser.add_argument(
        '--resource',
        type=str,
        metavar='FILE',
        help='Load resource file with module configurations'
    )

    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress banner and startup messages'
    )

    parser.add_argument(
        '--interface',
        type=str,
        metavar='INTERFACE',
        help='Auto-connect to CAN interface on startup (e.g., can0, vcan0)'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )

    return parser


def main() -> int:
    """
    Main entry point for AutoSploit.

    Returns:
        Exit code (0 for success, 1 for error)
    """
    console = Console()

    try:
        # Parse arguments
        parser = create_argument_parser()
        args = parser.parse_args()

        # Initialize logging
        logger = init_logging()
        logger.info("AutoSploit starting", version="0.1.0")

        # Create console instance
        autosploit_console = AutoSploitConsole()

        # Set quiet mode if requested
        if args.quiet:
            autosploit_console.quiet = True
            logger.info("Quiet mode enabled")

        # Handle auto-connect
        if args.interface:
            logger.info("Auto-connecting to interface", interface=args.interface)
            autosploit_console._print_info(f"Auto-connecting to {args.interface}")
            try:
                autosploit_console.do_connect(autosploit_console._convert_to_statement(args.interface))
            except Exception as e:
                autosploit_console._print_error(f"Failed to connect to {args.interface}: {e}")
                logger.error("Auto-connect failed", interface=args.interface, error=str(e))

        # Handle resource file
        if args.resource:
            if not load_resource_file(autosploit_console, args.resource, logger):
                return 1

        # Handle script execution
        if args.script:
            success = execute_script(autosploit_console, args.script, logger)
            if not success:
                return 1

            # Exit after script unless we want interactive mode
            # For now, exit after script completion
            logger.info("Script execution completed, exiting")
            return 0

        # Start interactive console
        logger.info("Starting interactive console")

        try:
            autosploit_console.cmdloop()
        except KeyboardInterrupt:
            autosploit_console._print_info("Interrupted by user")
            logger.info("Interrupted by user")
        except EOFError:
            autosploit_console._print_info("End of input")
            logger.info("End of input")
        finally:
            logger.info("AutoSploit exiting")

        return 0

    except FileNotFoundError as e:
        console.print(f"[red]Error: File not found - {e}[/red]")
        return 1

    except PermissionError as e:
        console.print(f"[red]Error: Permission denied - {e}[/red]")
        return 1

    except ImportError as e:
        console.print(f"[red]Error: Missing dependency - {e}[/red]")
        console.print("[yellow]Please ensure all dependencies are installed[/yellow]")
        return 1

    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        if hasattr(locals(), 'logger'):
            logger.error("Unexpected error", error=str(e), exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())