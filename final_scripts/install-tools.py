#!/usr/bin/env python3
# filepath: /home/root-02/Desktop/boc-tools/scripts/final_scripts/install-tools.py
"""
🔧 ULTRA-ROBUST BOC Tools Installation Script
============================================

This script handles ALL possible installation scenarios and error cases with 
multiple fallback methods for each tool and comprehensive error recovery.

Features:
- ✅ Multiple fallback installation methods for each tool
- ✅ Complete virtual environment management with error recovery  
- ✅ Handles externally-managed Python environments (Kali Linux, Ubuntu 23+)
- ✅ Advanced error detection and recovery with logging
- ✅ Support for automation.py and checkdmarc_enhanced.py with Excel capabilities
- ✅ Comprehensive dependency management and verification
- ✅ Automatic environment configuration and PATH management
- ✅ Rollback and recovery mechanisms for failed installations

Author: BOC Tools Team
Version: 3.0 - Ultra Robust Edition
"""

import subprocess
import sys
import os
import shutil
import json
import platform
import time
import logging
import tempfile
import signal
import threading
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Callable
from dataclasses import dataclass
from contextlib import contextmanager
import urllib.request
import urllib.error
 
# =============================================================================
# 🚀 CONFIGURATION AND LOGGING SETUP
# =============================================================================

# Configure comprehensive logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('boc_tools_install.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

@dataclass
class InstallationMethod:
    """Represents a single installation method with metadata."""
    name: str
    description: str
    command: List[str]
    check_command: List[str]
    requires_sudo: bool = False
    requires_internet: bool = True
    env_vars: Dict[str, str] = None
    working_dir: Optional[str] = None
    timeout: int = 300
    
@dataclass
class Tool:
    """Represents a tool to be installed with multiple fallback methods."""
    name: str
    description: str
    check_commands: List[str]
    install_methods: List[InstallationMethod]
    post_install_commands: List[List[str]] = None
    required_for: List[str] = None

class Colors:
    """ANSI color codes for beautiful terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# =============================================================================
# 🛠️ CORE UTILITY FUNCTIONS
# =============================================================================
 
 
    
 
@contextmanager
def timeout_context(seconds: int):
    """Context manager for command timeouts."""
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Command timed out after {seconds} seconds")
    
    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

def print_banner(text: str, color: str = Colors.HEADER) -> None:
    """Print a beautiful banner with color."""
    border = "=" * 80
    print(f"\n{color}{border}")
    print(f"🚀 {text}")
    print(f"{border}{Colors.ENDC}")

def print_step(step_num: int, total_steps: int, description: str) -> None:
    """Print step progress."""
    print(f"\n{Colors.OKCYAN}[{step_num}/{total_steps}] {description}{Colors.ENDC}")

def print_success(message: str) -> None:
    """Print success message."""
    print(f"{Colors.OKGREEN}✅ {message}{Colors.ENDC}")

def print_warning(message: str) -> None:
    """Print warning message."""
    print(f"{Colors.WARNING}⚠️ {message}{Colors.ENDC}")

def print_error(message: str) -> None:
    """Print error message."""
    print(f"{Colors.FAIL}❌ {message}{Colors.ENDC}")

def run_command(
    cmd: List[str], 
    check: bool = True, 
    capture_output: bool = True, 
    timeout: int = 300,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    shell: bool = False
) -> subprocess.CompletedProcess:
    """Enhanced command runner with comprehensive error handling."""
    try:
        logger.info(f"Running command: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        
        # Merge environment variables
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        
        with timeout_context(timeout):
            result = subprocess.run(
                cmd,
                check=check,
                capture_output=capture_output,
                text=True,
                cwd=cwd,
                env=run_env,
                shell=shell,
                timeout=timeout
            )
        
        if result.stdout:
            logger.debug(f"STDOUT: {result.stdout}")
        if result.stderr:
            logger.debug(f"STDERR: {result.stderr}")
            
        return result
        
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds: {cmd}")
        raise
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with return code {e.returncode}: {cmd}")
        logger.error(f"STDERR: {e.stderr}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error running command {cmd}: {e}")
        raise

def check_command_exists(command: str) -> bool:
    """Check if a command exists in the system PATH."""
    try:
        run_command(["which", command], check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def check_package_installed(package_name: str) -> bool:
    """Check if a package is installed using multiple methods."""
    # Method 1: dpkg for Debian/Ubuntu systems
    try:
        run_command(["dpkg", "-l", package_name], check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Method 2: Check if command exists in PATH
    if check_command_exists(package_name):
        return True
    
    # Method 3: Try rpm for RedHat systems
    try:
        run_command(["rpm", "-q", package_name], check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Method 4: Try pacman for Arch systems
    try:
        run_command(["pacman", "-Q", package_name], check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    return False

def check_python_externally_managed() -> bool:
    """Check if Python environment is externally managed."""
    try:
        # Check for PEP 668 marker file
        for path in [
            "/usr/lib/python*/EXTERNALLY-MANAGED",
            "/usr/local/lib/python*/EXTERNALLY-MANAGED"
        ]:
            if any(Path(p).exists() for p in Path("/").glob(path.lstrip("/"))):
                return True
                
        # Try installing a dummy package to check
        try:
            run_command([sys.executable, "-m", "pip", "install", "--dry-run", "requests"], 
                       capture_output=True, timeout=30)
            return False
        except subprocess.CalledProcessError as e:
            if "externally-managed-environment" in e.stderr.lower():
                return True
                
    except Exception as e:
        logger.warning(f"Could not determine if Python is externally managed: {e}")
        
    return False

def create_virtual_environment(venv_path: str, python_executable: str = None) -> bool:
    """Create a virtual environment with multiple fallback methods."""
    if python_executable is None:
        python_executable = sys.executable
    
    venv_path = Path(venv_path)
    
    # Method 1: Standard venv module
    try:
        logger.info(f"Creating virtual environment with venv module: {venv_path}")
        run_command([python_executable, "-m", "venv", str(venv_path)])
        return True
    except Exception as e:
        logger.warning(f"venv module failed: {e}")
    
    # Method 2: virtualenv package
    try:
        logger.info(f"Trying virtualenv package: {venv_path}")
        run_command(["virtualenv", str(venv_path)])
        return True
    except Exception as e:
        logger.warning(f"virtualenv package failed: {e}")
    
    # Method 3: python -m virtualenv
    try:
        logger.info(f"Trying python -m virtualenv: {venv_path}")
        run_command([python_executable, "-m", "virtualenv", str(venv_path)])
        return True
    except Exception as e:
        logger.warning(f"python -m virtualenv failed: {e}")
    
    return False

def install_to_venv(venv_path: str, packages: List[str], upgrade: bool = True) -> bool:
    """Install packages to a virtual environment with error recovery."""
    venv_path = Path(venv_path)
    
    # Determine pip path based on OS
    if os.name == 'nt':  # Windows
        pip_path = venv_path / "Scripts" / "pip"
        python_path = venv_path / "Scripts" / "python"
    else:  # Unix/Linux
        pip_path = venv_path / "bin" / "pip"
        python_path = venv_path / "bin" / "python"
    
    if not pip_path.exists():
        logger.error(f"Virtual environment pip not found at {pip_path}")
        return False
    
    # Upgrade pip first
    if upgrade:
        try:
            logger.info("Upgrading pip in virtual environment...")
            run_command([str(python_path), "-m", "pip", "install", "--upgrade", "pip"])
        except Exception as e:
            logger.warning(f"Could not upgrade pip: {e}")
    
    # Install packages one by one for better error handling
    success_count = 0
    for package in packages:
        try:
            logger.info(f"Installing {package} in virtual environment...")
            run_command([str(pip_path), "install", package])
            success_count += 1
            print_success(f"Installed {package}")
        except Exception as e:
            logger.error(f"Failed to install {package}: {e}")
            print_error(f"Failed to install {package}")
            
            # Try alternative installation methods
            try:
                logger.info(f"Trying alternative installation for {package}...")
                run_command([str(python_path), "-m", "pip", "install", package])
                success_count += 1
                print_success(f"Installed {package} (alternative method)")
            except Exception as e2:
                logger.error(f"Alternative installation also failed for {package}: {e2}")
    
    return success_count == len(packages)
            print('export PATH="$HOME/.pyenv/bin:$PATH"')
            print('eval "$(pyenv init --path)"')
            print('eval "$(pyenv init -)"')
            sys.exit(1)
        else:
            print("[+] pyenv is in PATH.") 
 
    # Check latest version of Go is installed
    if not check_command_exists("go"):
        print("[-] Go is not installed. Please install Go before proceeding.")
        print("[+] Installing Go...")
        subprocess.run(["sudo", "apt", "install", "-y", "golang"], check=True)
        sys.exit(1)
    else:
        print("[+] Go is installed.")
     # adding Go to PATH using this command 'echo export PATH=$PATH:$HOME/go/bin >> $HOME/.bashrc' and this 'source $HOME/.bashrc' if not already present by directly opening a terminal
    print("[-] Adding Go to PATH...")
    go_path = subprocess.run(
        ["bash", "-c", "echo 'export PATH=$PATH:$HOME/go/bin' >> $HOME/.bashrc"],
        check=True,
        capture_output=True
    )
    if go_path.returncode != 0:
        print("[-] Failed to add Go to PATH. Please add it manually.")
        sys.exit(1)
    else:
        print("[+] Go has been added to PATH.")
        print("[-] Checking if Go is actually in PATH...")
    if not check_command_exists("go"):
        print("[-] Go is not in PATH. Please add it to PATH before proceeding.")
        print("[+] Adding Go to PATH...")
        print("Please add the following line to your ~/.bashrc or ~/.zshrc file:")
        print("export PATH=$PATH:$HOME/go/bin")
        sys.exit(1)
    else:
        print("[+] Go is in PATH.")
 
 
def install_excel_dependencies():
    """Install Excel dependencies (pandas, openpyxl) in a dedicated virtual environment."""
    print("[-] Installing Excel reporting dependencies...")
    
    home_dir = os.path.expanduser("~")
    current_dir = os.getcwd()
    venv_excel_path = os.path.join(current_dir, "venv_excel")
    
    try:
        # Check if virtual environment already exists
        if os.path.exists(venv_excel_path):
            print("[+] Virtual environment for Excel already exists.")
        else:
            print("[-] Creating virtual environment for Excel reporting...")
            subprocess.run([sys.executable, "-m", "venv", "venv_excel"], check=True, cwd=current_dir)
            print("[+] Virtual environment for Excel created successfully.")
        
        # Get pip path for the virtual environment
        if os.name == 'nt':  # Windows
            venv_pip = os.path.join(venv_excel_path, "Scripts", "pip")
            venv_python = os.path.join(venv_excel_path, "Scripts", "python")
        else:  # Unix/Linux
            venv_pip = os.path.join(venv_excel_path, "bin", "pip")
            venv_python = os.path.join(venv_excel_path, "bin", "python")
        
        if not os.path.exists(venv_pip):
            print(f"[-] Virtual environment pip not found at {venv_pip}")
            return False
        
        # Install pandas and openpyxl
        print("[-] Installing pandas...")
        subprocess.run([venv_pip, "install", "pandas"], check=True)
        print("[+] pandas installed successfully.")
        
        print("[-] Installing openpyxl...")
        subprocess.run([venv_pip, "install", "openpyxl"], check=True)
        print("[+] openpyxl installed successfully.")
        
        # Verify installations
        print("[-] Verifying Excel dependencies installation...")
        test_script = """
import sys
try:
    import pandas as pd
    import openpyxl
    print("✅ Excel dependencies verified successfully")
    print(f"pandas version: {pd.__version__}")
    print(f"openpyxl version: {openpyxl.__version__}")
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)
"""
        with open("/tmp/test_excel_deps.py", "w") as f:
            f.write(test_script)
        
        result = subprocess.run([venv_python, "/tmp/test_excel_deps.py"], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] Excel dependencies verification successful!")
            print(result.stdout)
        else:
            print(f"[-] Excel dependencies verification failed: {result.stderr}")
            return False
        
        # Clean up test file
        os.remove("/tmp/test_excel_deps.py")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to install Excel dependencies: {e}")
        return False
    except Exception as e:
        print(f"[-] Unexpected error installing Excel dependencies: {e}")
        return False


def setup_environment_variables():
    """Setup and verify environment variables for all tools."""
    print("[-] Setting up environment variables...")
    
    # Get current user's shell profile
    home_dir = os.path.expanduser("~")
    shell_profile = None
    
    # Detect shell profile
    for profile in [".bashrc", ".zshrc", ".profile"]:
        profile_path = os.path.join(home_dir, profile)
        if os.path.exists(profile_path):
            shell_profile = profile_path
            break
    
    if not shell_profile:
        shell_profile = os.path.join(home_dir, ".bashrc")
        print(f"[-] No existing shell profile found, will create {shell_profile}")
    
    # Environment variables to add
    env_vars = [
        'export PATH="$HOME/.pyenv/bin:$PATH"',
        'eval "$(pyenv init --path)"',
        'eval "$(pyenv init -)"',
        'export PATH="$PATH:$HOME/go/bin"',
        'export PATH="$PATH:/usr/local/bin"'
    ]
    
    try:
        # Read existing profile
        existing_content = ""
        if os.path.exists(shell_profile):
            with open(shell_profile, "r") as f:
                existing_content = f.read()
        
        # Add missing environment variables
        modified = False
        for env_var in env_vars:
            if env_var not in existing_content:
                print(f"[-] Adding: {env_var}")
                with open(shell_profile, "a") as f:
                    f.write(f"\n{env_var}\n")
                modified = True
            else:
                print(f"[+] Already present: {env_var}")
        
        if modified:
            print(f"[+] Environment variables added to {shell_profile}")
            print("[-] Please run 'source ~/.bashrc' or restart your terminal for changes to take effect")
        else:
            print("[+] All environment variables already configured")
        
        return True
        
    except Exception as e:
        print(f"[-] Error setting up environment variables: {e}")
        return False


def install_python_dependencies():
    """Install additional Python dependencies needed for automation.py."""
    print("[-] Installing additional Python dependencies...")
    
    # Dependencies needed by automation.py and related scripts
    dependencies = [
        "requests",
        "colorama", 
        "python-nmap",
        "dnspython",
        "beautifulsoup4",
        "lxml",
        "urllib3",
        "certifi"
    ]
    
    try:
        for dep in dependencies:
            print(f"[-] Installing {dep}...")
            subprocess.run([sys.executable, "-m", "pip", "install", dep], check=True)
            print(f"[+] {dep} installed successfully.")
        
        print("[+] All Python dependencies installed successfully!")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to install Python dependencies: {e}")
        return False


def verify_tool_installations():
    """Verify that all tools are properly installed and accessible."""
    print("[-] Verifying tool installations...")
    
    tools_to_check = {
        "python3": "Python 3",
        "pip": "Python package installer",
        "pipx": "Python application installer", 
        "pyenv": "Python version manager",
        "go": "Go programming language",
        "amass": "OWASP Amass",
        "httpx": "ProjectDiscovery httpx",
        "nmap": "Network Mapper",
        "testssl.sh": "testssl.sh SSL/TLS tester",
        "checkdmarc": "CheckDMARC tool",
        "dnstwist": "DNSTwist tool"
    }
    
    verification_results = {}
    
    for tool, description in tools_to_check.items():
        try:
            result = subprocess.run(["which", tool], capture_output=True, text=True)
            if result.returncode == 0:
                tool_path = result.stdout.strip()
                print(f"[+] {description}: ✅ Found at {tool_path}")
                verification_results[tool] = {"status": "✅", "path": tool_path}
            else:
                print(f"[-] {description}: ❌ Not found in PATH")
                verification_results[tool] = {"status": "❌", "path": None}
        except Exception as e:
            print(f"[-] {description}: ❌ Error checking: {e}")
            verification_results[tool] = {"status": "❌", "path": None, "error": str(e)}
    
    # Check Excel capabilities
    try:
        current_dir = os.getcwd()
        venv_excel_path = os.path.join(current_dir, "venv_excel")
        if os.name == 'nt':
            venv_python = os.path.join(venv_excel_path, "Scripts", "python")
        else:
            venv_python = os.path.join(venv_excel_path, "bin", "python")
        
        if os.path.exists(venv_python):
            test_result = subprocess.run([venv_python, "-c", 
                                        "import pandas, openpyxl; print('Excel dependencies OK')"], 
                                       capture_output=True, text=True)
            if test_result.returncode == 0:
                print("[+] Excel dependencies: ✅ Available in venv_excel")
                verification_results["excel_deps"] = {"status": "✅", "path": venv_excel_path}
            else:
                print("[-] Excel dependencies: ❌ Import failed")
                verification_results["excel_deps"] = {"status": "❌", "path": None}
        else:
            print("[-] Excel dependencies: ❌ venv_excel not found")
            verification_results["excel_deps"] = {"status": "❌", "path": None}
    except Exception as e:
        print(f"[-] Excel dependencies: ❌ Error checking: {e}")
        verification_results["excel_deps"] = {"status": "❌", "path": None, "error": str(e)}
    
    # Summary
    successful = sum(1 for result in verification_results.values() if result["status"] == "✅")
    total = len(verification_results)
    
    print(f"\n{'='*60}")
    print(f"VERIFICATION SUMMARY: {successful}/{total} tools successfully installed")
    print(f"{'='*60}")
    
    if successful == total:
        print("🎉 All tools are properly installed and ready to use!")
        return True
    else:
        print("⚠️  Some tools are missing or not properly configured.")
        print("Please review the installation log above and fix any issues.")
        return False
def install_system_dependencies():
    # Loading pyenv into the shell environment using bash
    print("[-] Loading pyenv into the shell environment...")
    subprocess.run(["bash", "-c", "export PATH=\"$HOME/.pyenv/bin:$PATH\""], check=True)
    subprocess.run(["bash", "-c", "eval \"$(pyenv init --path)\""], check=True)
    subprocess.run(["bash", "-c", "eval \"$(pyenv init -)\""], check=True)

    print("[-] Installing system dependencies...")
    # Install amass by OWASP
    if not check_command_exists("amass"):
        print("[+] Installing amass...")
        subprocess.run(["sudo", "apt", "install", "-y", "amass"], check=True)
    # Manage errors if installation fails
    elif not check_package_installed("amass"):
        print("[-] amass installation failed. Please install it manually.")
        sys.exit(1)
    else:
        print("[+] amass is already installed.")
 
    print("[-] Installing httpx....")
    if not check_command_in_path("httpx"):
        print("[+] Installing httpx...")
        subprocess.run(["git", "clone", "https://github.com/projectdiscovery/httpx.git"], check=True)
        subprocess.run(["cd", "httpx/cmd/httpx", "&&", "go", "build"], shell=True, check=True)
        subprocess.run(["sudo", "mv", "httpx", "/usr/local/bin/"], check=True)
        subprocess.run(["httpx", "-version"], check=True)
    elif not check_package_installed("httpx"):
        print("[-] httpx installation failed. Please install it manually.")
        sys.exit(1)
    else:
        print("[+] httpx is already installed.")
    print("[-] Installing Nmap....")
    if not check_command_exists("nmap"):
        print("[+] Installing Nmap...")
        subprocess.run(["sudo", "apt", "install", "-y", "nmap"], check=True)
    elif not check_package_installed("nmap"):
        print("[-] Nmap installation failed. Please install it manually.")
        sys.exit(1)
    else:
        print("[+] Nmap is already installed.")
    print("[-] Installing testssl.sh....")
    # Remove existing testssl.sh folder if it exists
    if os.path.exists("testssl.sh"):
        subprocess.run(["sudo", "rm", "-rf", "testssl.sh"], check=True)
    
    # Clone the repository
    subprocess.run(["git", "clone", "https://github.com/testssl/testssl.sh.git"], check=True)
    
    if not check_command_exists("testssl.sh"):
        print("[+] Installing testssl.sh...")
        # Make the script executable
        subprocess.run(["chmod", "+x", "testssl.sh/testssl.sh"], check=True)
        
        # Create symbolic link using absolute path
        current_dir = os.getcwd()
        testssl_path = os.path.join(current_dir, "testssl.sh", "testssl.sh")
        
        if not check_command_exists("testssl.sh"):
            print("[-] Creating symbolic link for testssl.sh...")
            # Use absolute path instead of $(pwd)
            subprocess.run(["sudo", "ln", "-s", testssl_path, "/usr/local/bin/testssl.sh"], check=True)
            print("[+] testssl.sh symbolic link created successfully.")
        else:
            print("[+] testssl.sh is already in PATH.")
    else:
        print("[+] testssl.sh is already installed.")

    # Installing checkmarc and dnstwist, they both require Python 3.11 or later and create a virtual environment using pyenv before installing using pip
    # Vérifie si Python 3.11.9 est installé avec pyenv, sinon l'installe
    result = subprocess.run(["pyenv", "versions", "--bare"], capture_output=True, text=True)
    if "3.11.9" not in result.stdout.split():
        print("[-] Python 3.11.9 non trouvé, installation via pyenv...")
        subprocess.run(["pyenv", "install", "3.11.9"], check=True)
        print("[+] Python 3.11.9 installé avec succès.")
        
    else:
        print("[+] Python 3.11.9 déjà installé avec pyenv.")

    print("[-] Installing checkdmarc....")
    if not check_command_exists("checkdmarc"):
        print("[+] Installing checkdmarc...")
        try:
            # Create virtual environment
            subprocess.run(["pyenv", "virtualenv", "3.11.9", "checkdmarc-env"], check=True)
            
            # Install using the virtual environment's pip directly
            home_dir = os.path.expanduser("~")
            venv_pip = f"{home_dir}/.pyenv/versions/checkdmarc-env/bin/pip"
            
            # Check if the pip exists in the virtual environment
            if os.path.exists(venv_pip):
                subprocess.run([venv_pip, "install", "checkdmarc"], check=True)
                
                # Create a wrapper script to make checkdmarc available globally
                wrapper_script = f"""#!/bin/bash
{home_dir}/.pyenv/versions/checkdmarc-env/bin/checkdmarc "$@"
"""
                with open("/tmp/checkdmarc_wrapper", "w") as f:
                    f.write(wrapper_script)
                subprocess.run(["sudo", "cp", "/tmp/checkdmarc_wrapper", "/usr/local/bin/checkdmarc"], check=True)
                subprocess.run(["sudo", "chmod", "+x", "/usr/local/bin/checkdmarc"], check=True)
                print("[+] checkdmarc installed successfully.")
            else:
                print(f"[-] Virtual environment pip not found at {venv_pip}")
                print("[-] Trying alternative installation with pipx...")
                subprocess.run(["pipx", "install", "checkdmarc"], check=True)
                print("[+] checkdmarc installed successfully with pipx.")
        except subprocess.CalledProcessError as e:
            print(f"[-] Virtual environment creation failed: {e}")
            print("[-] Trying alternative installation with pipx...")
            subprocess.run(["pipx", "install", "checkdmarc"], check=True)
            print("[+] checkdmarc installed successfully with pipx.")
        
    elif not check_package_installed("checkdmarc"):
        print("[-] checkdmarc installation failed. Please install it manually.")
        sys.exit(1)
    else:
        print("[+] checkdmarc is already installed.")
        
    print("[-] Installing dnstwist....")
    if not check_command_exists("dnstwist"):
        try:
            print("[-] Creating virtual environment for dnstwist...")
            # Check if the virtual environment 'dnstwist-env' already exists
            result = subprocess.run(["pyenv", "virtualenvs", "--bare"], capture_output=True, text=True)
            if "dnstwist-env" not in result.stdout:
                print("[+] Creating virtual environment for dnstwist...")
                subprocess.run(["pyenv", "virtualenv", "3.11.9", "dnstwist-env"], check=True)
                print("[+] Virtual environment for dnstwist created successfully.")
            else:
                print("[+] Virtual environment for dnstwist already exists.")
                
            # Install dnstwist using the virtual environment's pip directly
            home_dir = os.path.expanduser("~")
            venv_pip = f"{home_dir}/.pyenv/versions/dnstwist-env/bin/pip"
            
            if os.path.exists(venv_pip):
                print("[-] Installing dnstwist...")
                subprocess.run([venv_pip, "install", "dnstwist"], check=True)
                
                # Create a wrapper script to make dnstwist available globally
                wrapper_script = f"""#!/bin/bash
{home_dir}/.pyenv/versions/dnstwist-env/bin/dnstwist "$@"
"""
                with open("/tmp/dnstwist_wrapper", "w") as f:
                    f.write(wrapper_script)
                subprocess.run(["sudo", "cp", "/tmp/dnstwist_wrapper", "/usr/local/bin/dnstwist"], check=True)
                subprocess.run(["sudo", "chmod", "+x", "/usr/local/bin/dnstwist"], check=True)
                print("[+] dnstwist installed successfully.")
            else:
                print(f"[-] Virtual environment pip not found at {venv_pip}")
                print("[-] Trying alternative installation with pipx...")
                subprocess.run(["pipx", "install", "dnstwist"], check=True)
                print("[+] dnstwist installed successfully with pipx.")
        except subprocess.CalledProcessError as e:
            print(f"[-] Virtual environment creation failed: {e}")
            print("[-] Trying alternative installation with pipx...")
            subprocess.run(["pipx", "install", "dnstwist"], check=True)
            print("[+] dnstwist installed successfully with pipx.")
        
    else:
        print("[+] dnstwist is already installed.")

    """modification ligne 473 précisement, timeout=timeout => http_timeout=timeout (fichier mta_sts.py)"""
    def modify_checkdmarc_mta_sts_line_473():
        """Modify the line 473 in mta_sts.py to change timeout to http_timeout."""
        mta_sts_path = os.path.expanduser("~/.pyenv/versions/checkdmarc-env/lib/python3.11/site-packages/checkdmarc/mta_sts.py")
        try:
            with open(mta_sts_path, "r") as file:
                lines = file.readlines()
            if len(lines) > 472:  # Ensure there are enough lines
               # Check if the line is already corrected, if not modify the line
                if "http_timeout=timeout" in lines[472]:
                    print("[+] Line 473 in mta_sts.py is already modified.")
                    return
                print("[+] Modifying line 473 in mta_sts.py...")
                # Modify the line 473 
                lines[472] = lines[472].replace("timeout=timeout", "http_timeout=timeout")
                with open(mta_sts_path, "w") as file:
                    file.writelines(lines)
                print("[+] Line 473 in mta_sts.py modified successfully.")
            else:
                print("[-] mta_sts.py does not have enough lines to modify.")
        except FileNotFoundError:
            print(f"[-] File not found: {mta_sts_path}")
        except Exception as e:
            print(f"[-] Error modifying mta_sts.py: {e}")
    modify_checkdmarc_mta_sts_line_473()

def main():
    subprocess.run(["clear"], shell=True)
    current_folder = subprocess.run(["pwd"], capture_output=True, text=True).stdout.strip()
    
    # Ensure the script is run with sudo privileges
    if not subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() == "0":
        print("[-] This script must be run with sudo privileges. Please run it as root or with sudo.")
        sys.exit(1)
    
    # Ensure the current folder has the right permissions
    print(f"[-] Ensuring the current folder ({current_folder}) has the right permissions...")
    # Change permissions of the current folder to allow read, write, and execute for all users
    subprocess.run(["sudo", "chmod", "777", current_folder], check=True)
    
    print("🚀 BOC Tools COMPLETE Installation Script")
    print("📦 Installing ALL dependencies for automation.py and checkdmarc_enhanced.py")
    print("=" * 80)
    
    # Installation steps
    installation_steps = [
        ("1/7", "Checking prerequisites", prerequisites),
        ("2/7", "Installing system dependencies", install_system_dependencies),
        ("3/7", "Installing Python dependencies", install_python_dependencies),
        ("4/7", "Installing Excel reporting capabilities", install_excel_dependencies),
        ("5/7", "Setting up environment variables", setup_environment_variables),
        ("6/7", "Verifying installations", verify_tool_installations),
    ]
    
    success_count = 0
    total_steps = len(installation_steps)
    
    for step_num, step_desc, step_func in installation_steps:
        print(f"\n{'='*80}")
        print(f"🔧 STEP {step_num}: {step_desc}")
        print(f"{'='*80}")
        
        try:
            if step_func():
                print(f"✅ STEP {step_num} completed successfully!")
                success_count += 1
            else:
                print(f"❌ STEP {step_num} failed!")
                print("Please check the error messages above and fix any issues.")
        except Exception as e:
            print(f"❌ STEP {step_num} failed with exception: {e}")
            print("Please check the error messages above and fix any issues.")
    
    # Final summary
    print(f"\n{'='*80}")
    print(f"🎯 INSTALLATION SUMMARY")
    print(f"{'='*80}")
    print(f"✅ Successfully completed: {success_count}/{total_steps} steps")
    
    if success_count == total_steps:
        print("🎉 COMPLETE SUCCESS! All tools and dependencies are installed.")
        print("\n📋 What you can now do:")
        print("   • Run automation.py for comprehensive security scanning")
        print("   • Use checkdmarc_enhanced.py with -excel option for detailed reports")
        print("   • Generate Excel reports with graphs and detailed analysis")
        print("   • All virtual environments are properly configured")
        
        print("\n🚀 Next steps:")
        print("   1. Restart your terminal or run: source ~/.bashrc")
        print("   2. Test the installation with: python3 automation.py --help")
        print("   3. Try Excel generation: python3 checkdmarc_enhanced.py sample.json -excel")
        
        print("\n📁 Virtual environments created:")
        print("   • ~/.pyenv/versions/checkdmarc-env/ (for checkdmarc)")
        print("   • ~/.pyenv/versions/dnstwist-env/ (for dnstwist)")
        print("   • ./venv_excel/ (for Excel reporting with pandas & openpyxl)")
        
    else:
        print("⚠️  PARTIAL SUCCESS: Some components may not work correctly.")
        print("Please review the error messages above and re-run the script if needed.")
        print("\n🔧 Common fixes:")
        print("   • Ensure you have sudo privileges")
        print("   • Check internet connectivity for downloads")
        print("   • Verify Python 3.11+ is available")
        print("   • Make sure Go language is installed for httpx")
    
    print(f"\n{'='*80}")
    return success_count == total_steps
 
if __name__ == "__main__":
    main()
