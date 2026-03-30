#!/usr/bin/env python3
"""
Automated Android App Build and Emulator Runner
This script automates the process of building the keyboard app and running it on an emulator.
"""

import os
import sys
import subprocess
import time
import argparse
from pathlib import Path
from typing import Tuple

# Fix Windows encoding issues
if sys.platform == "win32":
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Configuration
PROJECT_ROOT = Path(__file__).parent.absolute()
GRADLE_CMD = "gradlew.bat" if sys.platform == "win32" else "./gradlew"
ANDROID_SDK_PATH = Path.home() / "AppData" / "Local" / "Android" / "sdk" if sys.platform == "win32" else Path.home() / "Android" / "sdk"
EMULATOR_PATH = ANDROID_SDK_PATH / "emulator" / ("emulator.exe" if sys.platform == "win32" else "emulator")
ADB_PATH = ANDROID_SDK_PATH / "platform-tools" / ("adb.exe" if sys.platform == "win32" else "adb")
APK_INSTALL_TIMEOUT = 120  # seconds
EMULATOR_BOOT_TIMEOUT = 120  # seconds (increased for reliability)
BUILD_TIMEOUT = 600  # seconds


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_header(text: str):
    """Print a formatted header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}")
    print(f"{text:^60}")
    print(f"{'='*60}{Colors.ENDC}\n")


def print_success(text: str):
    """Print success message"""
    print(f"{Colors.OKGREEN}[OK] {text}{Colors.ENDC}")


def print_error(text: str):
    """Print error message"""
    print(f"{Colors.FAIL}[ERROR] {text}{Colors.ENDC}")


def print_info(text: str):
    """Print info message"""
    print(f"{Colors.OKCYAN}[INFO] {text}{Colors.ENDC}")


def print_warning(text: str):
    """Print warning message"""
    print(f"{Colors.WARNING}[WARN] {text}{Colors.ENDC}")


def run_command(cmd: list, timeout: int = None, description: str = "") -> Tuple[bool, str]:
    """
    Run a shell command and return success status and output
    
    Args:
        cmd: Command list to execute
        timeout: Timeout in seconds
        description: Description of what the command does
    
    Returns:
        Tuple of (success: bool, output: str)
    """
    if description:
        print_info(description)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(PROJECT_ROOT)
        )
        
        if result.returncode == 0:
            return True, result.stdout + result.stderr
        else:
            return False, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, f"Command timed out after {timeout} seconds"
    except Exception as e:
        return False, str(e)


def check_prerequisites() -> bool:
    """Check if all required tools are available"""
    print_header("Checking Prerequisites")
    
    checks = [
        (Path(GRADLE_CMD).exists() or run_command([GRADLE_CMD, "--version"])[0], 
         "Gradle"),
        (EMULATOR_PATH.exists(), "Android Emulator"),
        (ADB_PATH.exists(), "Android Debug Bridge (adb)"),
    ]
    
    all_ok = True
    for check, name in checks:
        if check:
            print_success(f"{name} found")
        else:
            print_error(f"{name} not found")
            all_ok = False
    
    return all_ok


def get_available_emulators() -> list:
    """Get list of available Android Virtual Devices"""
    success, output = run_command(
        [str(EMULATOR_PATH), "-list-avds"],
        description="Fetching available emulators..."
    )
    
    if success:
        emulators = [line.strip() for line in output.split('\n') if line.strip()]
        return emulators
    return []


def select_emulator(emulators: list) -> str:
    """Allow user to select an emulator"""
    if not emulators:
        print_error("No emulators found")
        return None
    
    if len(emulators) == 1:
        print_success(f"Using emulator: {emulators[0]}")
        return emulators[0]
    
    print("\nAvailable emulators:")
    for i, emu in enumerate(emulators, 1):
        print(f"  {i}. {emu}")
    
    while True:
        try:
            choice = int(input("\nSelect emulator (number): ")) - 1
            if 0 <= choice < len(emulators):
                return emulators[choice]
        except ValueError:
            pass
        print_warning("Invalid selection, please try again")


def is_emulator_running(emulator_name: str) -> bool:
    """Check if emulator is already running"""
    success, output = run_command([str(ADB_PATH), "devices"])
    if success and emulator_name in output:
        return True
    return False


def start_emulator(emulator_name: str) -> bool:
    """Start the Android emulator"""
    print_header(f"Starting Emulator: {emulator_name}")
    
    if is_emulator_running(emulator_name):
        print_success("Emulator is already running")
        return True
    
    print_info("Launching emulator (this may take a minute)...")
    
    # Start emulator in background
    try:
        subprocess.Popen(
            [str(EMULATOR_PATH), "-avd", emulator_name, "-no-snapshot-load"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Wait for emulator to boot
        print_info("Waiting for emulator to boot...")
        for i in range(EMULATOR_BOOT_TIMEOUT):
            time.sleep(1)
            if is_emulator_running(emulator_name):
                print_success("Emulator is ready")
                return True
            if (i + 1) % 10 == 0:
                print_info(f"Still waiting... ({i + 1}s)")
        
        print_error("Emulator failed to boot within timeout")
        return False
    except Exception as e:
        print_error(f"Failed to start emulator: {e}")
        return False


def clean_build_artifacts() -> bool:
    """Clean previous build artifacts"""
    print_info("Cleaning build artifacts...")
    
    # Kill any running gradle/java processes
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/IM", "java.exe"], 
                         capture_output=True, timeout=5)
            subprocess.run(["taskkill", "/F", "/IM", "gradle.exe"], 
                         capture_output=True, timeout=5)
    except:
        pass
    
    time.sleep(1)
    
    # Stop gradle daemon
    run_command([GRADLE_CMD, "--stop"], description="Stopping Gradle daemon...")
    time.sleep(2)
    
    # Remove build directories more aggressively
    build_dirs = [
        PROJECT_ROOT / "app" / "build",
        PROJECT_ROOT / "frogo-keyboard" / "build",
        PROJECT_ROOT / ".gradle",
    ]
    
    for build_dir in build_dirs:
        if build_dir.exists():
            try:
                import shutil
                # Try multiple times to delete stubborn directories
                max_retries = 5
                for attempt in range(max_retries):
                    try:
                        shutil.rmtree(build_dir, ignore_errors=True)
                        time.sleep(0.5)
                        # Verify deletion
                        if not build_dir.exists():
                            print_success(f"Cleaned {build_dir.name}")
                            break
                        elif attempt < max_retries - 1:
                            time.sleep(2)
                            print_warning(f"Retry {attempt + 1}/{max_retries - 1} for {build_dir.name}")
                    except Exception as e:
                        if attempt == max_retries - 1:
                            print_warning(f"Could not fully clean {build_dir.name}: {e}")
                        else:
                            time.sleep(1)
            except Exception as e:
                print_warning(f"Could not clean {build_dir.name}: {e}")
    
    time.sleep(3)
    return True


def build_app(clean: bool = False) -> bool:
    """Build the Android application"""
    print_header("Building Application")
    
    if clean:
        clean_build_artifacts()
    
    # Retry logic for builds
    max_build_retries = 3
    for build_attempt in range(max_build_retries):
        if build_attempt > 0:
            print_warning(f"Build attempt {build_attempt + 1}/{max_build_retries}")
        
        success, output = run_command(
            [GRADLE_CMD, "build", "-x", "lintDebug", "-x", "lintRelease"],
            timeout=BUILD_TIMEOUT,
            description="Building APK (this may take 2-3 minutes)..." if build_attempt == 0 else "Retrying build..."
        )
        
        if success:
            print_success("Build completed successfully")
            return True
        
        # Check for file lock errors
        has_file_lock = "Couldn't delete" in output or "being used by another process" in output or "Unable to delete" in output
        
        if has_file_lock and build_attempt < max_build_retries - 1:
            print_warning("Build failed due to locked files, cleaning and retrying...")
            clean_build_artifacts()
            time.sleep(2)
        elif not success:
            print_error("Build failed")
            if "error" in output.lower() or "FAILED" in output:
                print("\nRelevant build output:")
                lines = output.split('\n')
                for line in lines:
                    if any(keyword in line for keyword in ["FAILED", "error:", "Unable", "Couldn't", "Exception"]):
                        print(line)
            return False
    
    return False


def install_app(emulator_name: str) -> bool:
    """Install the app on the emulator"""
    print_header("Installing App")
    
    success, output = run_command(
        [GRADLE_CMD, "installDebug"],
        timeout=APK_INSTALL_TIMEOUT,
        description="Installing APK on emulator..."
    )
    
    if success and "Installed" in output:
        print_success("App installed successfully")
        return True
    else:
        print_error("Installation failed")
        return False


def launch_app() -> bool:
    """Launch the keyboard app (optional)"""
    print_info("App is installed and ready to use")
    print_info("To test it:")
    print_info("  1. Open any text field in the emulator")
    print_info("  2. The keyboard should appear automatically")
    print_info("  3. Select the compression button from the menu")
    return True


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description="Automated Android App Builder and Emulator Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python build_and_run.py                 # Interactive mode
  python build_and_run.py -e Medium_Phone_API_35    # Use specific emulator
  python build_and_run.py --clean         # Clean build
  python build_and_run.py --skip-emulator # Just build, don't run emulator
        """
    )
    
    parser.add_argument(
        "-e", "--emulator",
        help="Specific emulator to use (skip selection prompt)",
        default=None
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean build artifacts before building"
    )
    parser.add_argument(
        "--skip-emulator",
        action="store_true",
        help="Skip emulator launch, just build"
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip build, just install on running emulator"
    )
    
    args = parser.parse_args()
    
    print_header("Android App Build & Emulator Automation")
    
    # Check prerequisites
    if not check_prerequisites():
        print_error("Missing required tools. Please install Android SDK")
        sys.exit(1)
    
    # Get emulator
    if args.skip_emulator and args.skip_build:
        print_error("Must either build or run emulator (or both)")
        sys.exit(1)
    
    emulator_name = None
    if not args.skip_emulator:
        emulators = get_available_emulators()
        emulator_name = args.emulator or select_emulator(emulators)
        if not emulator_name:
            sys.exit(1)
    
    # Build
    if not args.skip_build:
        if not build_app(clean=args.clean):
            sys.exit(1)
    
    # Start emulator
    if not args.skip_emulator:
        if not start_emulator(emulator_name):
            sys.exit(1)
        
        # Install app
        if not install_app(emulator_name):
            sys.exit(1)
        
        # Launch
        launch_app()
    
    print_header("All Done! 🎉")
    print_success("Your app is ready to test")


if __name__ == "__main__":
    main()
