# Build & Run Automation Scripts

This directory contains scripts to automate the build and emulator process for the keyboard app.

## Quick Start

### On Windows:
Simply double-click `build_and_run.bat` or run:
```bash
build_and_run.bat
```

### On Linux/Mac:
```bash
python3 build_and_run.py
```

## Features

✓ Checks all prerequisites (Gradle, ADB, Emulator)
✓ Lists available emulators and lets you choose
✓ Starts emulator automatically
✓ Waits for emulator to boot
✓ Builds the APK
✓ Installs the app
✓ Provides feedback at each step
✓ Handles cleanup automatically

## Command Line Options

```bash
python3 build_and_run.py [OPTIONS]

Options:
  -e, --emulator EMULATOR    Use specific emulator (skip selection)
  --clean                    Clean build artifacts before building
  --skip-emulator           Just build, don't launch emulator
  --skip-build              Just install on running emulator
  -h, --help                Show help message

Examples:
  # Interactive mode (default)
  python3 build_and_run.py

  # Use specific emulator
  python3 build_and_run.py -e Medium_Phone_API_35

  # Clean build
  python3 build_and_run.py --clean

  # Just build, don't start emulator
  python3 build_and_run.py --skip-emulator

  # Just install on running emulator
  python3 build_and_run.py --skip-build
```

## What It Does

1. **Checks Prerequisites**: Verifies Gradle, ADB, and Emulator are installed
2. **Select Emulator**: Lists available AVDs and prompts for selection
3. **Start Emulator**: Launches the selected emulator and waits for boot
4. **Build App**: Runs `gradlew build` to compile the APK
5. **Install App**: Installs the APK using `gradlew installDebug`
6. **Success**: Notifies when everything is complete

## Troubleshooting

### "Python is not installed"
- Install Python 3.6+ from python.org
- Add Python to your PATH environment variable

### "Gradle not found"
- Make sure you're in the keyboard project root directory
- Android Studio should have set up Gradle automatically

### "Emulator timeout"
- The emulator is taking longer to start
- Try running: `python3 build_and_run.py --skip-emulator --skip-build` to manually start emulator
- Then: `python3 build_and_run.py --skip-build` to install

### Build fails with lint errors
- The script automatically skips lint checks to avoid path escape issues
- These are non-critical warnings and don't affect functionality

## Files

- `build_and_run.py` - Main Python automation script
- `build_and_run.bat` - Windows batch launcher
- `BUILD_AND_RUN_README.md` - This file

## Workflow

Typical development workflow:

1. Make code changes in Android Studio
2. Run the build script: `build_and_run.bat` (or `python3 build_and_run.py`)
3. Select emulator when prompted
4. Wait for build and installation
5. Test your changes in the emulator
6. Repeat from step 1

No more manual terminal commands! 🚀
