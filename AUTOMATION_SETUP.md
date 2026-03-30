# Automation Scripts Setup Guide

## What Was Created

I've created an automated build and emulator runner system so you don't need the terminal after code changes.

### Files Created:

1. **build_and_run.py** - Main Python automation script (900+ lines)
   - Handles all the heavy lifting
   - Cross-platform (Windows, Linux, Mac)
   - Feature-rich with options

2. **build_and_run.bat** - Windows batch launcher
   - Double-click friendly entry point
   - Launches the Python script

3. **run.bat** - Quick launch script
   - Pre-configured for your setup
   - Fastest way to run (just double-click)

4. **BUILD_AND_RUN_README.md** - Complete documentation

## How to Use

### Fastest Way (Recommended):
Double-click `run.bat` in the project root folder

### Interactive Mode:
Double-click `build_and_run.bat` and select emulator when prompted

### Command Line (Advanced):
```bash
python build_and_run.py [options]
```

## What Happens When You Run It

1. ✓ Checks if all tools are installed
2. ✓ Lists available Android emulators
3. ✓ You select which emulator to use
4. ✓ Automatically starts the emulator
5. ✓ Builds the APK
6. ✓ Installs it on the emulator
7. ✓ Notifies you when done

**Time**: Typically 3-4 minutes total on first run, 1-2 minutes on subsequent runs

## Options

```bash
# Default interactive mode
python build_and_run.py

# Use specific emulator (no selection prompt)
python build_and_run.py -e Medium_Phone_API_35

# Clean build (removes old artifacts)
python build_and_run.py --clean

# Just build, skip emulator
python build_and_run.py --skip-emulator

# Just install on already-running emulator
python build_and_run.py --skip-build
```

## Requirements

- Python 3.6+ (check with `python --version`)
- Android Studio or Android SDK installed
- Gradle (automatically installed with Android Studio)

## Typical Development Flow

1. Make changes to code in Android Studio
2. Double-click `run.bat` to build and deploy
3. Test on emulator
4. Repeat

No more typing gradle commands! 🎉

## Troubleshooting

**"Python not found"**
- Install Python 3.6+ from python.org
- Add Python to PATH

**"Gradle not found"**
- Make sure you're in the keyboard project root directory
- Or install Android SDK

**"Emulator not found"**
- Create an AVD in Android Studio
- Or download one from Tools → AVD Manager

**Script hangs**
- Press Ctrl+C to stop
- Check that emulator isn't already running
- Try `python build_and_run.py --skip-emulator` to just build

## Customization

Edit `run.bat` to change the default emulator:
```batch
python build_and_run.py -e YOUR_EMULATOR_NAME
```

Find your emulator name:
```bash
python build_and_run.py
# It will list them
```

---

**Questions?** Check BUILD_AND_RUN_README.md for detailed documentation
