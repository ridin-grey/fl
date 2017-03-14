from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need
# fine tuning.
buildOptions = dict(packages = [], excludes = [], includes = ['os'], include_files = ['bin', 'fl_conf.json'], include_msvcr = True)

import sys
base = 'Win32GUI' if sys.platform=='win32' else None

executables = [
    Executable('fl.py', base=base, targetName = 'FlexiLigner.exe', icon='fl_icon.ico')
]


shortcut_table = [
    ("ProgramMenuShortcut",        # Shortcut
     "ProgramMenuFolder",          # Directory_
     "FlexiLigner Sync",     # Name
     "TARGETDIR",              # Component_
     "[TARGETDIR]FlexiLigner.exe",   # Target
     None,                     # Arguments
     None,                     # Description
     None,                     # Hotkey
     None,                     # Icon
     None,                     # IconIndex
     None,                     # ShowCmd
     'TARGETDIR'               # WkDir
     ),

    ("StartupShortcut",        # Shortcut
     "StartupFolder",          # Directory_
     "FlexiLigner Sync",     # Name
     "TARGETDIR",              # Component_
     "[TARGETDIR]FlexiLigner.exe",   # Target
     None,                     # Arguments
     None,                     # Description
     None,                     # Hotkey
     None,                     # Icon
     None,                     # IconIndex
     None,                     # ShowCmd
     'TARGETDIR'               # WkDir
     ),

    ]

msi_data = {"Shortcut": shortcut_table}

bdist_msi_options = {'data': msi_data, 'upgrade_code': '{9cb335e4-90f1-4e69-8c00-131f72fd9655}'}

setup(name='FlexiLigner Sync',
      version = '0.5.1',
      author = 'Igor Zhidkov',
      author_email = 'igorzhidkoff@gmail.com',
      description = 'FlexiLigner Synchronizer',
      options = dict(build_exe = buildOptions, bdist_msi = bdist_msi_options),
      executables = executables)
