#!/usr/bin/env python

import sys
import os
import platform

# On Windows CE, use the "ppygui" frontend.
if platform.system() == "Windows" and platform.release() == "CE":
    from Loxodo.frontends.ppygui import loxodo
    sys.exit()

# All other platforms use the Config module
from Loxodo.config import config

# store base script name, taking special care if we're "frozen" using py2app or py2exe
if hasattr(sys,"frozen") and (sys.platform != 'darwin'):
    config.set_basescript(sys.executable)
else:
    config.set_basescript(__file__)

# If cmdline arguments were given, use the "cmdline" frontend.
if len(sys.argv) > 1:
    from Loxodo.frontends.cmdline import loxodo
    sys.exit()

# In all other cases, use the "wx" frontend.
try:
    import wx
except ImportError as e:
    print('Could not find wxPython, the wxWidgets Python bindings: %s' % e, file=sys.stderr)
    print('Falling back to cmdline frontend.', file=sys.stderr)
    print('', file=sys.stderr)
    from Loxodo.frontends.cmdline import loxodo
    sys.exit()

from Loxodo.frontends.wx import loxodo

