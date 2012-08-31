#!/usr/bin/env python

import sys
import os
import platform

# All other platforms use the Config module
from Loxodo.config import config

if len(sys.argv) > 1:
  config.web_host = sys.argv[1]

from Loxodo.frontends.web import loxodo
sys.exit(2)
