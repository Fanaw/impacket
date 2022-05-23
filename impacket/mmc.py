#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Python script for handling the msDS-AllowedToActOnBehalfOfOtherIdentity property of a target computer
#
# Authors:
#   Maxime Meignan (@th3m4ks)
#   Julien Galleron (@fana_win)
#
#  ToDo:
# [ ]: 

from __future__ import division
from __future__ import print_function
import sys
import logging
import argparse
import codecs

from datetime import datetime
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException