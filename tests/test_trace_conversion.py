#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pylint: disable=wrong-import-position
# pylint: disable=protected-access

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../core')))

from chrome2otf2 import ChromeTrace2OTF2  # noqa: E402


# Try out that trace conversion does not throw exceptions.
@pytest.mark.parametrize("trace_name", ["memcpy-host-device.rocprofiler.json.gz"])
def test_conversion(tmpdir, trace_name):
    input_file = os.path.join(os.path.dirname(__file__), "data", trace_name)
    output_folder = os.path.join(tmpdir, trace_name)
    ChromeTrace2OTF2(input_file).convert_trace(output_folder)
    assert os.path.exists(os.path.join(output_folder, "traces.otf2"))
