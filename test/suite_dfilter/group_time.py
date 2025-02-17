# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest
from suite_dfilter.dfiltertest import *


class TestDfilterTime:
    trace_file = "http.pcap"

    def test_eq_1(self, checkDFilterCount):
        dfilter = 'frame.time == "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_eq_2(self, checkDFilterCount):
        dfilter = 'frame.time == "Jan 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_eq_3(self, checkDFilterCount):
        dfilter = 'frame.time == "2002-12-31 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_ne_1(self, checkDFilterCount):
        dfilter = 'frame.time != "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_ne_2(self, checkDFilterCount):
        dfilter = 'frame.time != "Jan 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_gt_1(self, checkDFilterCount):
        dfilter = 'frame.time > "Dec 31, 2002 13:54:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_gt_2(self, checkDFilterCount):
        dfilter = 'frame.time > "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_gt_3(self, checkDFilterCount):
        dfilter = 'frame.time > "Dec 31, 2002 13:56:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_ge_1(self, checkDFilterCount):
        dfilter = 'frame.time >= "Dec 31, 2002 13:54:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_ge_2(self, checkDFilterCount):
        dfilter = 'frame.time >= "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_ge_3(self, checkDFilterCount):
        dfilter = 'frame.time >= "Dec 31, 2002 13:56:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_lt_1(self, checkDFilterCount):
        dfilter = 'frame.time < "Dec 31, 2002 13:54:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_lt_2(self, checkDFilterCount):
        dfilter = 'frame.time < "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_lt_3(self, checkDFilterCount):
        dfilter = 'frame.time < "Dec 31, 2002 13:56:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_le_1(self, checkDFilterCount):
        dfilter = 'frame.time <= "Dec 31, 2002 13:54:31.3"'
        checkDFilterCount(dfilter, 0)

    def test_le_2(self, checkDFilterCount):
        dfilter = 'frame.time <= "Dec 31, 2002 13:55:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_le_3(self, checkDFilterCount):
        dfilter = 'frame.time <= "Dec 31, 2002 13:56:31.3"'
        checkDFilterCount(dfilter, 1)

    def test_utc_time_1(self, checkDFilterCount):
        dfilter = 'frame.time == "Dec 31, 2002 13:55:31.3 UTC"'
        checkDFilterCount(dfilter, 1)

    def test_bad_time_1(self, checkDFilterFail):
        # This is an error, only UTC timezone can be used
        dfilter = 'frame.time == "Dec 31, 2002 13:56:31.3 WET"'
        error = 'Unexpected data after time value'
        checkDFilterFail(dfilter, error)

    def test_bad_time_2(self, checkDFilterFail):
        # Miliseconds can only occur after seconds.
        dfilter = 'frame.time == "2002-12-31 13:55.3"'
        error = 'requires a seconds field'
        checkDFilterFail(dfilter, error)

    def test_bad_time_3(self, checkDFilterFail):
        # Reject months in a different locale (mrt is March in nl_NL.UTF-8).
        dfilter = 'frame.time == "mrt 1, 2000 00:00:00"'
        error = '"mrt 1, 2000 00:00:00" is not a valid absolute time. Example: "Nov 12, 1999 08:55:44.123" or "2011-07-04 12:34:56"'
        checkDFilterFail(dfilter, error)

class TestDfilterTimeRelative:
    trace_file = "nfs.pcap"

    def test_relative_time_1(self, checkDFilterCount):
        dfilter = "frame.time_delta == 0.7"
        checkDFilterCount(dfilter, 1)

    def test_relative_time_2(self, checkDFilterCount):
        dfilter = "frame.time_delta > 0.7"
        checkDFilterCount(dfilter, 0)

    def test_relative_time_3(self, checkDFilterCount):
        dfilter = "frame.time_delta < 0.7"
        checkDFilterCount(dfilter, 1)
