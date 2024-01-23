# Copyright (C) 2024 Canonical Ltd.
# Author: Chris Peterson <chris.peterson@canonical.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import datetime
import json
import sys
import urllib
import urllib.request

URL_RUNNING = "http://autopkgtest.ubuntu.com/static/running.json"
URL_QUEUED = "http://autopkgtest.ubuntu.com/queues.json"


def _get_jobs(url: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={"Cache-Control": "max-age-0"},
    )
    with urllib.request.urlopen(request) as response:
        data = response.read()
        jobs = json.loads(data.decode("utf-8"))

    return jobs


def get_running():
    jobs = _get_jobs(URL_RUNNING)

    running = []
    for pkg in jobs:
        for handle in jobs[pkg]:
            for series in jobs[pkg][handle]:
                for arch in jobs[pkg][handle][series]:
                    jobinfo = jobs[pkg][handle][series][arch]
                    triggers = ",".join(jobinfo[0].get("triggers", "-"))
                    ppas = ",".join(jobinfo[0].get("ppas", "-"))
                    time = jobinfo[1]
                    env = jobinfo[0].get("env", "-")
                    time = str(datetime.timedelta(seconds=jobinfo[1]))
                    try:
                        line = f"R     {time:6} {pkg:30} {'-':10} {series:8} {arch:8} {ppas:31} {triggers} {env}\n"
                        running.append((jobinfo[1], line))
                    except BrokenPipeError:
                        sys.exit(1)

    output = ""
    for time, row in sorted(running, reverse=True):
        output += f"{row}"

    return output


def get_queued():
    queues = _get_jobs(URL_QUEUED)
    output = ""
    for origin in queues:
        for series in queues[origin]:
            for arch in queues[origin][series]:
                n = 0
                for key in queues[origin][series][arch]:
                    if key == "private job":
                        pkg = triggers = ppas = "private job"
                    else:
                        (pkg, json_data) = key.split(maxsplit=1)
                        try:
                            jobinfo = json.loads(json_data)
                            triggers = ",".join(jobinfo.get("triggers", "-"))
                            ppas = ",".join(jobinfo.get("ppas", "-"))
                        except json.decoder.JSONDecodeError:
                            pkg = triggers = ppas = "failed to parse"
                            continue

                    n = n + 1
                    try:
                        output += f"Q{n:04d} {'-:--':>6} {pkg:30} {origin:10} {series:8} {arch:8} {ppas:31} {triggers}\n"
                    except BrokenPipeError:
                        sys.exit(1)
    return output
