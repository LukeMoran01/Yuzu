- **`vuln_scan` `/tmp noexec` judges the mount actually on top of `/tmp` (#5517).** On Linux the
  check now reads `/proc/self/mountinfo` instead of `/proc/mounts`, finds the top `/tmp` mount by
  its parent links, and matches `noexec` only as an exact token of that mount's options. Before, it
  took the first `/tmp` line and searched all of it, so an exec mount stacked over a noexec one
  could read as passed, and a device name such as `/dev/noexec0` read as noexec. A host in either
  situation now reports MEDIUM.
