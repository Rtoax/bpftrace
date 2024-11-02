sudo bpftrace -e 'BEGIN{printf("%s\n", cgroup_path(1));}'
