# Memory usage example
Original README in https://github.com/libbpf/libbpf-bootstrap

## MMAP and MUNMAP

This example launches a binary using `-p` flag and tracks its memory usage. Ideally, after the end of the execution, `total` should be 0.

```shell
TIME     EVENT COMM             PID     PPID    REQUESTED BYTES  TOTAL
HELLO
BYE
20:19:32 MMAP   allsyscall       10965   10964    4096             4096            
20:19:32 MMAP   allsyscall       10965   10964    4096             8192            
20:19:32 MMAP   allsyscall       10965   10964    4096             12288           
20:19:32 MMAP   allsyscall       10965   10964    4096             16384           
20:19:32 MMAP   allsyscall       10965   10964    16384            32768           
20:19:32 MUNMAP allsyscall       10965   10964   -16384            16384           
20:19:32 MUNMAP allsyscall       10965   10964   -4096             12288           
20:19:32 MUNMAP allsyscall       10965   10964   -4096             8192            
20:19:32 MUNMAP allsyscall       10965   10964   -4096             4096            
20:19:32 MUNMAP allsyscall       10965   10964   -4096             0               
^C
```