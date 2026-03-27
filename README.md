# AOT

## 概述



## TODO

- [ ]: 其实这个是AOT模块，之后改一改。
- [ ]: 

## 使用方法

```shell
clang -O2 -target bpf -c xdp_hello.c -o xdp_hello.o
// 输出字节到标准输出
llvm-readelf -x xdp xdp_hello.o | grep -oE '[0-9a-fA-F]{8}' | sed 's/^/0x/' | ./bpf2rv
// 输出到文件
```