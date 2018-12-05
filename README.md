# Python Raw Packet Filter
To run pfilter.py:
---
[Read pfilter.py for more info](https://goo.gl/fTxENV)
```shell
$ python3 pfilter [rules filename] [packet filename]
```

## To run createPkt.py:
**Outputs a bytes file**
```shell
$ python3 createPkt.py [tcp|udp|other] [sourceIP] [sourcePort] [destIP] [destPort] [outputFilename.txt|.dat|etc]
```

## Rules format
**One rule per line**
```text
[allow|deny] [tcp|udp] sourceIP:sourcePort -> destIP:destPort
```

## Sample rule.txt
```text
allow udp 100.100.100.100:10000 -> 10.10.10.10:10
deny tcp 2.1.1.1:10000 -> 10.10.10.10:10
```
---
