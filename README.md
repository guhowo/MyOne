遗留问题：
1 topology.c中生成96位签名时，传进去的ts是何时获取的。     (已经解决)
2 What's the difference between fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK) and fcntl(udp_sockd,F_SETFL,O_NONBLOCK)
3 recvfrom收到的数据，数据结构需要优化成Buffer
4 数据包中latency（迟延）没有处理5 代码流程中未处理Moon，现在默认没有moons
6 报文的分片处理没有实现，现在默认不分片
7 互斥锁没有实现
# MyOne
