# AsyncRAT_C2_Search

## 功能
探测发现AsyncRAT C2 工具，目前实现探测特征：
1. TLS证书
2. ping包
3. Jarm指纹

## 使用方法
1. 检测单个端口：
```python
python3 AsyncRAT_C2_Seearch.py host port 
```
![](https://cdn.jsdelivr.net/gh/g1an123/blogimage@main/202403262215797.png)

2. 公网检测、ip、ip段检测，查看`C2公网探测.py` 
```
# scan_ip_range("186.137.33.1", "C") # 扫描ip段，可指定C B段  
# ip_scan("218.204.179.10")          # 扫描单个ip  
# ip_scan("161.97.151.222",7788)     # 扫描单个端口  
# process_target_csv("target1.csv")    # 扫描文件  
# scan_ip_range_from_file("ip_range.txt") # 从文件中获取ip段扫描
```
运行环境：Macos 12.5
其他环境暂未测试

## 公网探测部分
https://github.com/g1an123/AsyncRAT-go-Scanner

相关原理已在先知社区开源：https://xz.aliyun.com/t/14201
## 鸣谢
石总@smc帮忙优化了相关脚本🤪
