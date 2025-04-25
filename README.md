# Rent-PL
> ***一个端口流量限制脚本，辅助用户对特定端口组进行流量统计与限制，为意欲出租转发、代理类流量的用户提供面板之外的另一种选择***

### 🛠功能特点
- 基于iptables及cron实现了端口流量统计、流量超限拦截和定期重置三大核心功能
- 支持TCP+UDP、IPv4+IPv6
- 低破坏性，不会改动已有的iptables规则及cron任务
- 高灵活性，支持添加多组端口/端口范围/两者的组合
- 简易WEB服务，无需登录机器即可实时查询流量
- 统计指定sports+出站及指定dports+入站的流量——用于转发、代理类用途时，可视为****单向流量****

### ⚠注意事项
- 如果你的****流量转发使用的是iptables****，****请将落地机和中转机端口保持一致****，否则脚本无法正常统计流量
- 如果你设置的端口在动态端口范围内(用```sysctl net.ipv4.ip_local_port_range```查询)，****请确保端口有服务在监听****，否则有小概率多统计流量

### 📑快速使用
> **以下以Debian/Ubuntu为示例**

****1. 安装依赖****

```
sudo apt update && sudo apt upgrade
sudo apt install iptables bc python3 wget nano
```
> 其他部分发行版可能还需手动安装cron (cronie/dcron)

****2. 下载脚本****
```
wget -q https://raw.githubusercontent.com/BlackSheep-cry/Rent-PL/main/rent.sh -O /usr/local/bin/rent.sh && chmod +x /usr/local/bin/rent.sh
```

****3. 初始设置****
```
sudo rent.sh set
```

****4. 端口配置模板****
```
配置格式：单端口/端口范围/两者的自由组合 月度流量限制(GiB) 重置日期(1-28日)
例如：
6020-6030 100.00 1
443,80 1.5 15
5201,5202-5205 1 20 
7020-7030,7090-7095,7096-8000 10 12
PS: 组合时请用英文逗号隔开
```

****5. 初始化服务****
```
sudo rent.sh init
```

****6-A. 交互模式****
```
sudo rent.sh
```

****6-B. 命令行模式****
```
sudo rent.sh 命令选项
```

### ⭐使用截图
|***WEB***|***交互***|
|---|---|
|![image](https://raw.githubusercontent.com/BlackSheep-cry/Rent-PL/main/images/WEB.png)|![image](https://raw.githubusercontent.com/BlackSheep-cry/Rent-PL/main/images/interactive.png)|
