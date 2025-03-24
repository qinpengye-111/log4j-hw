# log4j漏洞代码分析和修复

## log4j漏洞缺陷代码逆向分析和定位

进入容器内找到相应的代码文件并且复制到靶机

![alt text](image-1.png)

![alt text](image-2.png)

![alt text](image-3.png)

在`/home/kali/demo_extracted/demo_extracted/BOOT-INF/classes/com/example/log4j2_rce`中存在`Log4j2RceApplication.class`通过CFR/`cfr-0.152.jar`进行反编译得到如下代码，发现trustURLcodebase属性为true，这里存在绕过的风险

![alt text](image-4.png)
