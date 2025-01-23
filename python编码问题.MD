## Python出现UnicodeEncodeError: 'gbk' codec can't encode character '\xef'如何解决？

![image-20241023012004203](https://s2.loli.net/2024/10/23/TCU6NPlJxZVKek2.png)

在使用request模块中保存文件时会出现这样的报错

#### 原因：编码问题



**如果打开一个文件使用以下代码**

```
with open('dongfang.html','w') as fp:
```

在国区windows下面，新文件的默认编码是gbk，这样的话，python解释器会根据系统的gbk编码去解析我们的网络数据流txt，然而txt此时已经是decode过的unicode编码，这样的话就会导致解析不了，出现上述问题。 

#### 解决方案：

**此时我们可以改成**

```
with open('dongfang.html','w',encoding='utf-8') as fp:
```

**或者直接把系统的全局编码改成utf8（后者应该更为方便）**

![image-20241023013008737](https://s2.loli.net/2024/10/23/X8cR1o7Qh3wFT5j.png)

![image-20241023013030570](https://s2.loli.net/2024/10/23/ot8WbYGnL3qpTSu.png)

参考:

> [解决python3 UnicodeEncodeError: 'gbk' codec can't encode character '\xXX' in position XX_jnicodeencodeerror: ' gbk' codec can't encode char-CSDN博客](https://blog.csdn.net/jim7424994/article/details/22675759)
>
> [Python写入文件报错‘gbk’ codec can’t encode character的解决办法-腾讯云开发者社区-腾讯云](https://cloud.tencent.com/developer/article/2294126)
>
> [把windows系统的默认编码改成UTF-8_改系统的编码,改成utf-8-CSDN博客](https://blog.csdn.net/robinhunan/article/details/106047345)