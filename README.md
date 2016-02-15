# DokuWiki Ucenter Authentication Method
 
## Author

 * 橘子(daxingplay)<daxingplay@gmail.com>
 
## Introduction

This is an alternative authentication method for [DokuWiki](http://www.dokuwiki.org) using [Ucenter](http://www.discuz.net).
For more information, please visit [my blog post](https://daxingplay.me/website/dokuwiki/release-ucenter-authentication-for-dokuwiki.html).

## Suitable for

This auth backend is only suitable for dokuwiki version before **2012-10-13 “Adora Belle”**(included) and older

## HowToUse

For English Users:

 - Put all files in Dokuwiki's base dir.
 - Copy conf/uc.conf.php.dist as conf/uc.conf.php (You can also rename the file.)
 - Enter the Administration interface of Ucenter, click "Application Admin", then "Add a new app"
 - Select "Custom Install", and select the app type as "Others". Then fill the blanks below as you needs.
 - Edit conf/uc.conf.php to match the settings in previous step.
 - Enter Dokuwiki's Admin Interface, set authtype as uc, then set superuser as the admin of Discuz or Ucenter.

For Chinese Users:

 - 下载好源码后，将所有文件放置在Dokuwiki的根目录下。
 - 将conf/uc.conf.php.dist复制一份为conf/uc.conf.php（当然你也可以直接重命名）
 - 进入Ucenter后台，点击应用管理，添加新应用
 - 选择自定义安装，应用类型选择“其它”，应用名称、应用URL根据自己需要填写，然后写一个稍微复杂点的通信密钥，是否开启同步登录，是否接受通知可以根据自己的需要进行选择
 - 点击提交之后，下面会出现“应用的Ucenter配置信息”，复制里面的所有内容
 - 编辑conf/uc.conf.php这个文件，把前面的define部分替换为刚才复制的内容
 - 进入Dokuwiki的管理后台，进入配置设置，将authtype（认证后台管理方式）设置为uc，superuser（超级用户）设置为Discuz或者Ucenter的超级管理员的用户名，然后点提交即可
 - 至此，已经安装完毕，进入Ucenter后台看看是否通信成功
 
If you have any questions, please commit an issue.

## ToDo List

 - Add User Group
 - Add multilanguage support
 
## license

MIT