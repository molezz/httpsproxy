# httpsproxy

纯https代理，方便调用，不依赖第三方客户端

确保根目录tls证书crt.crt和key.key存在

运行自定义:端口  用户名  密码  ：

``` bash
cargo run -- 10000 user pass
```

``` sh
httpsproxy 10000 user pass
```
