# jwt-compare
### 过程：  
 创建jws，并验证jws(不含密钥生成时间)

### 测试环境：
操作系统：Mac OS  
内存：8GB  
CPU core: 2
> 本地测试只做性能纵向对比，具体耗时取决于具体运行环境 


### 测试有效数据长度：
> 61

### 测试结果:

| 算法 | 循环次数 |总耗时(ms) |平均耗时(ms)|
| ------ | ----- | -------| ------|
| 对称加密|
| HS256 | 10000 | 2142 | 0.21 |
| HS384 | 10000 | 2492 | 0.24 |
| HS512 | 10000 | 2153 | 0.21 |
| HS256 | 100000 | 5964 | 0.059 |
| HS384 | 100000 | 5368 | 0.053 |
| HS512 | 100000 | 5210 | 0.052 |
| 非对称加密 RSA|
| RS256 | 10000 | 30342 | 3.03 |
| RS384 | 10000 | 88314 | 8.83|
| RS512 | 10000 | 196748| 19.67|
| RS256 | 100000 | 285911| 2.85|
| RS384 | 100000 | 858241| 8.58|
| RS512 | 100000 | 1861344| 18.61|
| 非对称加密 ECDSA|
| ES256 | 10000 | 32375| 3.23|
| ES384 | 10000 | 64646| 6.46|
| ES512 | 10000 | 86273 | 8.62|
| ES256 | 100000 | 285097| 2.85|
| ES384 | 100000 | 667266| 6.67|
| ES512 | 100000 | 764695| 7.64|

