

## spring-session-data-redis
### sesssion存的值及属性


`get spring:session:sessions:expires:381be901-f399-443d-baf7-a274a98ac019`

得到
`maxInactiveInterval`
`lastAccessedTime`
`creationTime`
`sessionAttr:Mic`

```java
request.getSession().setAttribute("Mic","value");
```



```
127.0.0.1:6379> hgetall spring:session:sessions:e8b7c9a1-8c4a-4f03-996f-619cfba91ea1
1) "maxInactiveInterval"
2) "\xac\xed\x00\x05sr\x00\x11java.lang.Integer\x12\xe2\xa0\xa4\xf7\x81\x878\x02\x00\x01I\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x02X"
3) "lastAccessedTime"
4) "\xac\xed\x00\x05sr\x00\x0ejava.lang.Long;\x8b\xe4\x90\xcc\x8f#\xdf\x02\x00\x01J\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x01h\xf9\xbb\xcc\xff"
5) "sessionAttr:Mic"
6) "\xac\xed\x00\x05t\x00\x05value"
7) "creationTime"
8) "\xac\xed\x00\x05sr\x00\x0ejava.lang.Long;\x8b\xe4\x90\xcc\x8f#\xdf\x02\x00\x01J\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x01h\xf9\xb6\xd0\xf5"
```

### 过期时间

`get spring:session:sessions:expires:e8b7c9a1-8c4a-4f03-996f-619cfba91ea1`

```
127.0.0.1:6379> get spring:session:sessions:expires:e8b7c9a1-8c4a-4f03-996f-619cfba91ea1
```



## JWT
> https://jwt.io

* 验证签名规范

### header

```
{
  "alg": "HS256",
  "typ": "JWT"
}
```



### payload

```
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```

### 签名算法 verify signature

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),  
"your-256-bit-secret"
)
```

* your-256-bit-secret 类似秘钥

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
```



### 代码参考

> https://gitee.com/Joey_z/vip-project-space/blob/master/user-service/user-provider/src/main/java/com/gupaoedu/user/utils/JwtTokenUtils.java



```
public class JwtTokenUtils {


    public static void main(String[] args) {
        System.out.println(UUID.randomUUID().
                toString().replace("-",""));
    }
    
    //定义your-256-bit-secret
    private static Key generatorKey(){
        SignatureAlgorithm saa=SignatureAlgorithm.HS256;
        byte[] bin=DatatypeConverter.parseBase64Binary
                ("f3973b64918e4324ad85acea1b6cbec5");
        Key key=new SecretKeySpec(bin,saa.getJcaName());
        return key;
    }

    public static String generatorToken(Map<String,Object> payLoad){
        ObjectMapper objectMapper=new ObjectMapper();

        try {

			//定义payload
            return Jwts.builder().setPayload(objectMapper.writeValueAsString(payLoad))
            //Jwt  SignatureAlgorithm.HS256定义了header
            .signWith(SignatureAlgorithm.HS256,generatorKey()).compact();

        } catch (JsonProcessingException e) {

            e.printStackTrace();
        }
        return null;
    }


    public static Claims phaseToken(String token){
        Jws<Claims> claimsJwt=Jwts.parser().setSigningKey(generatorKey()).parseClaimsJws(token);

        return claimsJwt.getBody();
    }
}

```



## OAuth2