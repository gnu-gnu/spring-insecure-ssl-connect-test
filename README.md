# spring-insecure-ssl-connect-test

proxy 환경을 통해 외부로 요청을 하거나 self-signed 인증서를 통해 운영되는 서버에 요청을 날릴 경우

일반적으로 SSLException 류의 예외가 나타난다.

Spring4 까지 주로 사용되던 RestTemplate과 Spring5 에서 사용하는 WebClient의 처리가 약간 다르기 때문에 예시로 작성한 소스이다.

/src/main/resources에 self-signed 인증서 샘플이 포함되어 있다. (ssl.jks)

test 폴더의 SpringBootSslServerTestApplicationTests를 통해 기능 확인이 가능하다. (RestTemplate 실패, 성공 / WebClient 실패, 성공)
