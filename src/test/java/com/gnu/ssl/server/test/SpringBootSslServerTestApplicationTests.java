package com.gnu.ssl.server.test;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.client.ResourceAccessException;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import reactor.netty.http.client.HttpClient;

/**
 * 
 * Self-signed 인증서가 설치된 환경에서 Spring4 까지 주로 사용하던 RestTemplate과 WebClient를 사용하는 방법을 테스트한다.
 * one-way test 이므로 client 측에서는 insecure ssl을 무시하고 진행할 수 있다.
 * 이 테스트는 classpath 에 존재하는 test.jks를 이용하여 테스트를 진행한다.
 * 
 * @author gnu-gnu(geunwoo.j.shim@gmail.com)
 *
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles(profiles="oneway")
public class SpringBootSslServerTestApplicationTests {

	@LocalServerPort
	private int rdmServerPort;
	@Autowired
	TestRestTemplate template;
	@Autowired
	WebTestClient webClient;
	private String uri = "";
	
	@Before
	public void initVariables() {
		uri = "https://127.0.0.1:" + rdmServerPort + "/endpoint";
	}
	
	/**
	 * self-signed 인증서 환경에서 RestTemplate으로 호출했을 경우 오류가 나는 경우
	 */
	@Test(expected = ResourceAccessException.class)
	public void insecureRestTemplateFail() {
		// RestTemplate template = new RestTemplate();
		template.getRestTemplate().getForEntity(uri, String.class).getBody();
	}
	/**
	 * RestTemplate 은 RequestFactory에서 SSLContext 와 HostnameVerifier를 구현하여 신뢰하지 않는 인증서도 통과시킨다.
	 */
	@Test
	public void insecureRestTemplateSuccess() {
		template.getRestTemplate().setRequestFactory(new SimpleClientHttpRequestFactory() {

			@Override
			protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
				if (connection instanceof HttpsURLConnection) {
					((HttpsURLConnection) connection).setHostnameVerifier((hostname, session) -> true);
					SSLContext sc;
					try {
						sc = SSLContext.getInstance("SSL");
						sc.init(null, new TrustManager[] { new X509TrustManager() {

							@Override
							public X509Certificate[] getAcceptedIssuers() {
								return null;
							}

							@Override
							public void checkServerTrusted(X509Certificate[] chain, String authType)
									throws CertificateException {

							}

							@Override
							public void checkClientTrusted(X509Certificate[] chain, String authType)
									throws CertificateException {

							}
						} }, new SecureRandom());
						((HttpsURLConnection) connection).setSSLSocketFactory(sc.getSocketFactory());
					} catch (NoSuchAlgorithmException e) {
						e.printStackTrace();
					} catch (KeyManagementException e) {
						e.printStackTrace();
					}
				}
				super.prepareConnection(connection, httpMethod);
			}

		});
		assertThat(template.getForEntity(uri, String.class).getBody()).isEqualTo("true");
	}
	/**
	 * insecure SSL 에 WebClient를 그냥 호출할 경우 Exception 발생
	 */
	@Test(expected = Exception.class)
	public void webClientFail() {
		webClient.get().uri(uri).exchange().expectBody(String.class).consumeWith(response -> {
			assertThat(response.getResponseBody()).isEqualTo("true");
		});
	}
	/**
	 * 
	 * WebClient 는 {@link javax.net.ssl.SSLContext}이 아니라 {@link io.netty.handler.ssl.SslContext}를 사용함
	 * 이 때 TrustManager에 {@link InsecureTrustManagerFactory}를 이용하며 모든 인증서를 신뢰할 수 있도록 처리하며
	 * 이것을 통해 생성한 {@link ClientHttpConnector}를 가지고 통신을 함
	 * 
	 * @throws SSLException
	 */
	@Test
	public void webClientSuccess() throws SSLException {
		SslContext ssl = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build();
		HttpClient httpClient = HttpClient.create().secure(builder -> builder.sslContext(ssl));
		ClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);
		WebTestClient.bindToServer(connector).build().get().uri(uri).exchange().expectBody(String.class).consumeWith(response -> {
			assertThat(response.getResponseBody()).isEqualTo("true");
		});
	}

}
