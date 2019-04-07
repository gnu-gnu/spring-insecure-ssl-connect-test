package com.gnu.ssl.server.test;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPermission;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.client.ResourceAccessException;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.ssl.util.SimpleTrustManagerFactory;
import io.netty.util.internal.ReflectionUtil;
import reactor.netty.http.client.HttpClient;

/**
 * 
 * Self-signed 인증서가 설치된 환경에서 client auth (two-way 인증) 을 RestTemplate과 WebClient로 테스트 한다
 * javax.net.ssl 의 설정은  classpath를 지정할 수 없으므로 package 의 client_auth_files에 있는 파일들을
 * 적절한 위치에 옮긴 후 아래의 CLIENT_KEY_STORE, CLIENT_TRUST_STORE 의 경로 및
 * 이 테스트가 사용하는 프로파일의 properties인 application-twoway.properties를 수정해준다. 
 * 
 * @author gnu-gnu(geunwoo.j.shim@gmail.com)
 *
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles(profiles="twoway")
public class SpringBootSslServerTestApplicationSslAuthTest {

	private static final String CLIENT_TRUST_STORE = "C:/key/client.truststore";
	private static final String CLIENT_KEY_STORE = "C:/key/client.jks";
	@LocalServerPort
	private int rdmServerPort;
	private String uri = "";
	
	private static final String KEY_STORE_PASS = "client";
	private static final String TRUST_STORE_PASS = "client";
	private static HostnameVerifier defaultHostnameVerifier;
	
	/**
	 * two-way 인증을 위한 Client측 인증 정보를 설정한다.
	 */
	@BeforeClass
	public static void initBeforeClass() {
		System.setProperty("javax.net.debug", "all");
		System.setProperty("javax.net.ssl.keyStore", CLIENT_KEY_STORE);
		System.setProperty("javax.net.ssl.keyStorePassword", KEY_STORE_PASS);
		System.setProperty("javax.net.ssl.trustStore", CLIENT_TRUST_STORE);
		System.setProperty("javax.net.ssl.trustStorePassword", TRUST_STORE_PASS);
		
		SecurityManager sm = System.getSecurityManager();
	        if (sm != null) {
	            sm.checkPermission(new SSLPermission("setHostnameVerifier"));
	        }
	        defaultHostnameVerifier = new HostnameVerifier() {
	    		@Override
	    		public boolean verify(String hostname, SSLSession session) {
	    			// TODO Auto-generated method stub
	    			return true;
	    		}
	    	};;
	}
	
	@Before
	public void initVariables() {
		uri = "https://127.0.0.1:" + rdmServerPort + "/endpoint";
	}
	
	/**
	 * oneway에서는 성공했던 테스트이다.
	 * 서버측에서 client auth를 수행하므로 oneway와는 다르게 이 테스트는 응답에 실패한다.
	 */
	@Test(expected = ResourceAccessException.class)
	public void oneWayInsecureRestTemplateFail() {
		TestRestTemplate template = new TestRestTemplate();
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
		assertThat(template.getForEntity(uri, String.class).getStatusCode()).isEqualTo(HttpStatus.OK);
	}
	/**
	 * two-way 인증을 통해 성공하는 RestTemplate이다.
	 * 인증서의 CN이 localhost로 발급되어 있어 이 테스트는 hostname verify가 없어도 성공한다.
	 * 만약 CN이 적절하지 않다면, one-way 때와 같이 hostname verifier는 구현해주어야 한다. 
	 */
	@Test
	public void twoWayInsecureRestTemplateSuccess() {
		TestRestTemplate template = new TestRestTemplate();
		assertThat(template.getForEntity(uri, String.class).getStatusCode()).isEqualTo(HttpStatus.OK);
	}
	
	/**
	 * oneway에서는 성공했지만 twoway에서는 실패하는 WebClient 테스트이다.
	 * 
	 * @throws SSLException
	 */
	@Test(expected = Exception.class)
	public void oneWayInsecureWebClientFail() throws SSLException {
		SslContext ssl = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build();
		HttpClient httpClient = HttpClient.create().secure(builder -> builder.sslContext(ssl));
		ClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);
		WebTestClient.bindToServer(connector).build().get().uri(uri).exchange().expectBody(String.class).consumeWith(response -> {
			assertThat(response.getStatus()).isEqualTo(HttpStatus.OK);
		});
	}
	
	/**
	 * two-way, WebClient가 성공하는 테스트이다
	 * WebClient는 System.property가 존재함에도 불구하고 별도로 Client Auth를 위한 설정을 먹여줘야 동작을 하는데 이유는 아직 잘 모르겠다... 
	 * 
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws UnrecoverableKeyException 
	 * @throws ClassNotFoundException 
	 * @throws SecurityException 
	 * @throws NoSuchFieldException 
	 * @throws IllegalAccessException 
	 * @throws IllegalArgumentException 
	 * @throws NoSuchMethodException 
	 */
	@Test
	public void twoWayInsecureWebClientSuccess() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, NoSuchFieldException, SecurityException, ClassNotFoundException, IllegalArgumentException, IllegalAccessException, NoSuchMethodException {
		KeyStore keystore = KeyStore.getInstance("jks");
		keystore.load(new FileInputStream(new File(CLIENT_KEY_STORE)), KEY_STORE_PASS.toCharArray());
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keystore, KEY_STORE_PASS.toCharArray());
		KeyStore truststore = KeyStore.getInstance(KeyStore.getDefaultType());
		truststore.load(new FileInputStream(new File(CLIENT_TRUST_STORE)), TRUST_STORE_PASS.toCharArray());
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(truststore);
		SslContext ssl = SslContextBuilder.forClient().clientAuth(ClientAuth.REQUIRE).keyManager(kmf).trustManager(tmf).build();
		HttpClient httpClient = HttpClient.create().secure(builder -> builder.sslContext(ssl));
		ClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);
		WebTestClient.bindToServer(connector).build().get().uri(uri).exchange().expectBody(String.class).consumeWith(response -> {
			assertThat(response.getStatus()).isEqualTo(HttpStatus.OK);
		});
	}

}
