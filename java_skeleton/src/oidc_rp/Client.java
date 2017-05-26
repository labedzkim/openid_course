package oidc_rp;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationErrorResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.rp.*;
import com.nimbusds.openid.connect.sdk.util.DefaultJWTDecoder;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONStyle;
import spark.Request;
import spark.Response;
import spark.Session;

import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

public class Client {
	// specify the correct path
	public static Path ROOT_PATH = Paths.get(".");
	// specify the correct URL
	public static String ISSUER = "https://op1.test.inacademia.org";

	OIDCProviderMetadata providerMetadata;
	OIDCClientInformation clientInformation;

	State lastState;

//	private FlowConfig flowConfig = FlowConfig.implicitFlow();
	private FlowConfig flowConfig = FlowConfig.codeFlow();

	public Client(String clientMetadataString)
			throws ParseException, URISyntaxException, IOException,
			SerializeException {

		OIDCClientMetadata clientMetadata = OIDCClientMetadata
				.parse(JSONObjectUtils.parse(clientMetadataString));

        // get the provider configuration information
		providerMetadata = downloadProviderMetadata();

		// register with the provider using the clientMetadata
		clientInformation = registerClient(clientMetadata, providerMetadata);
	}

	private OIDCClientInformation registerClient(OIDCClientMetadata clientMetadata, OIDCProviderMetadata providerMetadata) throws ParseException, IOException, SerializeException {

// Make registration request
		OIDCClientRegistrationRequest registrationRequest = new OIDCClientRegistrationRequest(providerMetadata.getRegistrationEndpointURI(), clientMetadata, null);
		HTTPResponse regHTTPResponse = registrationRequest.toHTTPRequest().send();

// Parse and check response
		ClientRegistrationResponse registrationResponse = OIDCClientRegistrationResponseParser.parse(regHTTPResponse);

		if (registrationResponse instanceof ClientRegistrationErrorResponse) {
			ErrorObject error = ((ClientRegistrationErrorResponse) registrationResponse)
					.getErrorObject();
			// error handling
		}

// Store client information from OP
		System.out.println(String.format("CLIENT INFORMATION RESPONSE:\n%s", regHTTPResponse.getContentAsJSONObject().toJSONString()));
		return ((OIDCClientInformationResponse)registrationResponse).getOIDCClientInformation();

	}

	private OIDCProviderMetadata downloadProviderMetadata() throws URISyntaxException, IOException, ParseException {
		URI issuerURI = new URI(ISSUER);
		URL providerConfigurationURL = issuerURI.resolve("/.well-known/openid-configuration").toURL();
		InputStream stream = providerConfigurationURL.openStream();
// Read all data from URL
		String providerInfo = null;
		try (java.util.Scanner s = new java.util.Scanner(stream)) {
			providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
		}
		System.out.println(String.format("PROVIDER INFO:\n%s", providerInfo));
		return OIDCProviderMetadata.parse(providerInfo);
	}

	public String authenticate(Request req, Response res)
			throws URISyntaxException, SerializeException {
		// session object that can be used to store state between requests
		Session session = req.session();

		// make authentication request
		// Generate random state string for pairing the response to the request
		State state = new State();
		lastState = state;
// Generate nonce
		Nonce nonce = new Nonce();
// Specify scope
		Scope scope = Scope.parse(flowConfig.getScope());

// Compose the request
		AuthenticationRequest authenticationRequest = new AuthenticationRequest(
				providerMetadata.getAuthorizationEndpointURI(),
				new ResponseType(flowConfig.getResponseType()),
				scope, clientInformation.getID(), flowConfig.getRedirectURI(), state, nonce);

		URI authReqURI = authenticationRequest.toURI();

		String login_url = authReqURI.toString(); // insert the redirect URL

		res.redirect(login_url);
		return null;
	}

	public String codeFlowCallback(Request req, Response res)
			throws IOException, ParseException, java.text.ParseException {
		// Callback redirect URI
		String url = req.url() + "?" + req.raw().getQueryString();

		// parse authentication response from url
		AuthorizationCode authCode = parseAuthenticationResponse(url).getAuthorizationCode();

		// make token request
		OIDCAccessTokenResponse accessTokenResponse = makeTokeRequest(authCode);

		// validate the ID Token according to the OpenID Connect spec (sec
		// 3.1.3.7.)
		verifyIdToken(accessTokenResponse.getIDToken(), providerMetadata);

		// make userinfo request
		AccessToken accessToken = accessTokenResponse.getAccessToken();
		UserInfoSuccessResponse userInfoResponse = makeUserInfoRequest(accessToken);

		// set the appropriate values
		String parsedIdToken = accessTokenResponse.getIDToken().getParsedString();
		ReadOnlyJWTClaimsSet idTokenClaims = accessTokenResponse.getIDToken().getJWTClaimsSet();

		return WebServer.successPage(authCode, accessToken, parsedIdToken,
				idTokenClaims, userInfoResponse);
	}

	private UserInfoSuccessResponse makeUserInfoRequest(Object accessToken) {

		UserInfoRequest userInfoReq = new UserInfoRequest(
				providerMetadata.getUserInfoEndpointURI(),
				(BearerAccessToken) accessToken);

		HTTPResponse userInfoHTTPResp = null;
		try {
			userInfoHTTPResp = userInfoReq.toHTTPRequest().send();
		} catch (SerializeException | IOException e) {
			// proper error handling
		}

		UserInfoResponse userInfoResponse = null;
		try {
			userInfoResponse = UserInfoResponse.parse(userInfoHTTPResp);
		} catch (ParseException e) {
			// proper error handling
		}

		if (userInfoResponse instanceof UserInfoErrorResponse) {
			ErrorObject error = ((UserInfoErrorResponse) userInfoResponse).getErrorObject();
			// error handling
		}

		UserInfoSuccessResponse successResponse = (UserInfoSuccessResponse) userInfoResponse;
		JSONObject claims = successResponse.getUserInfo().toJSONObject();

		System.out.println(String.format("USER INFO CLAIMS:\n%s", claims.toJSONString(JSONStyle.NO_COMPRESS)));

		return successResponse;
	}

	private OIDCAccessTokenResponse makeTokeRequest(AuthorizationCode authCode) {
		TokenRequest tokenReq = new TokenRequest(
				providerMetadata.getTokenEndpointURI(),
				new ClientSecretBasic(clientInformation.getID(),
						clientInformation.getSecret()),
				new AuthorizationCodeGrant(authCode, flowConfig.getRedirectURI()));

		HTTPResponse tokenHTTPResp = null;
		try {
			tokenHTTPResp = tokenReq.toHTTPRequest().send();
		} catch (SerializeException | IOException e) {
			// proper error handling
		}

// Parse and check response
		TokenResponse tokenResponse = null;
		try {
			tokenResponse = OIDCTokenResponseParser.parse(tokenHTTPResp);
		} catch (ParseException e) {
			// proper error handling
		}

		if (tokenResponse instanceof TokenErrorResponse) {
			ErrorObject error = ((TokenErrorResponse) tokenResponse).getErrorObject();
			// error handling
		}

		return (OIDCAccessTokenResponse) tokenResponse;
	}

	private AuthenticationSuccessResponse parseAuthenticationResponse(String url) {
		AuthenticationResponse authResp = null;
		try {
			authResp = AuthenticationResponseParser.parse(new URI(url));
		} catch (ParseException | URISyntaxException e) {
			throw new RuntimeException("Parsing error: " + e.getMessage());
		}

		if (authResp instanceof AuthenticationErrorResponse) {
			ErrorObject error = ((AuthenticationErrorResponse) authResp)
					.getErrorObject();
			throw new RuntimeException("Authentication error: " + error.toString());
		}

		AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResp;

/* Don't forget to check the state!
 * The state in the received authentication response must match the state
 * specified in the previous outgoing authentication request.
*/
		// validate the 'state' parameter
		if (!verifyState(successResponse.getState())) {
			// proper error handling
			throw new RuntimeException("State invalid: " + successResponse.getState());
		}

		return successResponse;
	}

	private boolean verifyState(State state) {

		if (state != null && lastState.equals(state)) {
			return true;
		}

		return false;
	}

	public String implicitFlowCallback(Request req, Response res)
			throws IOException, java.text.ParseException {
		// Callback redirect URI
		String url = req.url() + "#" + req.queryParams("url_fragment");

		// parse authentication response from url
		AuthenticationSuccessResponse authenticationSuccessResponse = parseAuthenticationResponse(url);

		JWT idToken = authenticationSuccessResponse.getIDToken();


		// TODO validate the ID Token according to the OpenID Connect spec (sec
		// 3.2.2.11.)

		// set the appropriate values
		AccessToken accessToken = authenticationSuccessResponse.getAccessToken();
		String parsedIdToken = idToken.getParsedString();
		ReadOnlyJWTClaimsSet idTokenClaims = idToken.getJWTClaimsSet();

		UserInfoSuccessResponse userinfo = makeUserInfoRequest(accessToken);

		return WebServer.successPage(null, accessToken, parsedIdToken,
				idTokenClaims, userinfo);
	}


	private ReadOnlyJWTClaimsSet verifyIdToken(JWT idToken, OIDCProviderMetadata providerMetadata) throws ParseException {
		RSAPublicKey providerKey = null;
		try {
			JSONObject key = getProviderRSAJWK(providerMetadata.getJWKSetURI().toURL().openStream());
			providerKey = RSAKey.parse(key).toRSAPublicKey();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException
				| IOException | java.text.ParseException e) {
			// error handling
		}

		DefaultJWTDecoder jwtDecoder = new DefaultJWTDecoder();
		jwtDecoder.addJWSVerifier(new RSASSAVerifier(providerKey));
		ReadOnlyJWTClaimsSet claims = null;
		try {
			claims = jwtDecoder.decodeJWT(idToken);
		} catch (JOSEException | java.text.ParseException e) {
			// error handling
		}

		return claims;
	}

	private JSONObject getProviderRSAJWK(InputStream is) throws ParseException {
		// Read all data from stream
		StringBuilder sb = new StringBuilder();
		try (Scanner scanner = new Scanner(is);) {
			while (scanner.hasNext()) {
				sb.append(scanner.next());
			}
		}

		// Parse the data as json
		String jsonString = sb.toString();
		JSONObject json = JSONObjectUtils.parse(jsonString);

		// Find the RSA signing key
		JSONArray keyList = (JSONArray) json.get("keys");
		for (Object key : keyList) {
			JSONObject k = (JSONObject) key;
			if (k.get("use").equals("sig") && k.get("kty").equals("RSA")) {
				return k;
			}
		}
		return null;
	}
}
