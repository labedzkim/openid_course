package oidc_rp;

import com.nimbusds.oauth2.sdk.ResponseType;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Created by Maciej Łabędzki (labedzki@man.poznan.pl))
 * Date: 25.05.2017
 */
public class FlowConfig {

    private Collection<String> scope = new ArrayList<>();
    private URI redirectURI;
    private String[] responseType;

    public Collection<String> getScope() {
        return scope;
    }

    static FlowConfig implicitFlow() throws URISyntaxException {

        FlowConfig flowConfig = new FlowConfig();
        flowConfig.scope.add("openid");
        flowConfig.redirectURI = new URI("http://localhost:8090/implicit_flow_callback");
        flowConfig.responseType = new String[]{"id_token", "token"};
        return flowConfig;
    }

    static FlowConfig codeFlow() throws URISyntaxException {

        FlowConfig flowConfig = new FlowConfig();
        flowConfig.scope.add("openid");
        flowConfig.scope.add("profile");
        flowConfig.scope.add("email");
        flowConfig.scope.add("phone");
        flowConfig.redirectURI = new URI("http://localhost:8090/code_flow_callback");
        flowConfig.responseType = new String[]{"code"};
        return flowConfig;
    }

    public URI getRedirectURI() {
        return redirectURI;
    }

    public String[] getResponseType() {
        return responseType;
    }

}
