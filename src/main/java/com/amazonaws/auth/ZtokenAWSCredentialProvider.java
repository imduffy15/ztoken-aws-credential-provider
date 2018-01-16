package com.amazonaws.auth;

import com.amazonaws.services.securitytoken.model.Credentials;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.concurrent.Callable;

public class ZtokenAWSCredentialProvider implements AWSCredentialsProvider {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    static {
        objectMapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        objectMapper.setPropertyNamingStrategy(PropertyNamingStrategy.CAMEL_CASE_TO_LOWER_CASE_WITH_UNDERSCORES);
    }

    private String accountId;
    private String roleName;
    private HttpClient httpClient;
    private ZalandoTokenProvider credentialsProvider;
    private String credentialsServiceUrl;
    private final Callable<SessionCredentialsHolder> refreshCallable = this::retrieveCredentials;
    private volatile RefreshableTask<SessionCredentialsHolder> refreshableTask;

    public ZtokenAWSCredentialProvider(Builder builder) {
        this.accountId = builder.accountId;
        this.roleName = builder.roleName;
        this.httpClient = builder.httpClient != null ? builder.httpClient : HttpClientBuilder.create().build();
        this.credentialsProvider = builder.credentialsProvider != null ? builder.credentialsProvider : new ZtokenProvider();
        this.credentialsServiceUrl = builder.credentialsServiceUrl != null ? builder.credentialsServiceUrl : "https://aws-credentials.stups.zalan.do";
        this.refreshableTask = createRefreshableTask();
    }

    @Override
    public AWSCredentials getCredentials() {
        return refreshableTask.getValue().getSessionCredentials();
    }

    @Override
    public void refresh() {
        refreshableTask.forceGetValue();
    }

    private RefreshableTask<SessionCredentialsHolder> createRefreshableTask() {
        return new RefreshableTask.Builder<SessionCredentialsHolder>()
                .withRefreshCallable(refreshCallable)
                .withBlockingRefreshPredicate(new ShouldDoBlockingSessionRefresh())
                .withAsyncRefreshPredicate(new ShouldDoAsyncSessionRefresh()).build();
    }

    private SessionCredentialsHolder retrieveCredentials() throws IOException {
        String accessToken = credentialsProvider.getAccessToken();
        HttpGet request = new HttpGet(String.format("%s/aws-accounts/%s/roles/%s/credentials", credentialsServiceUrl, accountId, roleName));
        request.addHeader("Authorization", "Bearer " + accessToken);
        String response = EntityUtils.toString(httpClient.execute(request).getEntity());
        SessionCredentialsHolder sessionCredentialsHolder = new SessionCredentialsHolder(objectMapper.readValue(response, Credentials.class));
        return sessionCredentialsHolder;
    }

    public static final class Builder {
        private final String accountId;
        private final String roleName;
        private HttpClient httpClient;
        private ZalandoTokenProvider credentialsProvider;
        private String credentialsServiceUrl;

        public Builder(String accountId, String roleName) {
            if (accountId == null || roleName == null) {
                throw new NullPointerException(
                        "You must specify a value for accountId and roleName");
            }
            this.accountId = accountId;
            this.roleName = roleName;
        }

        public Builder withHttpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        public Builder withCredentialsProvider(ZtokenProvider ztokenProvider) {
            this.credentialsProvider = ztokenProvider;
            return this;
        }

        public Builder withCredentialsService(String url) {
            this.credentialsServiceUrl = url;
            return this;
        }

        public ZtokenAWSCredentialProvider build() {
            return new ZtokenAWSCredentialProvider(this);
        }
    }
}
