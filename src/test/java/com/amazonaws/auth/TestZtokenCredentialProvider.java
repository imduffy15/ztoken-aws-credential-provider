package com.amazonaws.auth;

import com.amazonaws.services.securitytoken.model.Credentials;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Calendar;

import static org.mockito.Mockito.*;

public class TestZtokenCredentialProvider {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    static {
        objectMapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        objectMapper.setPropertyNamingStrategy(PropertyNamingStrategy.CAMEL_CASE_TO_LOWER_CASE_WITH_UNDERSCORES);
    }


    @Test(expected = NullPointerException.class)
    public void shouldThrowExceptionIfRoleNameNotSupplied() {
        AWSCredentialsProvider provider = new ZtokenAWSCredentialProvider.Builder("1111111", null).build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldThrowExceptionIfAccountIdNotSupplied() {
        AWSCredentialsProvider provider = new ZtokenAWSCredentialProvider.Builder(null, "PowerUser").build();
    }

    @Test
    public void shouldSuccessfullyGetCredentials() throws IOException {
        HttpClient httpClient = mock(HttpClient.class);

        AWSCredentialsProvider provider = new ZtokenAWSCredentialProvider
                .Builder("1111111", "test")
                .withHttpClient(httpClient)
                .build();

        Calendar calendar = Calendar.getInstance();
        calendar.set(2000, 1, 2, 0, 0, 0);

        HttpResponse httpResponse = createMockedResponse(calendar, "test");
        when(httpClient.execute(any())).thenReturn(httpResponse, httpResponse);

        ValidateSessionId(provider, "test");
    }

    private void ValidateSessionId(AWSCredentialsProvider provider, String sessionId) {
        AWSCredentials producedCredentials = provider.getCredentials();
        Assert.assertTrue(producedCredentials instanceof BasicSessionCredentials);
        BasicSessionCredentials sessionCredentials = (BasicSessionCredentials) producedCredentials;
        Assert.assertEquals("keyid", sessionCredentials.getAWSAccessKeyId());
        Assert.assertEquals("key", sessionCredentials.getAWSSecretKey());
        Assert.assertEquals(sessionId, sessionCredentials.getSessionToken());
    }

    private HttpResponse createMockedResponse(Calendar calendar, String sessionId) throws IOException {
        HttpResponse httpResponse = mock(HttpResponse.class);
        HttpEntity httpEntity = mock(HttpEntity.class);
        InputStream response = new ByteArrayInputStream(objectMapper.writer().writeValueAsString(
                new Credentials("keyid", "key", sessionId, calendar.getTime())
        ).getBytes());
        when(httpEntity.getContent()).thenReturn(response);
        when(httpResponse.getEntity()).thenReturn(httpEntity);
        return httpResponse;
    }
}
