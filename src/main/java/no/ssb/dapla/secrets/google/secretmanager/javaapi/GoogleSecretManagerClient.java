package no.ssb.dapla.secrets.google.secretmanager.javaapi;

import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.auth.oauth2.ComputeEngineCredentials;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretManagerServiceSettings;
import com.google.cloud.secretmanager.v1.SecretVersionName;
import no.ssb.dapla.secrets.api.SecretManagerClient;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.atomic.AtomicBoolean;

public class GoogleSecretManagerClient implements SecretManagerClient {

    private final String projectId;
    private final SecretManagerServiceClient client;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    // uses compute-engine
    public GoogleSecretManagerClient(String projectId) {
        this.projectId = projectId;
        GoogleCredentials credentials = ComputeEngineCredentials.create();
        GoogleCredentials scopedCredentials = credentials.createScoped("https://www.googleapis.com/auth/cloud-platform");
        SecretManagerServiceSettings settings = getServiceSettings(scopedCredentials);
        this.client = newClient(settings);
    }

    // uses service-account
    public GoogleSecretManagerClient(String projectId, String serviceAccountKeyPath) {
        this.projectId = projectId;
        GoogleCredentials credentials = getServiceAccountCredentials(serviceAccountKeyPath);
        GoogleCredentials scopedCredentials = credentials.createScoped("https://www.googleapis.com/auth/cloud-platform");
        SecretManagerServiceSettings settings = getServiceSettings(scopedCredentials);
        this.client = newClient(settings);
    }

    SecretManagerServiceClient newClient(SecretManagerServiceSettings settings) {
        try {
            return SecretManagerServiceClient.create(settings);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    SecretManagerServiceSettings getServiceSettings(GoogleCredentials scopedCredentials) {
        try {
            return SecretManagerServiceSettings.newBuilder().setCredentialsProvider(FixedCredentialsProvider.create(scopedCredentials)).build();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    GoogleCredentials getServiceAccountCredentials(String serviceAccountKeyPath) {
        try {
            return ServiceAccountCredentials.fromStream(Files.newInputStream(Paths.get(serviceAccountKeyPath), StandardOpenOption.READ));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    AccessSecretVersionResponse getSecret(String secretName, String secretVersion) {
        SecretVersionName secretVersionName = SecretVersionName.of(projectId, secretName, secretVersion);
        return client.accessSecretVersion(secretVersionName);
    }

    @Override
    public String readString(String secretName) {
        return readString(secretName, "latest");
    }

    @Override
    public String readString(String secretName, String secretVersion) {
        if (closed.get()) {
            throw new RuntimeException("Client is closed!");
        }
        AccessSecretVersionResponse response = getSecret(secretName, secretVersion);
        return response.getPayload().getData().toStringUtf8();
    }

    @Override
    public byte[] readBytes(String secretName) {
        return readBytes(secretName, "latest");
    }

    @Override
    public byte[] readBytes(String secretName, String secretVersion) {
        if (closed.get()) {
            throw new RuntimeException("Client is closed!");
        }
        AccessSecretVersionResponse response = getSecret(secretName, secretVersion);
        return response.getPayload().getData().toByteArray();
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            client.close();
        }
    }
}
