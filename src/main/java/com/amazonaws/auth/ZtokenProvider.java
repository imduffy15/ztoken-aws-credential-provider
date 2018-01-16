package com.amazonaws.auth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;


public class ZtokenProvider implements ZalandoTokenProvider {
    private static final Log LOG = LogFactory.getLog(InstanceProfileCredentialsProvider.class);
    private static final long CACHE_DURATION = 5 * 60 * 1000L;
    private final AtomicReference<Entry> token = new AtomicReference<>();

    private static String readAll(InputStream inputStream) throws IOException {
        try (final Reader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8)) {
            final StringBuilder sb = new StringBuilder();
            final char[] buf = new char[1024];
            int len;
            while ((len = reader.read(buf)) != -1) {
                sb.append(buf, 0, len);
            }
            return sb.toString();
        }
    }

    private static String zign() throws IOException {
        LOG.info("Refreshing token from zign...");
        final Process zign = new ProcessBuilder("ztoken", "token").start();
        try (final InputStream inputStream = zign.getInputStream()) {
            final String output = readAll(inputStream).trim();
            zign.waitFor(5, TimeUnit.SECONDS);
            if (zign.exitValue() != 0) {
                throw new IOException(String.format("zign failed with the exit code: %d", zign.exitValue()));
            }
            LOG.debug("Refreshed token from zign");
            return output;
        } catch (InterruptedException e) {
            throw new IOException("zign process took longer than 5 seconds to exit");
        }
    }

    private static Entry update(Entry entry) {
        final long now = System.currentTimeMillis();
        try {
            return entry == null || entry.timestamp < now - CACHE_DURATION ? new Entry(now, zign()) : entry;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public String getAccessToken() throws IOException {
        try {
            return token.updateAndGet(ZtokenProvider::update).value;
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

    static class Entry {
        final long timestamp;
        final String value;

        Entry(long timestamp, String value) {
            this.timestamp = timestamp;
            this.value = value;
        }
    }
}