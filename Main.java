package com.example;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.nio.charset.StandardCharsets;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// Replace all variables having a value of XXX with the actual ones.
public class Main {
    private static final String AWS_ACCESS_KEY = "XXX";
    private static final String AWS_SECRET_KEY = "XXX";
    
    // The region and service you're working with
    private static final String REGION = "XXX"; // us-east-1
    private static final String SERVICE = "aps";

    // COMPATIBLE APIs
    public static void main(String[] args) {
        /*
            The encodedQueryExample is: ALERTS%7Balertname%3D%22alert_name_2%22%7D, resulting in query=ALERTS%7Balertname%3D%22alert_name_2%22%7D.
            For a correct request, the format would be: api/v2/alerts?filter=alertname%3Dmetric%3Aalerting_rule. The key pattern to follow is filter=encoded(expression).

            The canonicalQueryString variable is crucial—it must match the part after ? in the URL (and follow the same pattern).
            In an alerting rule definition, for example: the [ - alert: metric:alerting_rule ] is the alertname, 
            and the expression vector(1) with a for: 1m clause can be used for testing purposes.
            
            sample result:
            for api/v2/alerts?filter=alertname%3Dmetric%3Aalerting_rule, we have:
            200 [{"annotations":{},"endsAt":"2024-10-21T00:27:19.284Z","fingerprint":"114212a24ca97549","receivers":[{"name":"default"}],"startsAt":"2024-10-21T00:11:19.284Z","status":{"inhibitedBy":[],"silencedBy":[],"state":"active"},"updatedAt":"2024-10-21T00:23:19.286Z","labels":{"alertname":"metric:alerting_rule"}}]
            for a non-existed alerting rule, e.g. api/v2/alerts?filter=alertname%3Dmetric%3Aalerting_rule_not_existed, we now have an empty result:
            200 []
        */
        String workspaceId = "XXX";
        String encodedQuery = "";
        String alertName = "XXX";
        try {
            encodedQuery = URLEncoder.encode("alertname=" + alertName, StandardCharsets.UTF_8.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
        String endpoint = "https://aps-workspaces." + REGION + ".amazonaws.com/workspaces/" + workspaceId + "/alertmanager/api/v2/alerts?filter=" + encodedQuery;
        // Create the URI object
        URI uri = URI.create(endpoint);

        // Create the signer with your credentials
        AWSSigner signer = new AWSSigner(AWS_ACCESS_KEY, AWS_SECRET_KEY, REGION, SERVICE, "filter=" + encodedQuery);
        // Create the GET request to the AMP endpoint
        HttpRequest request = HttpRequest.newBuilder()
            .uri(uri)
            .header("Content-Type", "application/json")
            .GET()
            .build();

        // Sign the request
        // Send the request using HttpClient
        HttpClient client = HttpClient.newHttpClient();
        try {
            // Sign the request using sigv4.
            HttpRequest signedRequest = signer.sign(request, uri.getHost(), "");
            HttpResponse<String> response = client.send(signedRequest, HttpResponse.BodyHandlers.ofString());

            // Print the response
            System.out.println(response.statusCode());
            System.out.println(response.body());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class AWSSigner {
    private static final String ALGORITHM = "AWS4-HMAC-SHA256";
    private static final String TERMINATION_STRING = "aws4_request";
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DATE_ONLY_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);

    private String accessKeyId;
    private String secretKey;
    private String region;
    private String service;
    private String queryString;

    public AWSSigner(String accessKeyId, String secretKey, String region, String service, String queryString) {
        this.accessKeyId = accessKeyId;
        this.secretKey = secretKey;
        this.region = region;
        this.service = service;
        this.queryString = queryString;
    }

    public HttpRequest sign(HttpRequest request, String host, String payload) throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);  // Truncate to seconds for consistency

        // Task 1: Prepare canonical request
        String method = request.method();
        URI uri = request.uri();
        String canonicalURI = uri.getPath();
        String canonicalQueryString = queryString;
        String canonicalHeaders = "host:" + host + "\n";
        String signedHeaders = "host";
        String hashedPayload = hash(payload);

        String canonicalRequest = method + '\n' +
                canonicalURI + '\n' +
                canonicalQueryString + '\n' +
                canonicalHeaders + '\n' +
                signedHeaders + '\n' +
                hashedPayload + "";
        // Task 2: Create string to sign
        String dateTimeStamp = DATE_FORMATTER.format(now); // Full ISO 8601 format
        String dateStamp = DATE_ONLY_FORMATTER.format(now); // Date-only format (YYYYMMDD)
        String credentialScope = dateStamp + "/" + region + "/" + service + "/" + TERMINATION_STRING;
        String stringToSign = ALGORITHM + '\n' +
                dateTimeStamp + '\n' +
                credentialScope + '\n' +
                hash(canonicalRequest);
        // Task 3: Calculate the signature
        byte[] signingKey = getSignatureKey(secretKey, dateStamp, region, service);
        byte[] signature = hmacSHA256(stringToSign, signingKey);

        // Task 4: Add signing information to request headers
        String authorizationHeader = ALGORITHM + ' ' +
                "Credential=" + accessKeyId + "/" + credentialScope + ", " +
                "SignedHeaders=" + signedHeaders + ", " +
                "Signature=" + bytesToHex(signature);

        return HttpRequest.newBuilder(request.uri())
                .method(request.method(), request.bodyPublisher().orElse(HttpRequest.BodyPublishers.noBody()))
                .header("Authorization", authorizationHeader)
                .header("x-amz-date", dateTimeStamp)
                .build();
    }

    // Hash the payload with SHA-256
    private static String hash(String text) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedHash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(encodedHash);
    }

    private static byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
        byte[] kDate = hmacSHA256(dateStamp, ("AWS4" + key).getBytes(StandardCharsets.UTF_8));
        byte[] kRegion = hmacSHA256(regionName, kDate);
        byte[] kService = hmacSHA256(serviceName, kRegion);
        byte[] kSigning = hmacSHA256(TERMINATION_STRING, kService);
        return kSigning;
    }

    private static byte[] hmacSHA256(String data, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
