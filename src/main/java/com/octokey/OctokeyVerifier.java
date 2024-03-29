package com.octokey;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.BufferUnderflowException;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.util.encoders.Base64;


public class OctokeyVerifier {
    private final AuthRequest auth_request;
    private final Set<PublicKey> public_keys;
    private final Set<String> hostnames;
    private final boolean valid;
    private final String error;

    private static final int MAX_BUFFER_SIZE = 1024 * 1024;

    /** Checks whether an auth request has a valid signature by one of a given
     * user's set of authorized public keys.
     *
     * @param auth_request_base64 The base64 auth request string sent by the client.
     * @param username The username of the user requesting access. Checked against
     *    the signed username in the auth request to make sure we're signing in the
     *    right user.
     * @param user_public_keys The authorized public keys for the user requesting
     *    access, in the same format as ~/.ssh/authorized_keys (plain text; keys
     *    separated by newlines; each line consisting of key type, base64 key and
     *    description text).
     * @param hostnames List of HTTP hostnames on which the login form may be
     *    submitted. If the signature is not for a URL on one of those hosts,
     *    verification fails (so that an attacker can't use an auth request from
     *    one site to log into another site).
     */
    public OctokeyVerifier(String auth_request_base64, String username, String user_public_keys,
                           String[] hostnames, ChallengeVerifier challenge_verifier) {
        this.auth_request = new AuthRequest(auth_request_base64);
        this.public_keys = parsePublicKeys(user_public_keys);
        this.hostnames = new HashSet<String>();
        for (String hostname : hostnames) this.hostnames.add(hostname);

        if (auth_request.signer == null) {
            this.valid = false;
            this.error = auth_request.error;
        } else if (!auth_request.username.equals(username)) { // check is not timing sensitive
            this.valid = false;
            this.error = "requested username does not match signed username";
        } else if (!public_keys.contains(auth_request.signer)) {
            this.valid = false;
            this.error = "signature is not for one of the user's public keys";
        } else if (!this.hostnames.contains(auth_request.request_url.getHost())) {
            this.valid = false;
            this.error = "auth request is for a non-whitelisted URL: " + auth_request.request_url;
        } else if (!challenge_verifier.verify(auth_request.challenge)) {
            this.valid = false;
            this.error = "auth request's challenge is not acceptable";
        } else {
            this.valid = true;
            this.error = null;
        }
    }

    public boolean isValid() {
        return valid;
    }

    public String getError() {
        return error;
    }

    private Set<PublicKey> parsePublicKeys(String public_keys) {
        HashSet<PublicKey> result = new HashSet<PublicKey>();
        for (String line : public_keys.split("[\r\n]")) {
            String[] fields = line.replaceFirst("#.*", "").trim().split("[\t ]+", 3);
            if (fields.length >= 1) {
                String key_type = fields[0];
                String key_base64 = (fields.length > 1) ? fields[1] : "";
                String description = (fields.length > 2) ? fields[2] : "";
                result.add(new PublicKey(key_type, key_base64, description));
            }
        }
        return result;
    }

    /** Reads a RFC4251 "string" type from a given buffer, and returns it as an array
     * of bytes. */
    private static byte[] readBytes(ByteBuffer buffer, String context) throws ParsingException {
        int length = buffer.getInt(); // network byte order (big endian) is default for ByteBuffer
        if (length < 0 || length > MAX_BUFFER_SIZE) {
            throw new ParsingException(context, "illegal buffer size: " + length);
        }
        byte[] result = new byte[length];
        buffer.get(result);
        return result;
    }

    /** Reads a RFC4251 "string" type from a given buffer, interprets it as UTF-8 and
     * returns it as a Java string. */
    private static String readString(ByteBuffer buffer, String context) throws ParsingException {
        try {
            return new String(readBytes(buffer, context), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e); // should not happen
        }
    }

    /** Reads a RFC4251 "mpint" type from a given buffer. */
    private static BigInteger readBigInt(ByteBuffer buffer, String context) throws ParsingException {
        byte[] bytes = readBytes(buffer, context);
        if (bytes.length == 0) return BigInteger.ZERO;

        // The sign bit of the first byte is interpreted as sign bit for the entire mpint,
        // but we don't need to support negative numbers here.
        if (bytes[0] < 0) throw new KeyException("negative mpint value not supported");

        // Crypto on excessively large numbers is slow; don't let people DoS us
        if (bytes.length > PublicKey.MAX_SIZE_BYTES) {
            throw new KeyException("mpint consisting of %d bytes is too large", bytes.length);
        }
        return new BigInteger(1, bytes); // argument 1 forces a positive number
    }


    /** Encapsulates a public key as found in the set of authorized keys for a user,
     * and also as embedded in an auth request. The format is specified in RFC 4253.
     * We currently only support the ssh-rsa key type. */
    public static class PublicKey {
        public static final int MAX_SIZE_BYTES = 8192; // same as OpenSSH's limit
        private final String key_type, description;
        private final RSAKeyParameters key;

        private PublicKey(String key_type, String key_base64, String description) {
            this(key_type, Base64.decode(key_base64), description);
        }

        private PublicKey(String key_type, byte[] key_bytes) {
            this(key_type, key_bytes, "");
        }

        private PublicKey(String key_type, byte[] key_bytes, String description) {
            if (!key_type.equals("ssh-rsa")) {
                throw new KeyException("unsupported public key type: %s", key_type);
            }
            this.key_type = key_type;
            this.description = description;
            ByteBuffer key_buf = ByteBuffer.wrap(key_bytes);

            try {
                String encoded_key_type = readString(key_buf, "pubkey type");
                if (!encoded_key_type.equals(this.key_type)) {
                    throw new KeyException("public key %s has key type mismatch: %s != %s",
                                           description, key_type, encoded_key_type);
                }

                BigInteger exponent = readBigInt(key_buf, "pubkey exponent");
                BigInteger modulus = readBigInt(key_buf, "pubkey modulus");

                if (key_buf.hasRemaining()) {
                    throw new KeyException("public key %s is too long -- corrupted?", description);
                }
                this.key = new RSAKeyParameters(false, modulus, exponent);

            } catch (BufferUnderflowException e) {
                // Most likely the base64 string was somehow truncated
                throw new KeyException("public key %s is too short -- corrupted?", description);
            } catch (ParsingException e) {
                throw new KeyException("public key %s corrupted: %s", description, e.getMessage());
            }
        }

        public String getDescription() {
            return description;
        }

        public int hashCode() {
            return key.getExponent().hashCode() + key.getModulus().hashCode();
        }

        public boolean equals(Object other) {
            if (other instanceof PublicKey) {
                return key.getExponent().equals(((PublicKey) other).key.getExponent()) &&
                    key.getModulus().equals(((PublicKey) other).key.getModulus());
            } else {
                return false;
            }
        }
    }


    /** Encapsulates a publickey authentication request as specified in RFC 4252. */
    public static class AuthRequest {
        private URL request_url;
        private PublicKey signer; // set only if the signature has been verified
        private byte[] challenge; // equivalent to session identifier in SSH
        private String username;  // username for which authentication is requested by the client
        private String error;     // error message if authentication failed, null if no error

        public static final String OCTOKEY_SERVICE_NAME = "octokey-auth";
        public static final String AUTHENTICATION_METHOD = "publickey";
        public static final String SIGNING_ALGORITHM = "ssh-rsa";

        private AuthRequest(String auth_request_base64) {
            ByteBuffer buffer = ByteBuffer.wrap(Base64.decode(auth_request_base64));
            try {
                this.challenge = readBytes(buffer, "challenge");

                String request_url_str = readString(buffer, "request_url");
                try {
                    this.request_url = new URL(request_url_str);
                } catch (MalformedURLException e) {
                    this.error = "malformed request URL: " + request_url_str;
                    return;
                }

                this.username = readString(buffer, "username");

                String service_name = readString(buffer, "service_name");
                if (!service_name.equals(OCTOKEY_SERVICE_NAME)) {
                    this.error = "unsupported service name: " + service_name;
                    return;
                }

                String auth_method = readString(buffer, "auth_method");
                if (!auth_method.equals(AUTHENTICATION_METHOD)) {
                    this.error = "unsupported authentication method: " + auth_method;
                    return;
                }

                String signing_algorithm = readString(buffer, "signing_algorithm");
                if (!signing_algorithm.equals(SIGNING_ALGORITHM)) {
                    this.error = "unsupported signing algorithm: " + signing_algorithm;
                    return;
                }

                PublicKey pubkey = new PublicKey(signing_algorithm, readBytes(buffer, "pubkey"));

                int signature_offset = buffer.position();
                Signature signature = new Signature(readBytes(buffer, "signature"));
                if (buffer.hasRemaining()) {
                    this.error = "auth request is too long -- did something get appended?";
                    return;
                }

                if (signature.validFor(buffer.array(), 0, signature_offset, pubkey)) {
                    this.signer = pubkey;
                } else {
                    this.error = "signature does not match";
                }

            } catch (BufferUnderflowException e) {
                this.error = "auth request is too short -- did it get truncated?";
            } catch (KeyException e) {
                this.error = e.getMessage();
            } catch (ParsingException e) {
                this.error = e.getMessage();
            }
        }
    }


    /** Encapsulates a public key signature as specified in RFC 4253. */
    private static class Signature {
        private byte[] sig_blob;
        public static final String SIGNING_ALGORITHM = "ssh-rsa";

        private Signature(byte[] sig_structure) throws ParsingException {
            ByteBuffer buffer = ByteBuffer.wrap(sig_structure);

            String algorithm = readString(buffer, "signature_algorithm");
            if (!algorithm.equals(SIGNING_ALGORITHM)) {
                throw new KeyException("unsupported signing algorithm: %s", algorithm);
            }

            this.sig_blob = readBytes(buffer, "signature_blob");
            if (buffer.hasRemaining()) {
                throw new KeyException("signature structure is too long -- corrupted?");
            }
        }

        public boolean validFor(byte[] data, int offset, int length, PublicKey pubkey) {
            RSADigestSigner signer = new RSADigestSigner(new SHA1Digest());
            signer.init(false, pubkey.key);
            signer.update(data, offset, length);
            return signer.verifySignature(sig_blob);
        }
    }


    public static class ParsingException extends Exception {
        public ParsingException(String context, String message) {
            super(String.format("while parsing %s: %s", context, message));
        }
    }

    public static class KeyException extends RuntimeException {
        public KeyException(String format, Object... args) {
            super(String.format(format, args));
        }
    }
}
