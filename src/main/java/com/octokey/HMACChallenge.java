package com.octokey;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;


/**
 * A challenge that the server can verify as a challenge it has issued, without
 * requiring any persistent state on the server. The challenge is constructed as
 * follows:
 *
 *   - 8 bytes  -- timestamp (milliseconds since epoch, big endian)
 *   - 1 byte   -- client IP address family (4 = IPv4, 6 = IPv6)
 *   - 4 bytes or 16 bytes -- client IP address in network byte order
 *   - 32 bytes -- random
 *   - 20 bytes -- SHA-1-based HMAC over all the other fields above
 */
public class HMACChallenge implements ChallengeVerifier {

    /** Maximum period of time for which a challenge is valid */
    public static final long MAX_CHALLENGE_AGE_MILLISECONDS = 300000; // 5 minutes

    /** Maximum time that a challenge is allowed to be in the future (this should
     * only happen if different servers' clocks are not quite in sync) */
    public static final long MAX_CHALLENGE_AHEAD_MILLISECONDS = 5000; // 5 seconds

    /** Number of random bytes to insert into the challenge, to make it unique and
     * to give the HMAC something meaty to sign */
    public static final int RANDOM_BYTES = 32;

    private final KeyParameter secret;
    private final InetAddress client_ip;
    private final Digest digest = new SHA1Digest();

    public HMACChallenge(String secret_base64, String client_ip) throws UnknownHostException {
        this.secret = new KeyParameter(Base64.decode(secret_base64));
        this.client_ip = InetAddress.getByName(client_ip);
    }

    private void serializeClientIP(ByteBuffer buffer) {
        if (client_ip instanceof Inet4Address) {
            buffer.put((byte) 4);
            byte[] address = ((Inet4Address) client_ip).getAddress();
            assert(address.length == 4);
            buffer.put(address);

        } else if (client_ip instanceof Inet6Address) {
            buffer.put((byte) 6);
            byte[] address = ((Inet4Address) client_ip).getAddress();
            assert(address.length == 16);
            buffer.put(address);

        } else {
            throw new IllegalStateException("unrecognized type of IP address: " + client_ip.getClass().getName());
        }
    }

    private boolean checkClientIP(ByteBuffer buffer) {
        try {
            byte type = buffer.get();
            if (type == 4) {
                byte[] ipv4_bytes = new byte[4];
                buffer.get(ipv4_bytes);
                InetAddress ipv4_addr = InetAddress.getByAddress(ipv4_bytes);
                return ipv4_addr.equals(client_ip);

            } else if (type == 6) {
                byte[] ipv6_bytes = new byte[16];
                buffer.get(ipv6_bytes);
                InetAddress ipv6_addr = InetAddress.getByAddress(ipv6_bytes);
                return ipv6_addr.equals(client_ip);

            } else {
                return false;
            }
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private boolean checkTimestamp(ByteBuffer buffer) {
        long timestamp = buffer.getLong();
        long now = new Date().getTime();
        return (now - timestamp <= MAX_CHALLENGE_AGE_MILLISECONDS) &&
               (timestamp - now <= MAX_CHALLENGE_AHEAD_MILLISECONDS);
    }

    public byte[] generate() {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        buffer.putLong(new Date().getTime());
        serializeClientIP(buffer);

        byte[] random = new byte[RANDOM_BYTES];
        new SecureRandom().nextBytes(random);
        buffer.put(random);

        HMac hmac = new HMac(digest);
        hmac.init(secret);
        hmac.update(buffer.array(), 0, buffer.position());
        hmac.doFinal(buffer.array(), buffer.position());

        byte[] output = new byte[buffer.position() + digest.getDigestSize()];
        buffer.rewind();
        buffer.get(output);
        return output;
    }

    @Override
    public boolean verify(byte[] challenge) {
        ByteBuffer buffer = ByteBuffer.wrap(challenge);
        try {
            if (!checkTimestamp(buffer)) return false;
            if (!checkClientIP(buffer)) return false;
            buffer.position(buffer.position() + RANDOM_BYTES);

            HMac hmac = new HMac(digest);
            hmac.init(secret);
            hmac.update(buffer.array(), 0, buffer.position());

            byte[] actual   = new byte[digest.getDigestSize()];
            byte[] expected = new byte[digest.getDigestSize()];
            buffer.get(actual);
            hmac.doFinal(expected, 0);

            if (buffer.hasRemaining()) return false; // don't allow trailing garbage
            return Arrays.constantTimeAreEqual(actual, expected);

        } catch (BufferUnderflowException e) {
            return false;
        }
    }
}
