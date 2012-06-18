package com.octokey;

public interface ChallengeVerifier {
    boolean verify(byte[] challenge);
}
