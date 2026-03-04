package com.sparrowwallet.drongo.nip05;

public class Nip05Exception extends Exception {
    public Nip05Exception(String message) {
        super(message);
    }

    public Nip05Exception(String message, Throwable cause) {
        super(message, cause);
    }
}
