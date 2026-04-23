package com.crypto;

import org.junit.jupiter.api.Test;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import java.security.MessageDigest;
import java.util.Random;

public class Sha3PerformanceTest {

    @Test
    void comparePerformance() throws Exception {
        int size = 100 * 1024 * 1024; 
        byte[] data = new byte[size];
        new Random().nextBytes(data);

        System.out.println("\n=== SHA3-256 PERFORMANCE COMPARISON (100 MB) ===");

        // Test Case 1: Standard Java (JDK) Implementation
        long startJDK = System.nanoTime();
        MessageDigest jdkDigest = MessageDigest.getInstance("SHA3-256");
        jdkDigest.update(data);
        jdkDigest.digest(); // Finalizes the hash
        long timeJDK = (System.nanoTime() - startJDK) / 1_000_000;
        System.out.println("Standard JDK:   " + timeJDK + " ms");

        // Test Case 2: Bouncy Castle Library Implementation
        long startBC = System.nanoTime();
        SHA3.Digest256 bcDigest = new SHA3.Digest256();
        bcDigest.update(data);
        bcDigest.digest(); 
        long timeBC = (System.nanoTime() - startBC) / 1_000_000;
        System.out.println("Bouncy Castle:  " + timeBC + " ms");

        String winner = (timeJDK < timeBC) ? "Standard JDK" : "Bouncy Castle";
        long difference = Math.abs(timeJDK - timeBC);
        
        System.out.println("Result: " + winner + " is faster by " + difference + " ms");
        System.out.println("================================================");
    }
}