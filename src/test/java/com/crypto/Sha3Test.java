package com.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import java.security.MessageDigest;

public class Sha3Test {

    // Test vectors SHA3-256: https://di-mgt.com.au/sha_testvectors.html
    private final String HASH_1_ABC = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
    private final String HASH_2_EMPTY = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    private final String HASH_3_448BIT = "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376";
    private final String HASH_4_896BIT = "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18";
    private final String HASH_5_MILLION_A = "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1";
    private final String HASH_6_EXTREMELY_LONG = "ecbbc42cbf296603acb2c6bc0410ef4378bafb24b710357f12df607758b33e2b";

    @Test
    @DisplayName("Test 1: 'abc'")
    void testVector1() throws Exception {
        assertEquals(HASH_1_ABC, getSha3Hash("abc".getBytes()));
    }

    @Test
    @DisplayName("Test 2: Empty string")
    void testVector2() throws Exception {
        assertEquals(HASH_2_EMPTY, getSha3Hash("".getBytes()));
    }

    @Test
    @DisplayName("Test 3: lenght 448 bits")
    void testVector3() throws Exception {
        String input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assertEquals(HASH_3_448BIT, getSha3Hash(input.getBytes()));
    }

    @Test
    @DisplayName("Test 4: lenght 896 bits")
    void testVector4() throws Exception {
        String input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        assertEquals(HASH_4_896BIT, getSha3Hash(input.getBytes()));
    }

    @Test
    @DisplayName("Test 5: 1,000,000 repetitions of 'a'")
    void testVector5() throws Exception {
        byte[] input = new byte[1000000];
        java.util.Arrays.fill(input, (byte) 'a');
        assertEquals(HASH_5_MILLION_A, getSha3Hash(input));
    }

    @Test
    @DisplayName("Test 6: Extremely-long message (~1 GB)")
    void testVector6() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        byte[] block = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".getBytes();
        for (int i = 0; i < 16777216; i++) {
            digest.update(block);
        }
        String result = Hex.toHexString(digest.digest()).toLowerCase();
        assertEquals(HASH_6_EXTREMELY_LONG, result);
    }

    private String getSha3Hash(byte[] input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        return Hex.toHexString(digest.digest(input)).toLowerCase();
    }
}