package net.meyfa.sha256;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import static org.junit.Assert.*;

public class Sha256Test {
    // HASHING - hash(byte[])

    @Test
    public void testHashEmpty() {
        byte[] b = {};
        byte[] expected = DatatypeConverter.parseHexBinary(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        assertArrayEquals(expected, Sha256.hash(b));
    }

    @Test
    public void testHashRegular() {
        byte[] b = "Hello world!".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = DatatypeConverter.parseHexBinary(
                "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a");

        assertArrayEquals(expected, Sha256.hash(b));
    }

    @Test
    public void testHashLong() {
        byte[] b = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
                + "Proin pulvinar turpis purus, sit amet dapibus magna commodo "
                + "quis metus.").getBytes(StandardCharsets.US_ASCII);
        byte[] expected = DatatypeConverter.parseHexBinary(
                "60497604d2f6b4df42cea5efb8956f587f81a4ad66fa1b65d9e085224d255036");

        assertArrayEquals(expected, Sha256.hash(b));
    }

    @Test
    public void testHashRawBytes() {
        byte[] b = new byte[256];
        for (int i = 0; i < b.length; ++i) {
            b[i] = (byte) i;
        }

        byte[] expected = DatatypeConverter.parseHexBinary(
                "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880");

        assertArrayEquals(expected, Sha256.hash(b));
    }

    @Test
    public void testHash55() {
        byte[] b = new byte[55];
        Arrays.fill(b, (byte) 'a');

        byte[] expected = DatatypeConverter.parseHexBinary(
                "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");

        assertArrayEquals(expected, Sha256.hash(b));
    }

    // PADDING

    @Test
    public void testPaddedLengthDivisibleBy512() {
        byte[] b = { 0, 1, 2, 3, 0 };

        byte[] padded = Sha256.pad(b);
        int paddedLengthBits = padded.length * 8;

        assertEquals(0, paddedLengthBits % 512);
    }

    @Test
    public void testPaddedMessageHas1Bit() {
        byte[] b = new byte[64];

        byte[] padded = Sha256.pad(b);

        assertEquals((byte) 0b1000_0000, padded[b.length]);
    }

    @Test
    public void testPaddingAllZero() {
        byte[] b = { 1, 1, 1, 1, 1, 1, 1, };

        byte[] padded = Sha256.pad(b);

        for (int i = b.length + 1; i < padded.length - 8; ++i) {
            assertEquals("byte " + i + " not 0", 0, padded[i]);
        }
    }

    // INT ARRAY CONSTRUCTION

    @Test
    public void testToIntArrayEmpty() {
        byte[] input = {};
        int[] expected = {};

        assertArrayEquals(expected, Sha256.toIntArray(input));
    }

    @Test
    public void testToIntArrayMultiple() {
        byte[] input = { 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3 };
        int[] expected = { 1, 2, 3 };

        assertArrayEquals(expected, Sha256.toIntArray(input));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testToIntArrayThrowsForIllegalLength() {
        Sha256.toIntArray(new byte[] { 0, 0, 0, 1, 0 });
    }

    // BYTE ARRAY CONSTRUCTION

    @Test
    public void testToByteArrayEmpty() {
        int[] input = {};
        byte[] expected = {};

        assertArrayEquals(expected, Sha256.toByteArray(input));
    }

    @Test
    public void testToByteArrayMultiple() {
        int[] input = { 1, 2, 3 };
        byte[] expected = { 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3 };

        assertArrayEquals(expected, Sha256.toByteArray(input));
    }
}
