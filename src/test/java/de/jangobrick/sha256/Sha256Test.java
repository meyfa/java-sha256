package de.jangobrick.sha256;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class Sha256Test
{
    @Test
    public void testPaddedLengthDivisibleBy512()
    {
        byte[] b = { 0, 1, 2, 3, 0 };

        byte[] padded = Sha256.pad(b);
        int paddedLengthBits = padded.length * 8;

        assertTrue(paddedLengthBits % 512 == 0);
    }

    @Test
    public void testPaddedMessageHas1Bit()
    {
        byte[] b = new byte[64];

        byte[] padded = Sha256.pad(b);

        assertEquals((byte) 0b1000_0000, padded[b.length]);
    }

    @Test
    public void testPaddingAllZero()
    {
        byte[] b = { 1, 1, 1, 1, 1, 1, 1, };

        byte[] padded = Sha256.pad(b);

        for (int i = b.length + 1; i < padded.length - 8; ++i) {
            assertEquals("byte " + i + " not 0", 0, padded[i]);
        }
    }
}
