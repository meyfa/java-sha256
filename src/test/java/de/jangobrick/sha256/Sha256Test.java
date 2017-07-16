package de.jangobrick.sha256;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class Sha256Test
{
    // PADDING

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

    // INT ARRAY CONSTRUCTION

    @Test
    public void testToIntArrayEmpty()
    {
        byte[] input = {};
        int[] expected = {};

        assertArrayEquals(expected, Sha256.toIntArray(input));
    }

    @Test
    public void testToIntArrayMultiple()
    {
        byte[] input = { 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3 };
        int[] expected = { 1, 2, 3 };

        assertArrayEquals(expected, Sha256.toIntArray(input));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testToIntArrayThrowsForIllegalLength()
    {
        Sha256.toIntArray(new byte[] { 0, 0, 0, 1, 0 });
    }

    // BYTE ARRAY CONSTRUCTION

    @Test
    public void testToByteArrayEmpty()
    {
        int[] input = {};
        byte[] expected = {};

        assertArrayEquals(expected, Sha256.toByteArray(input));
    }

    @Test
    public void testToByteArrayMultiple()
    {
        int[] input = { 1, 2, 3 };
        byte[] expected = { 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3 };

        assertArrayEquals(expected, Sha256.toByteArray(input));
    }
}
