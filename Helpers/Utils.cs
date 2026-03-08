namespace RE9SaveDecryptor.Helpers;

public static class Utils
{
    public static ulong SplitMix64(ulong state)
    {
        ulong z = state += 0x9E3779B97F4A7C15;
        z = (z ^ (z >> 0x1E)) * 0xBF58476D1CE4E5B9;
        z = (z ^ (z >> 0x1B)) * 0x94D049BB133111EB;
        return z ^ (z >> 0x1F);
    }
}