namespace RE9SaveDecryptor.Types;

public unsafe struct Pair
{
    public fixed byte a[0x40];
    public fixed byte b[0x40];
}

public struct AuthBlock
{
    public Pair Chunk0;
    public Pair Chunk1;
    public Pair Chunk2;
    public Pair Chunk3;
    public long Hash;
    public uint Unk0;
    public uint Unk1;
}