using System.Numerics;
using System.Runtime.InteropServices;

namespace RE9SaveDecryptor.Types;

public class Auth
{
    private static readonly byte[] pBytes = Convert.FromHexString("F33B6FB972A0B72515E45C391829E182AD8A9BDC0A64D3444D79C810AB863717");
    private static readonly byte[] qBytes = Convert.FromHexString("F99DB75C39D0DB920A72AE1C8C9470C156C54D6E05B269A2A63C648855C39B0B");
    private static readonly byte[] rBytes = Convert.FromHexString("E66F544AFCCE68C5EF07B9A07B277585344A1DB61376E831F73B9FBD5F44F715");
    
    public BigInteger p;
    public BigInteger q;
    public BigInteger r;
    public BigInteger s;
    public BigInteger u;
    public BigInteger e;
    public Auth(ulong seed)
    {
        p = new BigInteger(pBytes);
        q = new BigInteger(qBytes);
        r = new BigInteger(rBytes);
        u = new BigInteger(seed);
        u %= r;
        s = BigInteger.ModPow(r, u, p);
        e = new BigInteger(0x14);
    }

    public byte[] Decrypt(AuthBlock block)
    {
        byte[] buffer = new byte[0x20];

        Span<byte> span = buffer;
        Span<ulong> ulongs = MemoryMarshal.Cast<byte, ulong>(span);
        
        ulongs[0] = Decrypt(block.Chunk0);
        ulongs[1] = Decrypt(block.Chunk1);
        ulongs[2] = Decrypt(block.Chunk2);
        ulongs[3] = Decrypt(block.Chunk3);

        return buffer;
    }

    public unsafe ulong Decrypt(Pair chunk)
    {
        BigInteger x0 = new(new Span<byte>(chunk.a, 0x40));
        BigInteger ct = new(new Span<byte>(chunk.b, 0x40));
        BigInteger x = BigInteger.ModPow(x0, u, p);
        BigInteger k = ct / x;
        return (ulong)k;
    }
}