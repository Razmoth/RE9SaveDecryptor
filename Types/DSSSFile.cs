using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using HashifyNet;
using HashifyNet.Algorithms.CityHash;
using HashifyNet.Algorithms.MurmurHash;
using RE9SaveDecryptor.Helpers;
using System.Buffers;
using System.Security.Cryptography;

namespace RE9SaveDecryptor.Types;

[Flags]
public enum DSSSFlags
{
    Compressed = 8,
    Mandarin = 0x10,
}

public class DSSSFile
{
    private static readonly int BlockSize = 0x4000;
    private static readonly int[] Versions = [2];
    private static readonly string Signature = "DSSS";
    private static readonly IMurmurHash3 Murmur3Hasher = HashFactory<IMurmurHash3>.Create(new MurmurHash3Config() { Seed = -1 });
    private static readonly ICityHash CityHasher = HashFactory<ICityHash>.Create(new CityHashConfigProfile64Bits());

    public int Version { get; set; }
    public DSSSFlags Flags { get; set; }
    public long DataOffset { get; set; }
    public long UnpackSize { get; set; }
    public int Hash { get; set; }

    public DSSSFile(string path) : this(File.OpenRead(path)) {}
    public DSSSFile(Stream stream)
    {
        using BinaryReader reader = new(stream, Encoding.UTF8, true);
        string signature = reader.ReadNullString(Signature.Length);
        if (signature != Signature)
        {
            throw new InvalidDataException("Invalid Signature !!");
        }

        Version = reader.ReadInt32();
        if (!Versions.Contains(Version))
        {
            throw new InvalidDataException($"Version {Version} not supported !!");
        }

        Flags = (DSSSFlags)reader.ReadInt32();
        if (!Flags.HasFlag(DSSSFlags.Mandarin))
        {
            throw new InvalidDataException("Not a mandarin encrypted file !!");
        }

        reader.ReadInt32(); // padding

        DataOffset = reader.BaseStream.Position;

        long footerOffset = Marshal.SizeOf(UnpackSize) + Marshal.SizeOf(Hash);
        reader.BaseStream.Seek(-footerOffset, SeekOrigin.End);

        UnpackSize = reader.ReadInt64();
        ArgumentOutOfRangeException.ThrowIfGreaterThan(UnpackSize, reader.BaseStream.Length, nameof(UnpackSize));

        long hashOffset = reader.BaseStream.Position;
        
        Hash = reader.ReadInt32();

        SubStream dataStream = new(reader.BaseStream, 0, hashOffset);
        int computed = Murmur3Hasher.ComputeHash(dataStream).AsInt32();
        if (computed != Hash)
        {
            throw new InvalidDataException($"Data hash mismatch, expected {Hash} got {computed} !!");
        }
    }

    public void Decrypt(Stream inStream, Stream outStream, ulong seed)
    {
        Auth auth = new(seed);

        ulong state = 0x61F6868699C14DFAu;
        List<int> blocks = GetBlocks(ref state);
        state += seed;

        inStream.Position = DataOffset;

        byte[] buffer = ArrayPool<byte>.Shared.Rent(blocks.Max());
        try
        {
            long remaining = UnpackSize;
            foreach (int block in blocks)
            {
                inStream.ReadExactly(buffer, 0, Marshal.SizeOf<AuthBlock>());

                byte[] key = new byte[0x10];
                byte[] iv = new byte[0x10];
                for (int i = 0; i < 0x10; i++)
                {
                    state = Utils.SplitMix64(state);
                    key[i] = (byte)state;
                    iv[i] = (byte)(state >> 8);
                }

                for (int i = 0; i < Marshal.SizeOf<AuthBlock>(); i++)
                {
                    state = Utils.SplitMix64(state);
                    buffer[i] ^= (byte)state;
                }

                AuthBlock authBlock = MemoryMarshal.Read<AuthBlock>(buffer);
                byte[] authBuffer = auth.Decrypt(authBlock);

                byte[] key_verify = authBuffer[..0x10];
                byte[] iv_verify = authBuffer[0x10..];

                if (!key_verify.SequenceEqual(key))
                {
                    throw new InvalidDataException("Invalid key !!");
                }

                if (!iv_verify.SequenceEqual(iv))
                {
                    throw new InvalidDataException("Invalid iv !!");
                }

                AesOfb aes = new();
                ICryptoTransform decrpytor = aes.CreateDecryptor(key, iv);
                using CryptoStream cryptoStream = new(inStream, decrpytor, CryptoStreamMode.Read, true);

                cryptoStream.ReadExactly(buffer, 0, block);

                int length = (int)Math.Min(block, remaining);
                Span<byte> data = buffer.AsSpan(0, length);

                long computed = CityHasher.ComputeHash(data).AsInt64();
                if (computed != authBlock.Hash)
                {
                    throw new InvalidDataException("Decrypted data mismatch !!");
                }

                if (Flags.HasFlag(DSSSFlags.Compressed))
                {
                    using MemoryStream ims = new(data[0x18..].ToArray());
                    using DeflateStream ds = new(ims, CompressionMode.Decompress);
                    using MemoryStream oms = new();
                    ds.CopyTo(oms);

                    data = oms.ToArray();
                }

                outStream.Write(data);

                remaining -= length;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public List<int> GetBlocks(ref ulong state)
    {
        List<int> blocks = [];

        long remaining = UnpackSize;
        long blockCount = (remaining / BlockSize) + Convert.ToInt32(remaining % BlockSize != 0); 
        for (int i = 0; i < blockCount; i++)
        {
            if (remaining > 0)
            {
                int block = (int)(state % 8 + 1) * BlockSize;
                blocks.Add(block);
                remaining -= block;
            }

            state = Utils.SplitMix64(state);
        }

        return blocks;
    }
}