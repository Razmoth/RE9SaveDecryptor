using System.Security.Cryptography;

namespace RE9SaveDecryptor.Helpers;

public class AesOfb : SymmetricAlgorithm
{
    public AesOfb()
    {
        LegalBlockSizesValue = [new KeySizes(128, 128, 0)];
        LegalKeySizesValue = [new KeySizes(128, 128, 0)];
        
        BlockSize = 128;
        KeySize = 128;
        Mode = CipherMode.ECB;
        Padding = PaddingMode.None;
        FeedbackSize = 128;
    }

    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        return new AesOfbTransform(rgbKey, rgbIV ?? new byte[0x10]);
    }

    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        return new AesOfbTransform(rgbKey, rgbIV ?? new byte[0x10]);
    }

    public override void GenerateIV()
    {
        IV = RandomNumberGenerator.GetBytes(BlockSize / 8);
    }

    public override void GenerateKey()
    {
        Key = RandomNumberGenerator.GetBytes(KeySize / 8);
    }
}

internal class AesOfbTransform : ICryptoTransform
{
    private readonly Aes _aes;
    private readonly byte[] _feedback;
    private readonly byte[] _keystream;
    private readonly int _blockSizeBytes;

    public AesOfbTransform(byte[] key, byte[] iv)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, 16, nameof(iv));

        _aes = Aes.Create();
        _aes.Key = key;

        _blockSizeBytes = _aes.BlockSize / 8;

        _feedback = new byte[_blockSizeBytes];
        _keystream = new byte[_blockSizeBytes];
        iv.CopyTo(_feedback);
    }

    public int InputBlockSize => _blockSizeBytes;
    public int OutputBlockSize => _blockSizeBytes;
    public bool CanTransformMultipleBlocks => true;
    public bool CanReuseTransform => true;

    public void Dispose()
    {
        _aes.Dispose();
    }

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        ArgumentNullException.ThrowIfNull(inputBuffer);
        ArgumentNullException.ThrowIfNull(outputBuffer);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(inputOffset, inputBuffer.Length, nameof(inputOffset));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(inputCount, inputBuffer.Length - inputOffset, nameof(inputCount));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(outputOffset, outputBuffer.Length, nameof(outputOffset));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(inputCount, outputBuffer.Length - outputOffset, nameof(inputCount));

        int processed = 0;
        for (int i = 0; i < inputCount; i += _blockSizeBytes)
        {
            _aes.EncryptEcb(_feedback, _keystream, PaddingMode.None);
            int length = Math.Min(_keystream.Length, inputCount - i);
            for (int j = 0; j < length; j++)
            {
                outputBuffer[outputOffset + i + j] = (byte)(inputBuffer[inputOffset + i + j] ^ _keystream[j]);
            }

            _keystream.CopyTo(_feedback);
            processed += length;
        }

        return processed;
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        ArgumentNullException.ThrowIfNull(inputBuffer);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(inputOffset, inputBuffer.Length, nameof(inputOffset));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(inputCount, inputBuffer.Length - inputOffset, nameof(inputCount));

        byte[] output = new byte[inputCount];
        TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
        return output;
    }
}