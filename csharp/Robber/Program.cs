// Лабораторна робота №4 — «Захист даних»
// CodinGame: Hacking at RobberCity
//
// Друга, незалежна реалізація того самого алгоритму мовою C#.
// Призначення — перехресна перевірка: обидві реалізації мають давати
// побітово однаковий результат на всіх шести офіційних тестах.
//
// Запуск:
//   dotnet run --project csharp/Robber -- selftest
//   dotnet run --project csharp/Robber < input.txt        (режим CodinGame)
//   dotnet run --project csharp/Robber -- break m1 m2 m3
//   dotnet run --project csharp/Robber -- protocol "текст"

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Lab4.Robber;

/// <summary>Потоковий шифр XOR: шифрування та розшифрування — та сама дія.</summary>
public static class XorCipher
{
    public static byte[] Xor(byte[] left, byte[] right)
    {
        if (left.Length != right.Length)
            throw new ArgumentException(
                $"довжини не збігаються: {left.Length} і {right.Length}");

        var result = new byte[left.Length];
        for (int i = 0; i < left.Length; i++)
            result[i] = (byte)(left[i] ^ right[i]);
        return result;
    }

    public static byte[] XorAll(params byte[][] chunks)
    {
        if (chunks.Length == 0)
            throw new ArgumentException("потрібна хоча б одна послідовність");

        var result = chunks[0];
        for (int i = 1; i < chunks.Length; i++)
            result = Xor(result, chunks[i]);
        return result;
    }

    /// <summary>Криптографічно стійкий ключ заданої довжини.</summary>
    public static byte[] RandomKey(int length)
    {
        var key = new byte[length];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    public static byte[] FromHex(string digits)
    {
        var cleaned = new string(digits.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (cleaned.Length % 2 != 0)
            throw new ArgumentException($"непарна кількість цифр: {cleaned.Length}");

        var data = new byte[cleaned.Length / 2];
        for (int i = 0; i < data.Length; i++)
            data[i] = Convert.ToByte(cleaned.Substring(i * 2, 2), 16);
        return data;
    }

    public static string ToHex(byte[] data) =>
        string.Concat(data.Select(b => b.ToString("x2")));
}

/// <summary>Триетапний протокол «двох замків», реалізований на XOR.</summary>
public static class Protocol
{
    /// <summary>
    /// Повертає три повідомлення, що йдуть каналом:
    /// m1 = M^A, m2 = m1^B, m3 = m2^A. Четвертий крок (Боб знімає свій
    /// ключ) каналом не передається, тому атакуючий його не бачить.
    /// </summary>
    public static (byte[] M1, byte[] M2, byte[] M3) Run(
        byte[] message, byte[] aliceKey, byte[] bobKey)
    {
        var m1 = XorCipher.Xor(message, aliceKey);
        var m2 = XorCipher.Xor(m1, bobKey);
        var m3 = XorCipher.Xor(m2, aliceKey);

        if (!XorCipher.Xor(m3, bobKey).SequenceEqual(message))
            throw new InvalidOperationException("протокол не відтворив повідомлення");

        return (m1, m2, m3);
    }
}

/// <summary>
/// Атака. Система над GF(2) має повний ранг, тому відновлюються і текст,
/// і обидва одноразові ключі.
/// </summary>
public static class Attack
{
    public static byte[] RecoverMessage(byte[] m1, byte[] m2, byte[] m3) =>
        XorCipher.XorAll(m1, m2, m3);

    public static (byte[] Alice, byte[] Bob) RecoverKeys(byte[] m1, byte[] m2, byte[] m3) =>
        (XorCipher.Xor(m2, m3), XorCipher.Xor(m1, m2));
}

public static class Program
{
    /// <summary>Шість офіційних тестів CodinGame (входи та очікувані виходи).</summary>
    private static readonly (string Label, string M1, string M2, string M3, string Out)[] Cases =
    {
        ("Greetings",
         "391813c092a2d5ac9acb705dfe41be3df08de67d1145cbcc3f",
         "03adeae2c8c2f2336c8a8d312733c2456e76e0b2d9068adc3f",
         "72d0954e354045f09461dc4c911d0b58ff8963efb12c34303f",
         "Hello bob ! How are you ?"),
        ("Are you sure about that ?",
         "6cda2e033736a529f682473750fcf82813174997fa5ea8cf600327b77c024bde948a0713c235da2d2e8acc473c746521",
         "91eca2b11937389d047f1788c6e9b615a6d10e98501d70eaf8e0478bc567867c4b20584f21152379fa068af6ac4e6521",
         "b411e1924660edc48bdd27dab6732753d4aa2b768a25b750f687405d9912acdbffde307c804f9439a1e22fd2f14e6521",
         "I'm happy we finally found a way to communicate!"),
        ("Hey ! I'm listening",
         "1a41e784ab0ba87a8ff1eab1a9e2195e6a9c189cc5c7dc96c8d15ad95c187edfb79f51202a",
         "e31e08d1ec7100c65488b31b175bc484e8e3764dd0f88b1f1f5cd3e3032d2a15f22c05802a",
         "d32b8730341f88d4ba1a32cfcccafdbbf01a4ea27a5038e6f7fefd4f2f5c30ea649275802a",
         "*these hackers are soooo stupid !!! *"),
        ("Not a chance !",
         "fec53ecd38eddef721da340a6f1cc0527250098238cc7624a4c8d4ea434ac4e1536da5b993158b7f35",
         "3d0ef96b89a81c785b457d938af0e879908fef6ebc07199dce11e8bc55cdc23a8633b116d6eef17f35",
         "8ba4b7c3d730aee303b369ed8d89510b95b088cbf0eb0ddc4ab852767ff475aeb07e75c13c96157265",
         "Hopefully, they won't be an issue anymore"),
        ("Who laughs last laughs longest",
         "bc9d600870b7c0da44b820ed9036495606",
         "8210bb27f4e0c5d43b89374efaa435be06",
         "76ecfb47e5776d6f5f59768302f35cc921",
         "Ha ha ha ha ha !!"),
        ("THIS is really stupid",
         "2f03f64ddb650a4517b689a75c1d149dc38a43f0cf4f332871c1144e185552ccab3b13f6f0e831022f7963f5cf59224f4af60bde421be2be107146967d9c6c86b7ec16f81df38febb0810add94abd31e1e056042de83c790eb4102ed7ffd2419d75b1a90ea84f0af46ea9ae2a3e2b9ec6f0d1b99a0f5200e8f0d7d902f13b96aa50c1a1fc03fe245cc835756b03436396230",
         "67c7034ed1cb194b6c4db54783d0ac512dfb21ebeaf87e0c4db88bacd4e9c3627e8ff5c2d462d5bef2f90417586d7aa2d77248fdb37239042905b3ce197a629e013e693d25d7d8a6de673aa244bd1263ac93a7998267770fb0366a05c186e2d50be5f04d190211c0d1982f45cf890063d2f326e8d37edb8dc6fabc87fba324259d91610ddae0ff7162991e0e603436396230",
         "0a90a22f2ada7c2e08925190b3a4deb5ce1e176905d13850490bfac2a9c4f2c6b4da815157a6c4d0b8f44091b7412b88bdc50670d11eb2ce5154982144d73e2a82ff1dac4c04273f0790510bb536aa18cbb6f2bf3ed788fb6e14588e8f4da3afec8b8eb996e3d758f24681915d5cd8bf84ca584717efcbe171c4f671b185f9290aa9497729ba7c0c9d282c6be03436396230",
         "BTW, to simplify our future exchanges, let's use AES with my 1024-bit private key 5db38d5c0f16ec05ddee67e44617a094e6dd0b837fe5df242e3ea832e30469b0"),
    };

    public static int Main(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);

        if (args.Length == 0) return RunPuzzleMode();
        return args[0] switch
        {
            "selftest" => RunSelfTest(),
            "break" => RunBreak(args),
            "protocol" => RunProtocol(args),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.Error.WriteLine("вживання: selftest | break <m1> <m2> <m3> | protocol <текст>");
        return 2;
    }

    /// <summary>Режим CodinGame: три рядки зі stdin, відкритий текст у stdout.</summary>
    private static int RunPuzzleMode()
    {
        var m1 = XorCipher.FromHex(Console.ReadLine() ?? "");
        var m2 = XorCipher.FromHex(Console.ReadLine() ?? "");
        var m3 = XorCipher.FromHex(Console.ReadLine() ?? "");
        Console.WriteLine(Encoding.ASCII.GetString(Attack.RecoverMessage(m1, m2, m3)));
        return 0;
    }

    private static int RunBreak(string[] args)
    {
        if (args.Length < 4) return Usage();
        var m1 = XorCipher.FromHex(args[1]);
        var m2 = XorCipher.FromHex(args[2]);
        var m3 = XorCipher.FromHex(args[3]);
        var (alice, bob) = Attack.RecoverKeys(m1, m2, m3);
        Console.WriteLine(Encoding.ASCII.GetString(Attack.RecoverMessage(m1, m2, m3)));
        Console.WriteLine(XorCipher.ToHex(alice));
        Console.WriteLine(XorCipher.ToHex(bob));
        return 0;
    }

    /// <summary>Згенерувати сеанс із випадковими ключами й вивести три рядки каналу.</summary>
    private static int RunProtocol(string[] args)
    {
        if (args.Length < 2) return Usage();
        var message = Encoding.ASCII.GetBytes(args[1]);
        var alice = XorCipher.RandomKey(message.Length);
        var bob = XorCipher.RandomKey(message.Length);
        var (m1, m2, m3) = Protocol.Run(message, alice, bob);
        Console.WriteLine(XorCipher.ToHex(m1));
        Console.WriteLine(XorCipher.ToHex(m2));
        Console.WriteLine(XorCipher.ToHex(m3));
        return 0;
    }

    private static int RunSelfTest()
    {
        int passed = 0;
        Console.WriteLine("Офіційні тести CodinGame");
        foreach (var (label, h1, h2, h3, expected) in Cases)
        {
            var m1 = XorCipher.FromHex(h1);
            var m2 = XorCipher.FromHex(h2);
            var m3 = XorCipher.FromHex(h3);

            var text = Encoding.ASCII.GetString(Attack.RecoverMessage(m1, m2, m3));
            var (alice, bob) = Attack.RecoverKeys(m1, m2, m3);

            // Відновлені ключі мають відтворювати перехоплений трафік.
            var plain = Encoding.ASCII.GetBytes(text);
            bool keysOk = XorCipher.Xor(plain, alice).SequenceEqual(m1)
                       && XorCipher.Xor(plain, bob).SequenceEqual(m3);

            bool ok = text == expected && keysOk;
            passed += ok ? 1 : 0;
            Console.WriteLine($"[{(ok ? "OK" : "FAIL")}] {label}");
        }
        Console.WriteLine($"пройдено {passed} з {Cases.Length}");

        // Випадкові сеанси: протокол і атака мають узгоджуватися завжди.
        const int trials = 2000;
        int good = 0;
        var rnd = new Random(20261002);
        for (int i = 0; i < trials; i++)
        {
            int n = rnd.Next(1, 120);
            var message = new byte[n];
            for (int j = 0; j < n; j++) message[j] = (byte)rnd.Next(32, 127);

            var alice = XorCipher.RandomKey(n);
            var bob = XorCipher.RandomKey(n);
            var (m1, m2, m3) = Protocol.Run(message, alice, bob);

            var (ra, rb) = Attack.RecoverKeys(m1, m2, m3);
            if (Attack.RecoverMessage(m1, m2, m3).SequenceEqual(message)
                && ra.SequenceEqual(alice) && rb.SequenceEqual(bob)) good++;
        }
        Console.WriteLine($"випадкові сеанси: відновлено {good} з {trials}");

        bool allOk = passed == Cases.Length && good == trials;
        if (!allOk) Console.WriteLine("FAIL");
        return allOk ? 0 : 1;
    }
}
