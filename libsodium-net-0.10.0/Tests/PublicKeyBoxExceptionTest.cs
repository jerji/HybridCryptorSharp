﻿using System.Text;
using NUnit.Framework;
using Sodium;
using Sodium.Exceptions;

namespace Tests
{
  /// <summary>Exception tests for the PublicKeyBox class</summary>
  [TestFixture]
  public class PublicKeyBoxExceptionTest
  {
    [Test]
    [ExpectedException(typeof(SeedOutOfRangeException))]
    public void GenerateKeyPairFromPrivateBadKeyTest()
    {
      //Don`t copy bobSk for other tests (bad key)!
      //30 byte
      var bobSk = new byte[] {
				0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
				0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
				0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
				0x1c,0x2f,0x8b,0x27,0xff,0x88
			};
      PublicKeyBox.GenerateKeyPair(bobSk);
    }

    [Test]
    [ExpectedException(typeof(KeyOutOfRangeException))]
    public void PublicKeyBoxCreateWithBadPrivateKey()
    {
      var bobSk = new byte[] {
				0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
				0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
				0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
				0x1c,0x2f,0x8b,0x27,0xff,0x88
			};
      PublicKeyBox.Create(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"), bobSk,
        Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));
    }

    [Test]
    [ExpectedException(typeof(KeyOutOfRangeException))]
    public void PublicKeyBoxCreateWithBadPublicKey()
    {
      var bobPk = new byte[] {
				0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
				0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
				0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
				0x1c,0x2f,0x8b,0x27,0xff,0x88
			};
      PublicKeyBox.Create(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"), bobPk);
    }

    [Test]
    [ExpectedException(typeof(NonceOutOfRangeException))]
    public void PublicKeyBoxCreateWithBadNonce()
    {
      PublicKeyBox.Create(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVX"),
        Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
        Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));
    }

    [Test]
    [ExpectedException(typeof(KeyOutOfRangeException))]
    public void PublicKeyBoxCreateDetachedWithBadPrivateKey()
    {
      var bobSk = new byte[] {
				0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
				0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
				0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
				0x1c,0x2f,0x8b,0x27,0xff,0x88
			};
      PublicKeyBox.CreateDetached(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"), bobSk,
        Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));
    }

    [Test]
    [ExpectedException(typeof(KeyOutOfRangeException))]
    public void PublicKeyBoxCreateDetachedWithBadPublicKey()
    {
      var bobPk = new byte[] {
				0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
				0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
				0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
				0x1c,0x2f,0x8b,0x27,0xff,0x88
			};
      PublicKeyBox.CreateDetached(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"), bobPk);
    }

    [Test]
    [ExpectedException(typeof(NonceOutOfRangeException))]
    public void PublicKeyBoxCreateDetachedWithBadNonce()
    {
      PublicKeyBox.CreateDetached(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVX"),
        Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
        Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));
    }

    [Test]
    [ExpectedException(typeof(KeyOutOfRangeException))]
    public void PublicKeyBoxOpenBadPrivateKey()
    {
      var bobPk = new byte[] {
				0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
				0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
				0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
				0x1c,0x2f,0x8b,0x27,0xff,0x88
			};
      PublicKeyBox.Open(
        Utilities.HexToBinary("aed04284c55860ad0f6379f235cc2cb8c32aba7a811b35cfac94f64d"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        bobPk,
        Utilities.HexToBinary("753cb95919b15b76654b1969c554a4aaf8334402ef1468cb40a602b9c9fd2c13"));
    }

    [Test]
    [ExpectedException(typeof(KeyOutOfRangeException))]
    public void PublicKeyBoxOpenBadPublicKey()
    {
      var bobPk = new byte[] {
				0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
				0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
				0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
				0x1c,0x2f,0x8b,0x27,0xff,0x88
			};
      PublicKeyBox.Open(
        Utilities.HexToBinary("aed04284c55860ad0f6379f235cc2cb8c32aba7a811b35cfac94f64d"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Utilities.HexToBinary("d4c8438482d5d103a2315251a5eed7c46017864a02ddc4c8b03f0ede8cb3ef9b"), bobPk);
    }

    [Test]
    [ExpectedException(typeof(NonceOutOfRangeException))]
    public void PublicKeyBoxOpenBadNonce()
    {
      PublicKeyBox.Open(
        Utilities.HexToBinary("aed04284c55860ad0f6379f235cc2cb8c32aba7a811b35cfac94f64d"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
        Utilities.HexToBinary("d4c8438482d5d103a2315251a5eed7c46017864a02ddc4c8b03f0ede8cb3ef9b"),
        Utilities.HexToBinary("753cb95919b15b76654b1969c554a4aaf8334402ef1468cb40a602b9c9fd2c13"));
    }

    [Test]
    [ExpectedException(typeof(KeyOutOfRangeException))]
    public void PublicKeyBoxOpenDetachedBadPrivateKey()
    {
      var actual = PublicKeyBox.CreateDetached(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
        Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));

      var clear = PublicKeyBox.OpenDetached(actual.CipherText, actual.Mac,
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a159"),
        Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));

      //we shouldn't get here
      Assert.IsNull(clear);
    }

    [Test]
    [ExpectedException(typeof(KeyOutOfRangeException))]
    public void PublicKeyBoxOpenDetachedBadPublicKey()
    {
      var actual = PublicKeyBox.CreateDetached(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
        Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec856"));

      var clear = PublicKeyBox.OpenDetached(actual.CipherText, actual.Mac,
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
        Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));

      //we shouldn't get here
      Assert.IsNull(clear);
    }

    [Test]
    [ExpectedException(typeof(NonceOutOfRangeException))]
    public void PublicKeyBoxOpenDetachedBadNonce()
    {
      var actual = PublicKeyBox.CreateDetached(
        Encoding.UTF8.GetBytes("Adam Caudill"),
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
        Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));

      var clear = PublicKeyBox.OpenDetached(actual.CipherText, actual.Mac,
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVW"),
        Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
        Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));

      //we shouldn't get here
      Assert.IsNull(clear);
    }


    [Test]
    [ExpectedException(typeof(MacOutOfRangeException))]
    public void PublicKeyBoxOpenDetachedBadMac()
    {
      var actual = PublicKeyBox.CreateDetached(
      Encoding.UTF8.GetBytes("Adam Caudill"),
      Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
      Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
      Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));

      var clear = PublicKeyBox.OpenDetached(actual.CipherText, null,
        Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWX"),
        Utilities.HexToBinary("2a5c92fac62514f793c0bfd374f629a138c5702793a32c61dadc593728a15975"),
        Utilities.HexToBinary("83638e30326e2f55509286ac86afeb5bfd0732a3d11747bd50eb96bb9ec85645"));

      //we shouldn't get here
      Assert.IsNull(clear);
    }
  }
}
