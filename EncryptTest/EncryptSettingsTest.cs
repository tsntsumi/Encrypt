using NUnit.Framework;
using System;
using Encrypt;

namespace EncryptTest
{
    [TestFixture()]
    public class EncryptSettingsTest
    {
        EncryptSettings settings;

        [SetUp()]
        public void SetUpSettings()
        {
            settings = EncryptSettings.Instance;
        }

        [Test()]
        public void UniqueInstanceTest()
        {
            var moreSettings = EncryptSettings.Instance;

            Assert.AreSame(settings, moreSettings);
        }

        [Test(), ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void ThrowArgumentOutOfRangeExceptionWhenBlockSizeIsNot128()
        {
            settings.BlockSize = 192;
        }

        [Test()]
        public void BlockSizeMustBe128()
        {
            try
            {
                settings.BlockSize = 128;
            }
            catch
            {
                Assert.Fail();
            }
        }

        [Test(), ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void ThrowArgumentOutOfRangeExceptionWhenKeySizeIsNot128_192_256()
        {
            settings.KeySize = 144;
        }

        [Test()]
        public void KeySizeCanBeAssigned128_192_256()
        {
            try
            {
                settings.KeySize = 128;
                settings.KeySize = 192;
                settings.KeySize = 256;
            }
            catch
            {
                Assert.Fail();
            }
        }

        [Test(), ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void ThrowArgumentOutOfRangeExceptionWhenSaltSizeIsNotMultipleBy8()
        {
            settings.SaltSize = 7;
        }

        [Test(), ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void ThrowArgumentOutOfRangeExceptionWhenSaltSizeIsMinus()
        {
            settings.SaltSize = -8;
        }

        [Test(), ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void ThrowArgumentOutOfRangeExceptionWhenSaltSizeIsZero()
        {
            settings.SaltSize = 0;
        }

        [Test()]
        public void SaltSizeCanBeAssignValueMultipleBy8()
        {
            try
            {
                settings.SaltSize = 7 * 8;
            }
            catch
            {
                Assert.Fail();
            }
        }
    }
}

