{-# LANGUAGE DataKinds, TypeFamilies, TypeOperators #-}
module Java.Bouncycastle.Crypto where

import Java
import Java.Array
import Java.Math
import Java.Bouncycastle.Types
import Interop.Java.Security

-- Start org.bouncycastle.crypto.AsymmetricBlockCipher

foreign import java unsafe "@interface" getInputBlockSize :: Java AsymmetricBlockCipher Int

foreign import java unsafe "@interface" getOutputBlockSize :: Java AsymmetricBlockCipher Int

foreign import java unsafe "@interface" init :: Bool -> CipherParameters -> Java AsymmetricBlockCipher ()

foreign import java unsafe "@interface" processBlock :: JByteArray -> Int -> Int
    -> Java AsymmetricBlockCipher JByteArray

-- End org.bouncycastle.crypto.AsymmetricBlockCipher

-- Start org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator

foreign import java unsafe "@interface" generateKeyPair :: Java AsymmetricCipherKeyPairGenerator AsymmetricCipherKeyPair

foreign import java unsafe "@interface" initACKPG :: KeyGenerationParameters
  -> Java AsymmetricCipherKeyPairGenerator ()

-- End org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator

-- Start org.bouncycastle.crypto.KeyGenerationParameters

foreign import java unsafe getRandom :: Java KeyGenerationParameters SecureRandom

foreign import java unsafe getStrength :: Java KeyGenerationParameters Int

-- End org.bouncycastle.crypto.KeyGenerationParameters

-- Start org.bouncycastle.crypto.AsymmetricCipherKeyPair

foreign import java unsafe getPrivate :: Java AsymmetricCipherKeyPair AsymmetricKeyParameter

foreign import java unsafe getPublic :: Java AsymmetricCipherKeyPair AsymmetricKeyParameter

-- End org.bouncycastle.crypto.AsymmetricCipherKeyPair

-- Start org.bouncycastle.crypto.BasicAgreement

foreign import java unsafe "@interface" calculateAgreement :: CipherParameters -> Java BasicAgreement BigInteger

foreign import java unsafe "@interface" getFieldSize :: Java BasicAgreement Int

foreign import java unsafe "@interface" initBA :: CipherParameters -> Java BasicAgreement ()

-- End org.bouncycastle.crypto.BasicAgreement

-- Start org.bouncycastle.crypto.BlockCipher

foreign import java unsafe "@interface" getAlgorithmName :: Java BlockCipher String

foreign import java unsafe "@interface" getBlockSize :: Java BlockCipher Int

foreign import java unsafe "@interface" initBC :: Bool -> CipherParameters -> Java BlockCipher ()

foreign import java unsafe "@interface" processBlockBC :: JByteArray -> Int -> JByteArray -> Int
    -> Java BlockCipher Int

foreign import java unsafe "@interface" reset :: Java BlockCipher ()

-- End org.bouncycastle.crypto.BlockCipher

-- Start org.bouncycastle.crypto.CharToByteConverter

foreign import java unsafe "@interface" convert :: JCharArray -> Java CharToByteConverter JByteArray

foreign import java unsafe "@interface" getType :: Java CharToByteConverter String

-- End org.bouncycastle.crypto.CharToByteConverter

-- Start org.bouncycastle.crypto.Committer

foreign import java unsafe "@interface" commit :: JByteArray -> Java Committer Commitment

foreign import java unsafe "@interface" isRevealed :: Commitment -> JByteArray
  -> Java Committer Bool

-- End org.bouncycastle.crypto.Committer

-- Start org.bouncycastle.crypto.Commitment

foreign import java unsafe getcommitment :: Java Commitment JByteArray

foreign import java unsafe getSecret :: Java Commitment JByteArray

-- End org.bouncycastle.crypto.Commitment
