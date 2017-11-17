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

foreign import java unsafe calculateAgreement :: CipherParameters -> Java BasicAgreement BigInteger

foreign import java unsafe getFieldSize :: Java BasicAgreement Int

foreign import java unsafe initBA :: CipherParameters -> Java BasicAgreement ()

-- End org.bouncycastle.crypto.BasicAgreement
