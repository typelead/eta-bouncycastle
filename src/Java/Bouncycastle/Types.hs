{-# LANGUAGE DataKinds, TypeFamilies, TypeOperators #-}
module Java.Bouncycastle.Types where

import Java

data AsymmetricBlockCipher = AsymmetricBlockCipher @org.bouncycastle.crypto.AsymmetricBlockCipher
 deriving Class

data CipherParameters = CipherParameters @org.bouncycastle.crypto.CipherParameters
  deriving Class

data AsymmetricCipherKeyPairGenerator = AsymmetricCipherKeyPairGenerator @org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
  deriving Class

data AsymmetricCipherKeyPair = AsymmetricCipherKeyPair @org.bouncycastle.crypto.AsymmetricCipherKeyPair
  deriving Class

data KeyGenerationParameters = KeyGenerationParameters @org.bouncycastle.crypto.KeyGenerationParameters
  deriving Class

data AsymmetricKeyParameter = AsymmetricKeyParameter @org.bouncycastle.crypto.AsymmetricKeyParameter
  deriving Class

data BasicAgreement = BasicAgreement @org.bouncycastle.crypto.BasicAgreement
  deriving Class

data BlockCipher = BlockCipher @org.bouncycastle.crypto.BlockCipher
  deriving Class

data CharToByteConverter = CharToByteConverter @org.bouncycastle.crypto.CharToByteConverter
  deriving Class
