{-# LANGUAGE DataKinds, TypeFamilies, TypeOperators, MultiParamTypeClasses #-}
module Java.Bouncycastle.Types where

import Java
import Java.Array
import Java.Math

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

data Committer = Committer @org.bouncycastle.crypto.Committer
  deriving Class

data Commitment = Commitment @org.bouncycastle.crypto.Commiter
  deriving Class

data DerivationFunction = DerivationFunction @org.bouncycastle.crypto.DerivationFunction
  deriving Class

data DerivationParameters = DerivationParameters @org.bouncycastle.crypto.DerivationParameters
  deriving Class

data Digest = Digest @org.bouncycastle.crypto.Digest
  deriving Class

data DigestDerivationFunction = DigestDerivationFunction @org.bouncycastle.crypto.DigestDerivationFunction
  deriving Class

data DSA = DSA @org.bouncycastle.crypto.DSA
  deriving Class

data BigIntegerArray = BigIntegerArray @java.math.BigInteger[]
  deriving Class

instance JArray BigInteger BigIntegerArray
