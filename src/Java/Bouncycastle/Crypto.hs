{-# LANGUAGE DataKinds, TypeFamilies, TypeOperators #-}
module Java.Bouncycastle.Crypto where

import Java
import Java.Array
import Java.Math
import Java.Bouncycastle.Types
import Interop.Java.IO
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

foreign import java unsafe "@interface init" initACKPG :: KeyGenerationParameters
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

foreign import java unsafe "@interface init" initBA :: CipherParameters -> Java BasicAgreement ()

-- End org.bouncycastle.crypto.BasicAgreement

-- Start org.bouncycastle.crypto.BlockCipher

foreign import java unsafe "@interface" getAlgorithmName :: Java BlockCipher String

foreign import java unsafe "@interface" getBlockSize :: Java BlockCipher Int

foreign import java unsafe "@interface init" initBC :: Bool -> CipherParameters -> Java BlockCipher ()

foreign import java unsafe "@interface processBlock" processBlockBC :: JByteArray -> Int -> JByteArray -> Int
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

-- Start org.bouncycastle.crypto.DerivationFunction

foreign import java unsafe "@interface" generateBytes :: JByteArray -> Int -> Int -> Java DerivationFunction Int

foreign import java unsafe "@interface init" initDF :: DerivationParameters -> Java DerivationFunction ()

-- End org.bouncycastle.crypto.DerivationFunction

-- Start org.bouncycastle.crypto.Digest

foreign import java unsafe "@interface" doFinal :: JByteArray -> Int -> Java Digest Int

foreign import java unsafe "@interface getAlgorithmNameD" getAlgorithmNameD :: Java Digest String

foreign import java unsafe "@interface" getDigestSize :: Java Digest Int

foreign import java unsafe "@interface" update :: Byte -> Java Digest ()

foreign import java unsafe "@interface update" updateBA :: JByteArray -> Int -> Int -> Java Digest ()

-- End org.bouncycastle.crypto.Digest

-- Start org.bouncycastle.crypto.DigestDerivationFunction

foreign import java unsafe "@interface" getDigest :: Java DigestDerivationFunction Digest

-- End org.bouncycastle.crypto.DigestDerivationFunction

-- Start org.bouncycastle.crypto.DSA

foreign import java unsafe "@interface" generateSignature :: JByteArray -> Java DSA BigIntegerArray

foreign import java unsafe "@interface init" initDSA :: Bool -> CipherParameters -> Java DSA ()

foreign import java unsafe "@interface" verifySignature :: JByteArray -> BigInteger
  -> BigInteger -> Java DSA Bool

-- End org.bouncycastle.crypto.DSA

-- Start org.bouncycastle.crypto.ExtendedDigest

foreign import java unsafe "@interface" getByLength :: Java ExtendedDigest Int

-- End org.bouncycastle.crypto.ExtendedDigest

-- Start org.bouncycastle.crypto.KeyEncapsulation

foreign import java unsafe "@interface" decrypt :: JByteArray -> Int -> Int
  -> Int -> Java KeyEncapsulation CipherParameters

foreign import java unsafe "@interface" encrypt :: JByteArray -> Int -> Int
  -> Java KeyEncapsulation CipherParameters

foreign import java unsafe "@interface init" initKE :: CipherParameters -> Java KeyEncapsulation ()

-- End org.bouncycastle.crypto.KeyEncapsulation

-- Start org.bouncycastle.crypto.KeyEncoder

foreign import java unsafe "@interface" getEncoded :: AsymmetricKeyParameter -> Java KeyEncoder JByteArray

-- End org.bouncycastle.crypto.KeyEncoder

-- Start org.bouncycastle.crypto.KeyParser

foreign import java unsafe "@interface" readKey :: InputStream -> Java KeyParser AsymmetricKeyParameter

-- End org.bouncycastle.crypto.KeyParser

-- Start org.bouncycastle.crypto.Mac

foreign import java unsafe "@interface doFinal" doFinalMac :: JByteArray -> Int -> Java Mac Int

foreign import java unsafe "@interface getAlgorithmName" getAlgorithmNameMac :: Java Mac String

foreign import java unsafe "@interface" getMacSize :: Java Mac Int

foreign import java unsafe "@interface init" initMac :: CipherParameters -> Java Mac ()

foreign import java unsafe "@interface update" updateMac :: Byte -> Java Mac ()

foreign import java unsafe "@interface update" updateArrayMac :: JByteArray -> Int -> Int -> Java Mac ()

-- End org.bouncycastle.crypto.Mac

-- Start org.bouncycastle.crypto.MacDerivationFunction

foreign import java unsafe "@interface" getMac :: Java MacDerivationFunction Mac

-- End org.bouncycastle.crypto.MacDerivationFunction

-- Start org.bouncycastle.crypto.Signer

foreign import java unsafe "@interface generateSignature" generateSignatureS :: Java Signer JByteArray

foreign import java unsafe "@interface init" initS :: Bool -> CipherParameters -> Java Signer ()

foreign import java unsafe "@interface reset" resetS :: Java Signer ()

foreign import java unsafe "@interface update" updateS :: Byte -> Java Signer ()

foreign import java unsafe "@interface update" updateArrayS :: JByteArray -> Int -> Int -> Java Signer ()

foreign import java unsafe "@interface verifySignature" verifySignatureS :: JByteArray -> Java Signer Bool

-- End org.bouncycastle.crypto.Signer

-- Start org.bouncycastle.crypto.SignerWithRecovery

foreign import java unsafe "@interface" getRecoveredMessage :: Java SignerWithRecovery JByteArray

foreign import java unsafe "@interface" hasFullMessage :: Java SignerWithRecovery Bool

foreign import java unsafe "@interface" updateWithRecoveredMessage :: JByteArray -> Java SignerWithRecovery ()

-- End org.bouncycastle.crypto.SignerWithRecovery

-- Start org.bouncycastle.crypto.SkippingCipher

foreign import java unsafe "@interface" getPosition :: Java SkippingCipher Int64

foreign import java unsafe "@interface" seekTo :: Int64 -> Java SkippingCipher Int64

foreign import java unsafe "@interface" skip :: Int64 -> Java SkippingCipher Int64

-- End org.bouncycastle.crypto.SkippingCipher

-- Start org.bouncycastle.crypto.StreamCipher

foreign import java unsafe "@interface getAlgorithmName" getAlgorithmNameStream :: Java StreamCipher String

foreign import java unsafe "@interface init" initSC :: Bool -> CipherParameters -> Java StreamCipher ()

foreign import java unsafe "@interface" processBytes :: JByteArray -> Int -> Int -> JByteArray -> Int
  -> Java StreamCipher Int

foreign import java unsafe "@interface reset" resetStreamC :: Java StreamCipher ()

foreign import java unsafe "@interface" returnByte :: Byte -> Java StreamCipher Byte

-- End org.bouncycastle.crypto.StreamCipher

-- Start org.bouncycastle.crypto.Wrapper

foreign import java unsafe "@interface getAlgorithmName" getAlgorithmNameW :: Java Wrapper String

foreign import java unsafe "@interface init" initW :: Bool -> CipherParameters -> Java Wrapper ()

foreign import java unsafe "@interface" unwrap :: JByteArray -> Int -> Int -> Java Wrapper JByteArray

foreign import java unsafe "@interface" wrap :: JByteArray -> Int -> Int -> Java Wrapper JByteArray

-- End org.bouncycastle.crypto.Wrapper

-- Start org.bouncycastle.crypto.Xof

foreign import java unsafe "@interface doFinal" doFinalXof :: JByteArray -> Int -> Int -> Java Xof Int

foreign import java unsafe "@interface doOutput" doOutputXof :: JByteArray -> Int -> Int -> Java Xof Int

-- End org.bouncycastle.crypto.Xof

-- Start org.bouncycastle.crypto.BufferedAsymmetricBlockCipher

foreign import java unsafe "doFinal" doFinalBABC :: Java BufferedAsymmetricBlockCipher JByteArray

foreign import java unsafe getBufferPosition :: Java BufferedAsymmetricBlockCipher Int

foreign import java unsafe "getInputBlockSize" getInputBlockSizeBABC :: Java BufferedAsymmetricBlockCipher Int

foreign import java unsafe "getOutputBlockSize" getOutputBlockSizeBABC :: Java BufferedAsymmetricBlockCipher Int

foreign import java unsafe getUnderlyingCipher :: Java BufferedAsymmetricBlockCipher AsymmetricBlockCipher

-- End org.bouncycastle.crypto.BufferedAsymmetricBlockCipher

-- Start org.bouncycastle.crypto.BufferedBlockCipher

foreign import java unsafe buf :: Java BufferedAsymmetricBlockCipher JByteArray
