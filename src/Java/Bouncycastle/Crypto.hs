{-# LANGUAGE DataKinds, TypeFamilies, TypeOperators #-}
module Java.Bouncycastle.Crypto where

import Java
import Java.Array
import Java.Bouncycastle.Types

-- Start org.bouncycastle.crypto.AsymmetricBlockCipher

foreign import java unsafe "@interface" getInputBlockSize :: Java AsymmetricBlockCipher Int

foreign import java unsafe "@interface" getOutputBlockSize :: Java AsymmetricBlockCipher Int

foreign import java unsafe "@interface" init :: Bool -> CipherParameters -> Java AsymmetricBlockCipher ()

foreign import java unsafe "@interface" processBlock :: JByteArray -> Int -> Int
    -> Java AsymmetricBlockCipher JByteArray

-- End org.bouncycastle.crypto.AsymmetricBlockCipher
