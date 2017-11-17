{-# LANGUAGE DataKinds, TypeFamilies, TypeOperators #-}
module Java.Bouncycastle.Types where

import Java

data AsymmetricBlockCipher = AsymmetricBlockCipher @org.bouncycastle.crypto.AsymmetricBlockCipher
 deriving Class

data CipherParameters = CipherParameters @org.bouncycastle.crypto.CipherParameters
  deriving Class
