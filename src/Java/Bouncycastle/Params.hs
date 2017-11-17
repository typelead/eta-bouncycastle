{-# LANGUAGE DataKinds, TypeFamilies, TypeOperators #-}
module Java.Bouncycastle.Params where


import Java
import Java.Bouncycastle.Types


-- Start org.bouncycastle.crypto.AsymmetricKeyParameter

foreign import java unsafe isPrivate :: Java AsymmetricKeyParameter Bool

-- End org.bouncycastle.crypto.AsymmetricKeyParameter
