{-|

Copyright:
  This file is part of the package sthenauth. It is subject to the
  license terms in the LICENSE file found in the top-level directory
  of this distribution and at:

    git://code.devalot.com/sthenauth.git

  No part of this package, including this file, may be copied,
  modified, propagated, or distributed except according to the terms
  contained in the LICENSE file.

License: Apache-2.0

-}
module Sthenauth.Core.Policy
  ( Authenticator(..)
  , AssuranceLevel
  , maxSessionDuration
  , maxInactivityDuration
  , primaryAuthenticators
  , secondaryAuthenticators
  , Seconds(..)
  , nominalSeconds
  , addSeconds
  , AccountCreation(..)
  , Policy
  , assuranceLevel
  , minimumPasswordLength
  , jwkExpiresIn
  , oidcPartialExpiresIn
  , accountCreation
  , maxSessionsPerAccount
  , aal1
  , aal2
  , aal3
  , checkPolicy
  , checkAssuranceLevel
  , defaultPolicy
  , sessionExpire
  , sessionInactive
  , openLocalAccountCreation
  , assertPolicyRules
  , zxcvbnConfig
  ) where

--------------------------------------------------------------------------------
-- Imports:
import Control.Lens.TH (makeLenses)
import qualified Data.Aeson as Aeson
import qualified Data.List.NonEmpty as NonEmpty
import qualified Data.Map as Map
import Data.Time.Clock
import Iolaus.Database.JSON (liftJSON)
import Iolaus.Validation
import Sthenauth.Core.Error
import qualified Text.Password.Strength as Zxcvbn
import qualified Text.Password.Strength.Config as Zxcvbn

--------------------------------------------------------------------------------
-- | NIST 800-63B authenticator types.  Section 5.1.
data Authenticator
  = MemorizedSecret
    -- ^ Memorized secrete (password, PIN).  Section 5.1.1.

  | LookUpSecret
    -- ^ Something the user is in possession of (e.g., a recovery
    -- code).  Section  5.1.2.

  | OutOfBand
    -- ^ Secondary channel authentication device.  Section 5.1.3.

  | SingleFactorOTPSoftware
    -- ^ Software One Time Password (OTP) generator.  Section 5.1.4.

  | SingleFactorOTPHardware
    -- ^ One Time Password (OTP) generator.  Section 5.1.4.

  | MultiFactorOTPSoftware
    -- ^ Similar to a 'SingleFactorOTPSoftware', with the additional
    -- requirement that in order to operate the software you must
    -- authenticate to it using a password or biometric.  Section
    -- 5.1.5.

  | MultiFactorOTPHardware
    -- ^ Similar to a 'SingleFactorOTPHardware', with the additional
    -- requirement that in order to operate the device you must
    -- authenticate to it using a password or biometric.  Section
    -- 5.1.5.

  | SingleFactorCryptoSoftware
    -- ^ A cryptographic key that you can prove you are in control
    -- of.  Section 5.1.6.

  | MultiFactorCryptoSoftware
    -- ^ Similar to 'SingleFactorCryptoSoftware', with the additional
    -- requirement that the user must authenticate with the
    -- device/software using a second factor.  Section 5.1.8.

  | SingleFactorCryptoHardware
    -- ^ A hardware device that can directly communicate with the user
    -- endpoint and prove the user is in control of the device.
    -- Section 5.1.7.

  | MultiFactorCryptoHardware
    -- ^ Similar to 'SingleFactorCryptoHardware' with the additional
    -- requirement that the user must authenticate with the device
    -- using a second factor.  Section 5.1.9.

  | CryptoSoftwareAndPassword
    -- ^ Requires both 'SingleFactorCryptoSoftware' and
    -- 'MemorizedSecret'.  Needed in order to support AAL3.

  deriving (Generic, Show, Eq, Ord, Enum, Bounded, ToJSON, FromJSON)

--------------------------------------------------------------------------------
instance ToJSONKey Authenticator where
  toJSONKey = Aeson.genericToJSONKey Aeson.defaultJSONKeyOptions

instance FromJSONKey Authenticator where
  fromJSONKey = Aeson.genericFromJSONKey Aeson.defaultJSONKeyOptions

--------------------------------------------------------------------------------
-- | Simple wrapper to represent some number of seconds.
newtype Seconds = Seconds { getSeconds :: Int64 }
  deriving (Generic, Show, Eq, Ord)

instance ToJSON Seconds where
  toJSON = toJSON . getSeconds
  toEncoding = toEncoding . getSeconds

instance FromJSON Seconds where
  parseJSON = fmap Seconds . parseJSON

--------------------------------------------------------------------------------
-- | Convert 'Seconds' to 'NominalDiffTime'.
nominalSeconds :: Seconds -> NominalDiffTime
nominalSeconds = fromIntegral . getSeconds

--------------------------------------------------------------------------------
-- | Add some 'Seconds' to a 'UTCTime'.
addSeconds :: Seconds -> UTCTime -> UTCTime
addSeconds s = addUTCTime (nominalSeconds s)

--------------------------------------------------------------------------------
-- | Settings that affect the level of certainty that the system is
-- interacting with the account owned by the current user.
data AssuranceLevel = AssuranceLevel
  { _maxSessionDuration :: Seconds
    -- ^ Maximum number of seconds that a user may have a session
    -- before being asked to reauthenticate.

  , _maxInactivityDuration :: Seconds
    -- ^ Maximum number of seconds that a user may be inactive before
    -- being logged out automatically.

  , _primaryAuthenticators :: NonEmpty Authenticator
    -- ^ Authenticators that can be used to initiate a log in process.

  , _secondaryAuthenticators :: Map Authenticator (NonEmpty Authenticator)
    -- ^ Secondary authenticators that may be required in order to
    -- log in.
    --
    -- The primary authenticator is looked up in this map.  If it
    -- exists, then one of the listed authenticators must be used in
    -- order to finish the log in process.
    --
    -- Keys in this table are automatically added to the primary
    -- authenticators list so the user can start with a secondary
    -- authenticator and end with a primary authenticator as well.

  }
  deriving (Generic, Show)
  deriving (ToJSON, FromJSON) via GenericJSON AssuranceLevel

makeLenses ''AssuranceLevel

--------------------------------------------------------------------------------
-- | Policy for how accounts can be created.
data AccountCreation
  = AdminInvitation
    -- ^ An administrator must invite a user to sign up.

  | SelfService
    -- ^ A user may create an account or log in via OIDC.

  | OnlyFromOIDC
    -- ^ Local accounts are forbidden but users can log in with OIDC.

  deriving (Generic, Show, Eq, Ord, Enum, Bounded, ToJSON, FromJSON)

--------------------------------------------------------------------------------
-- | Settings and security policy for a site.
data Policy = Policy
  { _assuranceLevel :: AssuranceLevel
    -- ^ The Authenticator Assurance Level (AAL).

  , _minimumPasswordLength :: Int
    -- ^ Minimum number of characters allowed in a password.

  , _jwkExpiresIn :: Seconds
    -- ^ Number of seconds before a new JWK expires.

  , _oidcPartialExpiresIn :: Seconds
    -- ^ Number of seconds before a partial (in-progress) OIDC
    -- connection is expired.

  , _accountCreation :: AccountCreation
    -- ^ Policy for how new accounts are created.

  , _maxSessionsPerAccount :: Int64
    -- ^ Maximum number of allowed sessions for a single account.

  }
  deriving (Generic, Show)
  deriving (ToJSON, FromJSON) via GenericJSON Policy

makeLenses ''Policy
liftJSON ''Policy

--------------------------------------------------------------------------------
-- | NIST 800-63B Authenticator Assurance Level 1.
aal1 :: AssuranceLevel
aal1 = AssuranceLevel
  { _maxSessionDuration  = Seconds (30 * 24 * 60 * 60) -- 30 days.
  , _maxInactivityDuration = Seconds (30 * 24 * 60 * 60) -- 30 days.
  , _primaryAuthenticators = NonEmpty.fromList universe
  , _secondaryAuthenticators = Map.empty
  }

--------------------------------------------------------------------------------
-- | NIST 800-63B Authenticator Assurance Level 2.
aal2 :: AssuranceLevel
aal2 = AssuranceLevel
  { _maxSessionDuration = Seconds (12 * 60 * 60) -- 12 hours.
  , _maxInactivityDuration = Seconds (30 * 60) -- 30 minutes.

  , _primaryAuthenticators = NonEmpty.fromList
      [ MultiFactorOTPHardware
      , MultiFactorOTPSoftware
      , MultiFactorCryptoSoftware
      , MultiFactorCryptoHardware
      , MemorizedSecret
      ]

  , _secondaryAuthenticators = Map.fromList
      [ ( MemorizedSecret
        , NonEmpty.fromList
            [ LookUpSecret
            , OutOfBand
            , SingleFactorOTPSoftware
            , SingleFactorOTPHardware
            , SingleFactorCryptoHardware
            ]
        )
      ]
  }

--------------------------------------------------------------------------------
-- | NIST 800-63B Authenticator Assurance Level 3.
aal3 :: AssuranceLevel
aal3 = AssuranceLevel
  { _maxSessionDuration = Seconds (12 * 60 * 60) -- 12 hours.
  , _maxInactivityDuration = Seconds (15 * 60) -- 15 minutes.

  , _primaryAuthenticators = NonEmpty.fromList
      [ MultiFactorCryptoHardware
      , SingleFactorCryptoHardware
      , MultiFactorOTPHardware
      , MultiFactorOTPSoftware
      , SingleFactorOTPHardware
      ]

  , _secondaryAuthenticators = Map.fromList
      [ ( SingleFactorCryptoHardware
        , NonEmpty.fromList
           [ MemorizedSecret
           , MultiFactorOTPHardware
           , MultiFactorOTPSoftware
           ]
        )
      , ( MultiFactorOTPHardware
        , NonEmpty.fromList
            [ SingleFactorCryptoHardware
            ]
        )
      , ( MultiFactorOTPSoftware
        , NonEmpty.fromList
            [ SingleFactorCryptoHardware
            ]
        )
      , ( SingleFactorOTPHardware
        , NonEmpty.fromList
            [ MultiFactorCryptoSoftware
            , CryptoSoftwareAndPassword
            ]
        )
      ]
  }

--------------------------------------------------------------------------------
-- | 'Policy' validation.
checkPolicy :: (Applicative m) => ValidT m Policy
checkPolicy = Policy
  <$> _assuranceLevel .: checkAssuranceLevel <?> "assurance_level"
  <*> _minimumPasswordLength .: minInt 4 <?> "minimum_password_length"
  <*> (Seconds <$> (getSeconds . _jwkExpiresIn) .: minInt 300 <?> "jwk_expires_in")
  <*> (Seconds <$> (getSeconds . _oidcPartialExpiresIn) .: intRange 120 1800 <?> "oidc_partial_expires_in")
  <*> _accountCreation .: passthru <?> "account_creation"
  <*> _maxSessionsPerAccount .: intRange 1 100 <?> "max_sessions_per_account"

--------------------------------------------------------------------------------
-- | 'AssuranceLevel' validation.
checkAssuranceLevel :: (Applicative m) => ValidT m AssuranceLevel
checkAssuranceLevel = AssuranceLevel
  <$> (Seconds <$> (getSeconds . _maxSessionDuration) .: minInt 300 <?> "max_session_duration")
  <*> (Seconds <$> (getSeconds . _maxInactivityDuration) .: minInt 60 <?> "max_inactivity_duration")
  <*> _primaryAuthenticators .: passthru <?> "primary_authenticators"
  <*> _secondaryAuthenticators .: passthru <?> "secondary_authenticators"

--------------------------------------------------------------------------------
-- | The default policy used for new sites.
defaultPolicy :: Policy
defaultPolicy = Policy
  { _assuranceLevel = aal1
  , _minimumPasswordLength = 6
  , _jwkExpiresIn = Seconds (24 * 60 * 60) -- 24 hours.
  , _oidcPartialExpiresIn = Seconds (5 * 60) -- 5 minutes.
  , _accountCreation = AdminInvitation
  , _maxSessionsPerAccount = 25
  }

--------------------------------------------------------------------------------
-- | Calculate when a session should expire.
sessionExpire :: Policy -> UTCTime -> UTCTime
sessionExpire p = addSeconds (p ^. (assuranceLevel.maxSessionDuration))

--------------------------------------------------------------------------------
-- | Calculate when a session should be marked inactive.
sessionInactive :: Policy -> UTCTime -> UTCTime
sessionInactive p = addSeconds (p ^. (assuranceLevel.maxInactivityDuration))

--------------------------------------------------------------------------------
-- | True if the policy allows users to create their own local accounts.
openLocalAccountCreation :: Policy -> Bool
openLocalAccountCreation p =
  case p ^. accountCreation of
   AdminInvitation -> False
   SelfService     -> True
   OnlyFromOIDC    -> False

--------------------------------------------------------------------------------
-- | Evaluate the given policy rules and abort if any of them fail.
assertPolicyRules
  :: Has Error sig m
  => Policy -> [Policy -> Bool] -> m ()
assertPolicyRules policy rules =
  unless (all ($ policy) rules) (throwUserError PermissionDenied)

--------------------------------------------------------------------------------
-- | Access the zxcvbn configuration.
zxcvbnConfig :: Policy -> Zxcvbn.Config
zxcvbnConfig _ = Zxcvbn.en_US -- FIXME: actually calculate this.
