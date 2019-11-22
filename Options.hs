{-|

Copyright:
  This file is part of the package sthenauth. It is subject to the
  license terms in the LICENSE file found in the top-level directory
  of this distribution and at:

    https://code.devalot.com/sthenauth/sthenauth

  No part of this package, including this file, may be copied,
  modified, propagated, or distributed except according to the terms
  contained in the LICENSE file.

License: Apache-2.0

-}
module Sthenauth.Shell.Options
  ( IsCommand(..)
  , Options(..)
  , parse
  ) where

--------------------------------------------------------------------------------
-- Library Imports:
import qualified Data.List as List
import Data.Version (showVersion)
import Options.Applicative
import System.Environment (getEnvironment)

--------------------------------------------------------------------------------
-- Project Imports:
import qualified Paths_sthenauth as Sthenauth

--------------------------------------------------------------------------------
-- | Class for types that can act as a command.
class IsCommand a where
  parseCommand :: Parser a

--------------------------------------------------------------------------------
-- | Global command line options.
data Options a = Options
  { version  :: Bool
  , init     :: Bool
  , migrate  :: Bool
  , config   :: FilePath
  , private  :: FilePath
  , dbconn   :: Maybe String
  , secrets  :: Maybe FilePath
  , site     :: Maybe Text
  , session  :: Maybe Text
  , email    :: Maybe Text
  , password :: Maybe Text
  , command  :: a
  }

--------------------------------------------------------------------------------
-- | Command line parser.
parser :: (IsCommand a) => [(String, String)] -> Parser (Options a)
parser env =
  Options <$> optVersion
          <*> optInit "INIT"
          <*> optMigrate "MIGRATE"
          <*> optConfig "CONFIG"
          <*> optPrivate "PRIVATE_DIR"
          <*> ((Just <$> optDbconn "DB") <|> pure Nothing)
          <*> ((Just <$> optSecrets "SECRETS_PATH") <|> pure Nothing)
          <*> optSite
          <*> optSession
          <*> optional (option str (long "email"    <> hidden))
          <*> optional (option str (long "password" <> hidden))
          <*> parseCommand

  where
    optVersion :: Parser Bool
    optVersion = switch $
      mconcat [ short 'V'
              , long "version"
              , help "Print version info and exit"
              ]

    optInit :: String -> Parser Bool
    optInit key = ((not . null <$> tryEnv key) <|>) $ switch $
      mconcat [ short 'i'
              , long "init"
              , help ("Automatically initialize a new instance" <> also key)
              ]

    optMigrate :: String -> Parser Bool
    optMigrate key = ((not . null <$> tryEnv key) <|>) $ switch $
      mconcat [ short 'm'
              , long "migrate"
              , help ("Allow this instance to run database migrations" <> also key)
              ]

    optConfig :: String -> Parser FilePath
    optConfig key = (tryEnv key <|>) $ strOption $
      mconcat [ short 'c'
              , long "config"
              , metavar "FILE"
              , value "/var/lib/sthenauth/config.dhall"
              , help ("Specify the configuration file to use" <> also key)
              ]

    optPrivate :: String -> Parser FilePath
    optPrivate key = (tryEnv key <|>) $ strOption $
      mconcat [ short 'p'
              , long "private"
              , metavar "DIR"
              , value "/var/lib/sthenauth"
              , help ("Use DIR to store private/secret files" <> also key)
              ]

    optDbconn :: String -> Parser String
    optDbconn key = (tryEnv key <|>) $ strOption $
      mconcat [ long "db"
              , metavar "STR"
              , help ("Use STR as the database connection string" <> also key)
              ]

    optSecrets :: String -> Parser String
    optSecrets key = (tryEnv key <|>) $ strOption $
      mconcat [ long "secrets"
              , metavar "PATH"
              , help ("Load the encryption keys from PATH" <> also key)
              ]

    optSession :: Parser (Maybe Text)
    optSession = optional $ option str $
      mconcat [ long "session"
              , metavar "STR"
              , help "Resume the session given in STR"
              ]

    optSite :: Parser (Maybe Text)
    optSite = optional $ option str $
      mconcat [ long "site"
              , metavar "STR"
              , help "Site FQDN, UUID, or alias FQDN"
              ]

    envPrefix :: String
    envPrefix = "STHENAUTH_"

    tryEnv :: String -> Parser String
    tryEnv key =
      case List.lookup (envPrefix <> key) env of
        Nothing -> empty
        Just v  -> pure v

    also :: String -> String
    also key = " (also " <> envPrefix <> key <> ")"

--------------------------------------------------------------------------------
-- | Execute a command line parser and return the resulting options.
parse :: (IsCommand a) => IO (Options a)
parse = do
  env <- getEnvironment
  options <- execParser (optInfo env)

  when (version options) $ do
    putStrLn (showVersion Sthenauth.version)
    exitSuccess

  pure options

  where
    optInfo :: (IsCommand a) => [(String, String)] -> ParserInfo (Options a)
    optInfo env = info (parser env <**> helper) $
      mconcat [ fullDesc
              , progDesc "Run the sthenauth command COMMAND"
              , header "sthenauth - A micro-service for authentication"
              ]
