-- |
--
-- Copyright:
-- This file is part of the package sthenauth. It is subject to the
-- license terms in the LICENSE file found in the top-level directory
-- of this distribution and at:
--
-- git://code.devalot.com/sthenauth.git
--
-- No part of this package, including this file, may be copied,
-- modified, propagated, or distributed except according to the terms
-- contained in the LICENSE file.
--
-- License: Apache-2.0
module Sthenauth.Core.Maintenance
  ( Interval (..),
    Task,
    task,
    schedule,
    cancel,
  )
where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (Async)
import qualified Control.Concurrent.Async as Async
import Control.Exception.Safe (tryAnyDeep)
import qualified Data.Aeson as Aeson
import Sthenauth.Core.Logger

-- | How often to execute a task.
data Interval
  = -- | Run /N/ seconds after the last run.
    Seconds Int
  | -- | Run /N/ minutes after last run.
    Minutes Int
  | -- | Run /N/ hours after the last run.
    Hours Int

instance Semigroup Interval where
  (<>) (Seconds x) (Seconds y) = Seconds (x + y)
  (<>) x y =
    Seconds
      ( ( intervalToMicroseconds x
            + intervalToMicroseconds y
        )
          `div` 1_000_000
      )

-- | Convert an 'Interval' into microseconds.
--
-- @since 0.1.0
intervalToMicroseconds :: Interval -> Int
intervalToMicroseconds = \case
  Seconds n -> n * 1_000_000
  Minutes n -> intervalToMicroseconds $ Seconds (n * 60)
  Hours n -> intervalToMicroseconds $ Seconds (n * 60 * 60)

-- | A scheduled task.
data Task = Task
  { taskId :: Async (),
    taskEnv :: MVar (Interval, Logger)
  }

-- | Create a new task that runs the given action.
--
-- @since 0.1.0.0
task :: (Logger -> IO ()) -> IO Task
task action = do
  var <- newEmptyMVar
  thread <- Async.async (go var)
  pure (Task thread var)
  where
    go :: MVar (Interval, Logger) -> IO ()
    go var = do
      (interval, logger) <- takeMVar var
      let ms = intervalToMicroseconds interval
      forever $ do
        threadDelay ms
        tryAnyDeep (action logger) >>= \case
          Right _ -> pass
          Left e ->
            log logger LogError $
              Aeson.object
                [ "error" Aeson..= (show e :: Text)
                ]

-- | Schedule a task.
--
-- @since 0.1.0
schedule :: Interval -> Logger -> Task -> IO ()
schedule interval logger Task {taskEnv} =
  putMVar taskEnv (interval, logger)

-- | FIXME: Write description for cancel
--
-- @since 0.1.0.0
cancel :: Task -> IO ()
cancel Task {taskId} = Async.cancel taskId
