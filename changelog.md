# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
(Placeholder for unreleased content)

## [2019-12-11]

### Fixed
- dnstoresolve added to module_args to properly create some DNS checks
- Fixed creating WEBSOCKET checks with the `data` field. The way to utilize the `data` field for the WEBSOCKET check is to use the `websocketdata` argument, since `data` is of type dictionary, and `data` for the WEBSOCKET check requires a string.
