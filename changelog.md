# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
(Placeholder for unreleased content)

## [2020-07-29]

### Added

A new `nodeping_maintenance` module has been added so you can create new ad-hoc or scheduled
maintenance to disable your checks while you do your work in a maintenance window

## [2020-07-28]

### Changed

Instead fetching from a preconfigured list of check types that can be created, this module now looks at the (required) nodeping-api import and looks at
the different create check functions so as the nodeping-api library is updated, this module does not require modification

## [2020-07-16]
- Fixed an issue with submitting checks with null fields
- Fixed an import issue with Python 2
- Added support for a few check types

## [2019-12-12]
- Fixed updating WEBSOCKET checks with the `data` field. As with creating, using the `websocketdata` argument will update the `data` field for WEBSOCKET checks


## [2019-12-11]

### Fixed
- dnstoresolve added to module_args to properly create some DNS checks
- Fixed creating WEBSOCKET checks with the `data` field. The way to utilize the `data` field for the WEBSOCKET check is to use the `websocketdata` argument, since `data` is of type dictionary, and `data` for the WEBSOCKET check requires a string.
