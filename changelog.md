# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
(Placeholder for unreleased content)

## [2025-05-16]

* Fix imports with `nodepingpy` 1.1.0
* Remove shebang from module files

## [2024-04-04]

Example corrections and some code refactoring

## [2024-04-01]

### Fixed

Documentation corrected to match functionality and existing test playbooks

### Added

* Create and update checks with `notificationprofile` contacts.

###  Changed

Swithched the dependency to [nodepingpy](https://github.com/NodePing/nodepingpy)


## [2023-07-12]

### Fixed

Checking "changed" status on enabling and muting checks

## [2023-07-10]

### Fixed

Fixed muting/unmuting to match Ansible booleans properly

## [2023-07-07]

### Fixed

Fixed an issue in the nodeping module where updating a check to be enabled or disabled
would not work properly

### Changed

Removed Python 2 support

## [2022-11-16]

### Added

Supports new fields:

* mute
* description
* clientcert
* dohdot
* dnssection
* query
* sshkey
* hosts
* database
* edns
* redistype
* regex
* sentinelname
* servername

You can create muted checks, and mute existing checks. Examples provided for muting checks
and others in the examples directory

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
