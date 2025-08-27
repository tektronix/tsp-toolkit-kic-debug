# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!--
Check [Keep a Changelog](http://keepachangelog.com/) for recommendations on how to structure this file.

    Added -- for new features.
    Changed -- for changes in existing functionality.
    Deprecated -- for soon-to-be removed features.
    Removed -- for now removed features.
    Fixed -- for any bug fixes.
    Security -- in case of vulnerabilities.
-->

## [0.16.1]

### Added

- Add `.debug restart` REPL command to restart the debugging session
- Updated to latest version of `tsp-toolkit-kic-lib`
- Connect to instrument using a VISA connection
- Connect to instrument with password

### Fixed

- Fixed issue where the variables pane shows a JSON parse error

## [0.16.0]

### Changed

- Updated to use the 0.19.5 version of `tsp-toolkit-kic-lib`

### Fixed

- Fixed issue in debugging a file with nested functions


## [0.15.3]

### Fixed
- Debugger not hitting breakpoints entered in loops (TSP-633)

## [0.15.1]

### Changed
- **tsp-toolkit-kic-lib:** Clean up instrument connections when an AsyncStream
  stream is dropped

## [0.15.0]

### Added
- If an instrument is set to a non-TSP language (e.g. SCPI), exit with an error
  requesting the user change the language mode.
- Trial License cross-verification

### Fixed
- Fix an issue in which a script name of greater than 27 characters will cause a TTI
  instrument to throw an error when it is loaded. (TSP-613)

## [0.14.1]

### Changed
- Delete debugger source from instrument after loading (TSP-515)

### Added
- Improved license exception handling (TSP-582)

### Fixed
- Add watchpoint and set-variable features are broken (TSP-596)
- Debugger never hits breakpoint (TSP-612)

## [0.13.2]

### Changed
- Update kic-lib version


## [0.13.0]

### Fixed
- Variable pane showing debugger script's variables and functions (TSP-489)
- Fixed issue with fatal error in TTI instruments if a script name is too long (TSP-415)


## [0.12.1]

### Changed
- Modification in calling Instrument login feature.


## [0.11.2]

### Added
- Debugger is implemented


[Unreleased]: https://github.com/TEK-Engineering/tsp-toolkit-kic-debug/compare/v0.16.1...HEAD
[0.16.1]: https://github.com/TEK-Engineering/tsp-toolkit-kic-debug/releases/tag/v0.16.1
[0.16.0]: https://github.com/TEK-Engineering/tsp-toolkit-kic-debug/releases/tag/v0.16.0
[0.15.3]: https://github.com/TEK-Engineering/tsp-toolkit-kic-debug/releases/tag/v0.15.3
[0.15.1]: https://github.com/TEK-Engineering/tsp-toolkit-kic-debug/releases/tag/v0.15.1
[0.15.0]: https://github.com/TEK-Engineering/tsp-toolkit-kic-debug/releases/tag/v0.15.0
[0.14.1]: https://github.com/TEK-Engineering/tsp-toolkit-kic-debug/releases/tag/v0.14.1
[0.13.2]: https://github.com/TEK-Engineering/tsp-toolkit-kic-debug/releases/tag/v0.13.2
[0.13.0]: https://github.com/TEK-Engineering/tsp-toolkit-kic-debug/releases/tag/v0.13.0
[0.12.1]: https://github.com/TEK-Engineering/tsp-toolkit-kic-debug/releases/tag/v0.12.1
[0.11.2]: https://github.com/TEK-Engineering/tsp-toolkit-kic-debug/releases/tag/v0.11.2
