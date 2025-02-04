# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Added `Realm` entity to manipulate
  all `realm` features (CRUD)

### Added
- Add the `ASTARTE_INSTANCE_ID` env to allow sharing
  the database between multiple Astarte instances.
  Default to `""` to maintain backward compatibility.

### Changed
- Update Elixir to 1.15.7.
- Update Erlang/OTP to 26.1.

## [1.1.1] - 2023-10-03
### Fixed
- Don't crash when retrieving the interface version
  in a device whose introspection is empty.

## [1.1.0] - 2023-06-20

## [1.1.0-rc.0] - 2023-06-08
### Changed
- BREAKING: The library now handles DB connections and
  must be started in a supervision tree.
- Use Xandra as database driver.
- BREAKING: Public functions now accept a realm name as first
  argument instead of a CQEx client.

## [1.1.0-alpha.0] - 2022-11-14

## [1.0.5] - 2022-09-25

## [1.0.4] - 2022-10-24

## [1.0.3] - 2022-07-04

## [1.0.2] - 2022-03-29

## [1.0.1] - 2021-12-16

## [1.0.0] - 2021-06-28

## [1.0.0-rc.0] - 2021-05-05

## [1.0.0-beta.2] - 2021-03-23
### Changed
- Run tests against ScyllaDB 4.4-rc.4 / Cassandra 3.11.10.
- Update dependencies to latest available versions (see `mix.lock` files).
- Update Elixir to 1.11 and OTP to 23.2.

## [1.0.0-beta.1] - 2021-02-12

## [1.0.0-alpha.1] - 2020-06-18
### Changed
- Handle env variables with Skogsra.
- Change env variable ASTARTE_CASSANDRA_NODES into CASSANDRA_NODES

### Added
- Support SSL for Cassandra connections.
- Default max certificate chain length to 10.

## [0.11.4] - 2021-01-25

## [0.11.3] - 2020-09-24

## [0.11.2] - 2020-08-14
### Changed
- Test against Elixir 1.8.2.

## [0.11.1] - 2020-05-18

## [0.11.0] - 2020-04-06

## [0.11.0-rc.1] - 2020-03-25
### Fixed
- Update re2, fixing a compilation problem that prevented applications depending
  from CQEx from starting.

## [0.11.0-rc.0] - 2020-02-26

## [0.11.0-beta.2] - 2020-01-24

## [0.11.0-beta.1] - 2019-12-24
### Changed
- Update requirements to OTP 21.3, Elixir 1.8.1 and Cassandra 3.11.4.
- Fetch mapping database_retention_policy and database_retention_ttl.

## [0.10.2] - 2019-12-09

## [0.10.1] - 2019-10-02

## [0.10.0] - 2019-04-16

## [0.10.0-rc.0] - 2019-04-03

## [0.10.0-beta.3] - 2018-12-19

## [0.10.0-beta.2] - 2018-10-19

## [0.10.0-beta.1] - 2018-08-10
### Added
- First Astarte release.
