# FIXTURE: the PHP version a project declares, read from a Dockerfile.
#
# Every other fixture is code. This one is a declaration: which PHP the image
# is built on. PHP2Shell (CVE-2026-109618 / CVE-2026-109619, 21 Oct 2026) was a
# flaw in PHP itself, so perfect code on PHP 8.2.20 is still exposed.

# A build argument with a default, as most real Dockerfiles spell it.
ARG PHP_VERSION=8.2.20

# EXPECT-SIGNATURE runtime-version
FROM php:${PHP_VERSION}-apache AS app

# Not PHP: never read.
FROM node:20-alpine AS assets

# An out-of-support branch: no official release will fix it.
# EXPECT-SIGNATURE runtime-version
FROM docker.io/library/php:7.4-fpm AS legacy

# A floating branch tag: fixed only if built after the fix was released.
# EXPECT-SIGNATURE runtime-version
FROM php:8.3-cli AS worker

# An earlier stage, not an image - must not be read as one.
FROM app
