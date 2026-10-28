# FIXTURE: a PHP image with every fix Defuse's table knows of.
# EXPECT-NONE
FROM php:8.4.27-apache
COPY . /var/www/html
