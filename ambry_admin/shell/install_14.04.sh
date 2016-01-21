#!/usr/bin/env bash
# Install from the net with:
# $ sudo sh -c "$(curl -fsSL https://raw.githubusercontent.com/CivicKnowledge/ambry-admin/master/ambry_admin/shell/install_14.04.sh)"


apt-get update

apt-get install -y language-pack-en build-essential
apt-get install -y make gcc wget curl git
apt-get install -y python  python-dev python-pip
apt-get install -y libffi-dev sqlite3  libpq-dev
apt-get install -y libgdal-dev gdal-bin python-gdal python-numpy python-scipy
apt-get install -y libsqlite3-dev libspatialite5 libspatialite-dev spatialite-bin libspatialindex-dev

apt-get clean
apt-get autoremove -y
rm -rf /var/lib/apt/lists/*

# Fixes security warnings in later pip installs. The --ignore-installed bit is requred because some of the
# installed packages already exist, but pip 8 refuses to remove them because they were installed with
# distutils.
pip install --upgrade pip
pip install --ignore-installed requests

export LANGUAGE=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
locale-gen en_US.UTF-8
dpkg-reconfigure locales

groupadd -g 1000  ambry

# This package allows Sqlalchemy to load the spatialite shared object to provide
# Spatialite services.
pip install git+https://github.com/clarinova/pysqlite.git#egg=pysqlite

# Install development version
pip install git+https://github.com/CivicKnowledge/ambry.git@develop

# Development versions
pip install git+https://github.com/CivicKnowledge/ambry_sources.git
pip install git+https://github.com/CivicKnowledge/geoid.git
pip install git+https://github.com/CivicKnowledge/censuslib.git

pip install git+https://github.com/CivicKnowledge/ambry-admin.git
ambry config installcli ambry_admin

pip install git+https://github.com/CivicKnowledge/ambry-ui.git
ambry config installcli ambry_ui
