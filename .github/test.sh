#!/bin/dash

pip install -e /openedx/requirements/uchileedxlogin

cd /openedx/requirements/uchileedxlogin
cp /openedx/edx-platform/setup.cfg .
mkdir test_root
cd test_root/
ln -s /openedx/staticfiles .

cd /openedx/requirements/uchileedxlogin

pip install pytest-cov genbadge[coverage]
sed -i '/--json-report/c addopts = --nomigrations --reuse-db --durations=20 --json-report --json-report-omit keywords streams collectors log traceback tests --json-report-file=none --cov=uchileedxlogin/ --cov-report term-missing --cov-report xml:reports/coverage/coverage.xml --cov-fail-under 70' setup.cfg

DJANGO_SETTINGS_MODULE=lms.envs.test EDXAPP_TEST_MONGO_HOST=mongodb pytest uchileedxlogin/tests.py

rm -rf test_root

genbadge coverage