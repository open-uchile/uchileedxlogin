#!/bin/dash

pip install -e /openedx/requirements/uchileedxlogin

cd /openedx/requirements/uchileedxlogin
cp /openedx/edx-platform/setup.cfg .
mkdir test_root
cd test_root/
ln -s /openedx/staticfiles .

cd /openedx/requirements/uchileedxlogin

DJANGO_SETTINGS_MODULE=lms.envs.test EDXAPP_TEST_MONGO_HOST=mongodb pytest uchileedxlogin/tests.py
