from mock import patch, Mock, MagicMock
from collections import namedtuple
from django.urls import reverse
from django.test import TestCase, Client
from django.test import Client
from django.conf import settings
from django.contrib.auth.models import User
from urlparse import parse_qs

from opaque_keys.edx.locator import CourseLocator

import json
import urlparse

from .views import EdxLoginLoginRedirect, EdxLoginCallback

# Create your tests here.
class TestRedirectView(TestCase):

    def setUp(self):
        self.client = Client()

    def test_set_session(self):
        result = self.client.get(reverse('uchileedxlogin-login:login'))
        self.assertEqual(result.status_code, 302)

    def test_return_request(self):
        result = self.client.get(reverse('uchileedxlogin-login:login'))
        request = urlparse.urlparse(result.url)
        args = urlparse.parse_qs(request.query)

        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.netloc, '172.25.14.6:9513')
        self.assertEqual(request.path, '/login')        
        self.assertEqual(args['service'][0], 'http://testserver/uchileedxlogin/callback/')

    def test_redirect_already_logged(self):
        user = User.objects.create_user(username='testuser', password='123')
        self.client.login(username='testuser', password='123')
        result = self.client.get(reverse('uchileedxlogin-login:login'))
        request = urlparse.urlparse(result.url)
        self.assertEqual(request.path, '/')


def create_user(user_data):
    return User.objects.create_user(
        username=user_data['username'].replace('.','_'),
        email=user_data['email'])

class TestCallbackView(TestCase):
    def setUp(self):
        self.client = Client()
        result = self.client.get(reverse('uchileedxlogin-login:login'))

        self.modules = {
            'student': MagicMock(),
            'student.forms': MagicMock(),
            'student.helpers': MagicMock(),
            'student.models': MagicMock(),
        }
        self.module_patcher = patch.dict('sys.modules', self.modules)
        self.module_patcher.start()

    def tearDown(self):
        self.module_patcher.stop()

    @patch('requests.post')
    @patch('requests.get')
    def test_login_parameters(self, get, post):
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request", ["status_code", "content"])(200, 'yes\ntest.name\n'), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"apellidoPaterno":"TESTLASTNAME","apellidoMaterno":"TESTLASTNAME","nombres":"TEST.NAME","nombreCompleto":"TEST.NAME TESTLASTNAME TESTLASTNAME","rut":"0112223334"}))]
        post.side_effect = [namedtuple("Request", ["status_code", "text"])(200, json.dumps({"usuarioLdap":{"mail":"test@test.test"}}))]

        result = self.client.get(reverse('uchileedxlogin-login:callback'), data={'ticket': 'testticket'})
        self.assertEqual(result.status_code, 302)

        username = parse_qs(get.call_args_list[1][1]['params'])
        self.assertEqual(get.call_args_list[0][0][0], settings.EDXLOGIN_RESULT_VALIDATE)
        self.assertEqual(username['username'][0], 'test.name')
        self.assertEqual(get.call_args_list[1][0][0], settings.EDXLOGIN_USER_INFO_URL)
    
    @patch("uchileedxlogin.views.EdxLoginCallback.create_user_by_data", side_effect=create_user)
    @patch('requests.post')
    @patch('requests.get')
    def test_login_create_user(self, get, post, mock_created_user):
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request", ["status_code", "content"])(200, 'yes\ntest.name\n'), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"apellidoPaterno":"TESTLASTNAME","apellidoMaterno":"TESTLASTNAME","nombres":"TEST.NAME","nombreCompleto":"TEST.NAME TESTLASTNAME TESTLASTNAME","rut":"0112223334"}))]
        post.side_effect = [namedtuple("Request", ["status_code", "text"])(200, json.dumps({"usuarioLdap":{"mail":"test@test.test"}}))]

        result = self.client.get(reverse('uchileedxlogin-login:callback'), data={'ticket': 'testticket'})
        self.assertEqual(mock_created_user.call_args_list[0][0][0], {'username': 'test.name', 'apellidoMaterno': 'TESTLASTNAME', 'nombres': 'TEST.NAME', 'apellidoPaterno': 'TESTLASTNAME', 'nombreCompleto': 'TEST.NAME TESTLASTNAME TESTLASTNAME', 'rut': '0112223334'})

    @patch('requests.post')
    @patch('requests.get')
    def test_login_wrong_ticket(self, get, post):
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request", ["status_code", "content"])(200, 'no\n\n'), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"apellidoPaterno":"TESTLASTNAME","apellidoMaterno":"TESTLASTNAME","nombres":"TEST.NAME","nombreCompleto":"TEST.NAME TESTLASTNAME TESTLASTNAME","rut":"0112223334"}))]
        post.side_effect = [namedtuple("Request", ["status_code", "text"])(200, json.dumps({"usuarioLdap":{"mail":"test@test.test"}}))]

        result = self.client.get(reverse('uchileedxlogin-login:callback'), data={'ticket': 'wrongticket'})
        request = urlparse.urlparse(result.url)
        self.assertEqual(request.path, '/uchileedxlogin/login/')

    @patch('requests.post')
    @patch('requests.get')
    def test_login_wrong_username(self, get, post):
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request", ["status_code", "content"])(200, 'yes\nwrongname\n'), namedtuple("Request", ["status_code", "text"])(200, json.dumps({}))]
        post.side_effect = [namedtuple("Request", ["status_code", "text"])(200, json.dumps({"usuarioLdap":{"mail":"test@test.test"}}))]

        result = self.client.get(reverse('uchileedxlogin-login:callback'), data={'ticket': 'testticket'})
        request = urlparse.urlparse(result.url)
        self.assertEqual(request.path, '/uchileedxlogin/login/')