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
        self.assertEqual(request.netloc, settings.HOST.replace('http://','') + ':9513')
        self.assertEqual(request.path, '/login')        
        self.assertEqual(args['service'][0], settings.SERVICE)

    def test_redirect_already_logged(self):
        user = User.objects.create_user(username='testuser', password='123')
        self.client.login(username='testuser', password='123')
        result = self.client.get(reverse('uchileedxlogin-login:login'))
        request = urlparse.urlparse(result.url)
        self.assertEqual(request.path, '/')


def create_user(user_data):
    return User.objects.create_user(
        username=user_data['username'],
        email=user_data['email'])

def mocked_requests_get(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data
    if args[0] == settings.RESULT_VALIDATE + '?ticket=test&service=callback':
        return MockResponse({"content":'yes\nfelipe.espinoza.r\n'}, 302)
    elif args[0] == settings.USER_INFO_URL + '?username=felipe.espinoza.r':
        return MockResponse({"apellidoPaterno":"ESPINOZA","apellidoMaterno":"ROSALES","nombres":"FELIPE ALEJANDRO","nombreCompleto":"FELIPE ALEJANDRO ESPINOZA ROSALES","rut":"0187658322"}, 302)

    return MockResponse(None, 404)

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

    @patch('requests.get', side_effect=mocked_requests_get)
    def test_login_parameters(self, mock_get):
        # Assert requests.get calls
        mgc = EdxLoginCallback()

        json_data = mgc.fetch_json(settings.RESULT_VALIDATE + '?ticket=test&service=callback')
        self.assertEqual(json_data, {"content":'yes\nfelipe.espinoza.r\n'})

        json_data = mgc.fetch_json(settings.USER_INFO_URL + '?username=felipe.espinoza.r')
        self.assertEqual(json_data, {"apellidoPaterno":"ESPINOZA","apellidoMaterno":"ROSALES","nombres":"FELIPE ALEJANDRO","nombreCompleto":"FELIPE ALEJANDRO ESPINOZA ROSALES","rut":"0187658322"})
        
    @patch('requests.get', side_effect=mocked_requests_get)
    def test_login_wrong_ticket(self, mock_get):
        # Assert requests.get calls
        mgc = EdxLoginCallback()

        json_data = mgc.fetch_json(settings.RESULT_VALIDATE + '?ticket=wrongticket&service=callback')
        self.assertEqual(json_data, None)        

    @patch('requests.get', side_effect=mocked_requests_get)
    def test_login_wrong_service(self, mock_get):
        # Assert requests.get calls
        mgc = EdxLoginCallback()

        json_data = mgc.fetch_json(settings.RESULT_VALIDATE + '?ticket=test&service=wrongcallback')
        self.assertEqual(json_data, None)        
       
    @patch('requests.get', side_effect=mocked_requests_get)
    def test_login_wrong_username(self, mock_get):
        mgc = EdxLoginCallback()

        json_data = mgc.fetch_json(settings.RESULT_VALIDATE + '?ticket=test&service=callback')
        self.assertEqual(json_data, {"content":'yes\nfelipe.espinoza.r\n'})

        json_data = mgc.fetch_json(settings.USER_INFO_URL + '?username=None')
        self.assertEqual(json_data, None)
