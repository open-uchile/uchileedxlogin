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

from .views import EdxLoginLoginRedirect, EdxLoginCallback, EdxLoginStaff
from .models import EdxLoginUserCourseRegistration
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
        self.assertEqual(request.netloc, '172.25.14.64:9513')
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
        username=EdxLoginCallback().generate_username(user_data),
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

    @patch('requests.get')
    def test_login_parameters(self, get):
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request", ["status_code", "content"])(200, 'yes\ntest.name\n'), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"apellidoPaterno":"TESTLASTNAME","apellidoMaterno":"TESTLASTNAME","nombres":"TEST.NAME","nombreCompleto":"TEST.NAME TESTLASTNAME TESTLASTNAME","rut":"0112223334"})), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"emails":[{"rut":"0112223334", "email":"test@test.test", "codigoTipoEmail": "1", "nombreTipoEmail": "PRINCIPAL", "fechaRegistro": 1331157396000}]}))]
        
        result = self.client.get(reverse('uchileedxlogin-login:callback'), data={'ticket': 'testticket'})
        self.assertEqual(result.status_code, 302)

        username = parse_qs(get.call_args_list[1][1]['params'])
        self.assertEqual(get.call_args_list[0][0][0], settings.EDXLOGIN_RESULT_VALIDATE)
        self.assertEqual(username['username'][0], 'test.name')
        self.assertEqual(get.call_args_list[1][0][0], settings.EDXLOGIN_USER_INFO_URL)
        self.assertEqual(get.call_args_list[2][0][0], settings.EDXLOGIN_USER_EMAIL + "0112223334" + '/emails')
    
    @patch("uchileedxlogin.views.EdxLoginCallback.create_user_by_data", side_effect=create_user)    
    @patch('requests.get')
    def test_login_create_user(self, get, mock_created_user):
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request", ["status_code", "content"])(200, 'yes\ntest.name\n'), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"apellidoPaterno":"TESTLASTNAME","apellidoMaterno":"TESTLASTNAME","nombres":"TEST NAME","nombreCompleto":"TEST NAME TESTLASTNAME TESTLASTNAME","rut":"0112223334"})), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"emails":[{"rut":"0112223334", "email":"test@test.test", "codigoTipoEmail": "1", "nombreTipoEmail": "PRINCIPAL", "fechaRegistro": 1331157396000}]}))]
        
        result = self.client.get(reverse('uchileedxlogin-login:callback'), data={'ticket': 'testticket'})
        self.assertEqual(mock_created_user.call_args_list[0][0][0], {'username': 'test.name', 'apellidoMaterno': 'TESTLASTNAME', 'nombres': 'TEST NAME', 'apellidoPaterno': 'TESTLASTNAME', 'nombreCompleto': 'TEST NAME TESTLASTNAME TESTLASTNAME', 'rut': '0112223334', 'email': 'test@test.test'})

    @patch("uchileedxlogin.views.EdxLoginCallback.create_user_by_data", side_effect=create_user)    
    @patch('requests.get')
    def test_login_create_user_no_email(self, get, mock_created_user):
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request", ["status_code", "content"])(200, 'yes\ntest.name\n'), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"apellidoPaterno":"TESTLASTNAME","apellidoMaterno":"TESTLASTNAME","nombres":"TEST NAME","nombreCompleto":"TEST NAME TESTLASTNAME TESTLASTNAME","rut":"0112223334"})), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"emails":[{"rut":"0112223334", "email":"test@test.test", "codigoTipoEmail": "2", "nombreTipoEmail": "ALTERNATIVO", "fechaRegistro": 1331157396000}]}))]
        
        result = self.client.get(reverse('uchileedxlogin-login:callback'), data={'ticket': 'testticket'})
        self.assertEqual(mock_created_user.call_args_list[0][0][0], {'username': 'test.name', 'apellidoMaterno': 'TESTLASTNAME', 'nombres': 'TEST NAME', 'apellidoPaterno': 'TESTLASTNAME', 'nombreCompleto': 'TEST NAME TESTLASTNAME TESTLASTNAME', 'rut': '0112223334', 'email': 'null'})

    @patch('requests.get')
    def test_login_wrong_ticket(self, get):
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request", ["status_code", "content"])(200, 'no\n\n'), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"apellidoPaterno":"TESTLASTNAME","apellidoMaterno":"TESTLASTNAME","nombres":"TEST NAME","nombreCompleto":"TEST NAME TESTLASTNAME TESTLASTNAME","rut":"0112223334"})), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"emails":[{"rut":"0112223334", "email":"test@test.test", "codigoTipoEmail": "1", "nombreTipoEmail": "PRINCIPAL", "fechaRegistro": 1331157396000}]}))]
        
        result = self.client.get(reverse('uchileedxlogin-login:callback'), data={'ticket': 'wrongticket'})
        request = urlparse.urlparse(result.url)
        self.assertEqual(request.path, '/uchileedxlogin/login/')
   
    @patch('requests.get')
    def test_login_wrong_username(self, get):
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request", ["status_code", "content"])(200, 'yes\nwrongname\n'), namedtuple("Request", ["status_code", "text"])(200, json.dumps({}))]
        
        result = self.client.get(reverse('uchileedxlogin-login:callback'), data={'ticket': 'testticket'})
        request = urlparse.urlparse(result.url)
        self.assertEqual(request.path, '/uchileedxlogin/login/')
    
    @patch("uchileedxlogin.views.EdxLoginCallback.create_user_by_data", side_effect=create_user)
    def test_generate_username(self, _):
        data = {
            'username': 'test.name', 
            'apellidoMaterno': 'dd', 
            'nombres': 'aa bb', 
            'apellidoPaterno': 'cc', 
            'nombreCompleto': 'aa bb cc dd', 
            'rut': '0112223334',
            'email': 'test@test.test'
        }        
        self.assertEqual(EdxLoginCallback().create_user_by_data(data).username, 'aa_cc')
        self.assertEqual(EdxLoginCallback().create_user_by_data(data).username, 'aa_cc_d')
        self.assertEqual(EdxLoginCallback().create_user_by_data(data).username, 'aa_cc_dd')
        self.assertEqual(EdxLoginCallback().create_user_by_data(data).username, 'aa_b_cc')
        self.assertEqual(EdxLoginCallback().create_user_by_data(data).username, 'aa_bb_cc')
        self.assertEqual(EdxLoginCallback().create_user_by_data(data).username, 'aa_b_cc_d')
        self.assertEqual(EdxLoginCallback().create_user_by_data(data).username, 'aa_b_cc_dd')
        self.assertEqual(EdxLoginCallback().create_user_by_data(data).username, 'aa_bb_cc_d')
        self.assertEqual(EdxLoginCallback().create_user_by_data(data).username, 'aa_bb_cc_dd')
        self.assertEqual(EdxLoginCallback().create_user_by_data(data).username, 'aa_cc1')
        self.assertEqual(EdxLoginCallback().create_user_by_data(data).username, 'aa_cc2')

    @patch("uchileedxlogin.views.EdxLoginCallback.create_user_by_data", side_effect=create_user)
    def test_long_name(self, _):
        data = {
            'username': 'test.name', 
            'apellidoMaterno': 'ff', 
            'nombres': 'a2345678901234567890123 bb', 
            'apellidoPaterno': '4567890', 
            'nombreCompleto': 'a2345678901234567890123 bb 4567890 ff', 
            'rut': '0112223334',
            'email': 'test@test.test'
        }
        
        self.assertEqual(EdxLoginCallback().create_user_by_data(data).username, 'a2345678901234567890123_41')

    @patch("uchileedxlogin.views.EdxLoginCallback.create_user_by_data", side_effect=create_user)
    def test_long_name_middle(self, _):
        data = {
            'username': 'test.name', 
            'apellidoMaterno': 'ff', 
            'nombres': 'a23456789012345678901234 bb', 
            'apellidoPaterno': '4567890', 
            'nombreCompleto': 'a23456789012345678901234 bb 4567890 ff', 
            'rut': '0112223334',
            'email': 'test@test.test'
        }
        self.assertEqual(EdxLoginCallback().create_user_by_data(data).username, 'a234567890123456789012341')
    
    @patch("uchileedxlogin.views.EdxLoginCallback.create_user_by_data", side_effect=create_user)   
    @patch('requests.get')
    def test_test(self, get, _):
        EdxLoginUserCourseRegistration.objects.create(
            run='0112223334',           
            course="course-v1:test+TEST+2019-2",
            mode="honor",
            auto_enroll=True)
        EdxLoginUserCourseRegistration.objects.create(
            run='0112223334',            
            course="course-v1:test+TEST+2019-4",
            mode="honor",
            auto_enroll=False)
        
        get.side_effect = [namedtuple("Request", ["status_code", "content"])(200, 'yes\ntest.name\n'), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"apellidoPaterno":"TESTLASTNAME","apellidoMaterno":"TESTLASTNAME","nombres":"TEST.NAME","nombreCompleto":"TEST.NAME TESTLASTNAME TESTLASTNAME","rut":"0112223334"})), namedtuple("Request", ["status_code", "text"])(200, json.dumps({"emails":[{"rut":"0112223334", "email":"test@test.test", "codigoTipoEmail": "1", "nombreTipoEmail": "PRINCIPAL", "fechaRegistro": 1331157396000}]}))]
        result = self.client.get(reverse('uchileedxlogin-login:callback'), data={'ticket': 'testticket'})
    
        self.assertEqual(EdxLoginUserCourseRegistration.objects.count(), 0)
        self.assertEqual(self.modules['student.models'].CourseEnrollment.method_calls[0][1][1], CourseLocator.from_string("course-v1:test+TEST+2019-2"))
        _, _, kwargs = self.modules['student.models'].CourseEnrollmentAllowed.mock_calls[0]
        self.assertEqual(kwargs['course_id'], CourseLocator.from_string("course-v1:test+TEST+2019-4"))

def always_true(x):
    return True

class TestStaffView(TestCase):

    def setUp(self):
        self.client = Client()
        user = User.objects.create_user(username='testuser', password='12345')
        user.is_staff = True
        user.save()
        self.client.login(username='testuser', password='12345')

        result = self.client.get(reverse('uchileedxlogin-login:staff'))

    def test_staff_get(self):

        response = self.client.get(reverse('uchileedxlogin-login:staff'))
        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'edxlogin/staff.html')

    @patch("uchileedxlogin.views.EdxLoginStaff.validate_course", side_effect=always_true)
    def test_staff_post(self, _):
        post_data = {
            'runs': '10-8',
            'course': 'course-v1:mss+MSS001+2019_2',
            'modes': 'audit',
            'enroll': '1'
        }

        response = self.client.post(reverse('uchileedxlogin-login:staff'), post_data)
        self.assertEquals(response.status_code, 200)

        aux = EdxLoginUserCourseRegistration.objects.get(run="0000000108")

        self.assertEqual(aux.run, "0000000108")        
        self.assertEqual(aux.mode, 'audit')
        self.assertEqual(aux.auto_enroll, True)
        self.assertEquals(EdxLoginUserCourseRegistration.objects.all().count(), 1)

    @patch("uchileedxlogin.views.EdxLoginStaff.validate_course", side_effect=always_true)
    def test_staff_post_multiple_run(self, _):
        post_data = {
            'runs': '10-8\n10-8\n10-8\n10-8\n10-8',            
            'course': 'course-v1:mss+MSS001+2019_2',
            'modes': 'audit',
            'enroll': '1'
        }

        response = self.client.post(reverse('uchileedxlogin-login:staff'), post_data)
        self.assertEquals(response.status_code, 200)

        aux = EdxLoginUserCourseRegistration.objects.filter(run="0000000108")
        for var in aux:
            self.assertEqual(var.run, "0000000108")
            self.assertEqual(var.mode, 'audit')
            self.assertEqual(var.auto_enroll, True)

        self.assertEquals(EdxLoginUserCourseRegistration.objects.all().count(), 5)

    @patch("uchileedxlogin.views.EdxLoginStaff.validate_course", side_effect=always_true)
    def test_staff_post_sin_curso(self, _):
        post_data = {
            'runs': '10-8',           
            'course': '',
            'modes': 'audit',
            'enroll': '1'
        }

        response = self.client.post(reverse('uchileedxlogin-login:staff'), post_data)
        self.assertEquals(response.status_code, 200)
        self.assertEqual(response.context['curso2'], '')
        self.assertEquals(EdxLoginUserCourseRegistration.objects.all().count(), 0)

    @patch("uchileedxlogin.views.EdxLoginStaff.validate_course", side_effect=always_true)
    def test_staff_post_sin_run(self, _):
        post_data = {
            'runs': '',           
            'course': 'course-v1:mss+MSS001+2019_2',
            'modes': 'audit',
            'enroll': '1'
        }

        response = self.client.post(reverse('uchileedxlogin-login:staff'), post_data)
        self.assertEquals(response.status_code, 200)
        self.assertEqual(response.context['no_run'], '')
        self.assertEquals(EdxLoginUserCourseRegistration.objects.all().count(), 0)

    @patch("uchileedxlogin.views.EdxLoginStaff.validate_course", side_effect=always_true)
    def test_staff_post_run_malo(self, _):
        post_data = {
            'runs': '12345678-9',            
            'course': 'course-v1:mss+MSS001+2019_2',
            'modes': 'audit',
            'enroll': '1'
        }

        response = self.client.post(reverse('uchileedxlogin-login:staff'), post_data)
        self.assertEquals(response.status_code, 200)
        self.assertEqual(response.context['run_malos'], '123456789')
        self.assertEquals(EdxLoginUserCourseRegistration.objects.all().count(), 0)
