from rest_framework import status
from rest_framework.test import APIClient
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.test import TestCase
from unittest.mock import patch, ANY, MagicMock
from django.core.mail import send_mail
from django.core import mail
import secrets
from urllib.parse import urlparse, parse_qs
from smtplib import SMTPException
from rest_framework.test import APITestCase
from .models import EmailVerification
from .serializers import CustomUserSerializer
from rest_framework.test import force_authenticate
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework.test import force_authenticate
from .views import test_token


User = get_user_model()


class SignupViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.signup_url = reverse('signup')
        # self.user = User.objects.create_user(username='testuser', password='testpassword', email='test@example.com')

    def test_successful_signup_and_mail_verification(self):
        data = {
            'email': 'newuser@example.com',
            'password': 'newpassword',
            'first_name': 'John',
            'last_name': 'Doe',
        }
        response = self.client.post(self.signup_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(email='newuser@example.com')
        self.assertTrue(EmailVerification.objects.filter(user=user).exists())
        self.assertTrue(User.objects.filter(email='newuser@example.com').exists())
        verification = EmailVerification.objects.get(user=user)

        response = self.client.get(f'/auth/verify-email/{verification.token}/')
        # Check that the response status code is 200 (OK)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Refresh the user instance from the database
        user.refresh_from_db()

        # Check that the user is now active
        self.assertTrue(user.is_active)

        # Check that the EmailVerification instance has been deleted
        with self.assertRaises(EmailVerification.DoesNotExist):
            EmailVerification.objects.get(token=verification.token)
        # self.verification = EmailVerification.objects.create(user=user)

    @patch('user_auth.views.send_mail')
    def test_failed_email_sending(self, mock_send_mail):
        # Configure the side effect to raise an exception
        mock_send_mail.side_effect = Exception("Simulated email sending failure")

        # Call the signup view
        url = reverse('signup')
        data = {
            'email': 'testuser@example.com',
            'password': 'newpassword',
            'first_name': 'John',
            'last_name': 'Doe',
        }
        response = self.client.post(url, data, format='json')

        # Assert that the response indicates a failure
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Assert that the user was not created
        self.assertFalse(User.objects.filter(email='testuser@example.com').exists())

        # Assert that the exception was logged or handled appropriately
        # (This depends on how you handle exceptions in your code)

        # Reset the side effect for subsequent tests
        mock_send_mail.side_effect = None

    def test_duplicate_email_signup(self):
        # Create a user with the same email as in the previous test
        existing_user = User.objects.create_user(
            email='existinguser@example.com',
            password='existingpassword',
            first_name='Existing',
            last_name='User',
        )

        data = {
            'email': 'existinguser@example.com',
            'password': 'newpassword',
            'first_name': 'John',
            'last_name': 'Doe',
        }
        response = self.client.post(self.signup_url, data, format='json')
        print(response.data)
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertIn('user already exist', response.data.get('message', ''))

    def test_short_password_signup(self):
        data = {
            'email': 'shortpassword@example.com',
            'password': 'short',
            'first_name': 'John',
            'last_name': 'Doe',
        }
        response = self.client.post(self.signup_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password should be higher than 6 character', response.data.get('message', ''))



# Note: Adjust the 'test_token' in reverse('test_token') based on your actual URL configuration.

    # def tearDown(self):
    #     if hasattr(self._outcome, 'errors'):
    #         # Python 3.4 - 3.10  (These two methods have no side effects)
    #         result = self.defaultTestResult()
    #         self._feedErrorsToResult(result, self._outcome.errors)
    #     else:
    #         # Python 3.11+
    #         result = self._outcome.result
    #     ok = all(test != self for test, text in result.errors + result.failures)

    #     # Demo output:  (print short info immediately - not important)
    #     if ok:
    #         print('\n\n\n',(self.id(),) , 'PASSED: \n\n\n' )
    #     for typ, errors in (('ERROR', result.errors), ('FAIL', result.failures)):
    #         for test, text in errors:
    #             if test is self:
    #                 #  the full traceback is in the variable `text`
    #                 msg = [x for x in text.split('\n')[1:]
    #                        if not x.startswith(' ')][0]
    #                 print("\n\n%s: %s\n     %s" % (typ, self.id(), msg))


#Inheriting from APITestCase so as to have access to force_authenticate
class TestTokenViews(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(first_name='testuser', last_name='lastname', password='testpassword', email='test@example.com')
        self.url_obtain = reverse('token_obtain_pair')
        self.url_refresh = reverse('token_refresh')
        self.url_protected_view = reverse('protected_view')
        self.user.is_active= True
        self.user.save()

    def test_obtain_token(self):
        data = {
            'email': 'test@example.com',
            'password': 'testpassword',
        }

        # Make a POST request to the token_obtain_pair endpoint
        response = self.client.post(self.url_obtain, data, format='json')
        # Check that the response status code is 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check that the response contains the access and refresh tokens
        self.assertIn('access', response.data['data'])
        self.assertIn('refresh', response.data['data'])
    def test_refresh_token(self):
        # Obtain an access token
        obtain_data = {
            'email': 'test@example.com',
            'password': 'testpassword',
        }
        obtain_response = self.client.post(self.url_obtain, obtain_data, format='json')

        # Check that the response status code is 200 OK
        self.assertEqual(obtain_response.status_code, status.HTTP_200_OK)

        # Extract the refresh token from the obtain response
        refresh_token = obtain_response.data['data']['refresh']

        # Make a POST request to the token_refresh endpoint with the refresh token
        refresh_data = {'refresh': refresh_token}
        refresh_response = self.client.post(self.url_refresh, refresh_data, format='json')

        # Check that the response status code is 200 OK
        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)

        # Check that the response contains a new access token
        self.assertIn('access', refresh_response.data['data'])

    def test_refresh_token_invalid(self):
        # Make a POST request to the token_refresh endpoint with an invalid refresh token
        refresh_data = {'refresh': 'invalid_token'}
        refresh_response = self.client.post(self.url_refresh, refresh_data, format='json')

        # Check that the response status code is 401 Unauthorized
        self.assertEqual(refresh_response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_token_view_authenticated(self):
        # Authenticate the request with the user
        self.client.force_authenticate(user=self.user)

        # Make a GET request to the test_token endpoint
        response = self.client.get(self.url_protected_view)

        # Check that the response status code is 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check that the response data matches the serialized user data
        expected_data = CustomUserSerializer(self.user).data
        self.assertEqual(response.data['data']['id'], expected_data['id'])

    def test_token_view_unauthenticated(self):
        # Make a GET request to the test_token endpoint without authentication
        response = self.client.get(self.url_protected_view)

        # Check that the response status code is 401 Unauthorized
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class GoogleAuthTests(APITestCase):

    def test_google_auth_initiate(self):
        url = reverse('google_auth_initiate')  # Replace with your actual URL configuration

        # Make a GET request to the google_auth_initiate endpoint
        response = self.client.get(url)

        # Check that the response status code is 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check that the response data contains the authorization URL
        expected_url_part = 'https://accounts.google.com/o/oauth2/auth'
        actual_url = response.data['data']
        self.assertIn(expected_url_part, actual_url, f"Expected '{expected_url_part}' in '{actual_url}'")
        parsed_url = urlparse(actual_url)
        actual_params = parse_qs(parsed_url.query)
        
        
        expected_params = [
            'client_id',
            'redirect_uri',
            'response_type',
            'scope',
            'state',
        ]

        session= self.client.session

        session['google_auth_state2'] = 'mock_state'
        session.save()
        # print('\n\n\n\n', session['google_auth_state2'],'\n\n\n')
        # Check that all expected query parameters are present in the actual URL
        for param in expected_params:
            self.assertIn(param, actual_params, f"Expected '{param}' in query parameters")
            self.assertTrue(actual_params[param], f"Expected non-empty value for query parameter '{param}'")



class ResetPasswordTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(first_name='testuser',last_name='tope' , password='testpassword', email='testpasswordreset@example.com')
    

    def reload_user(self):
        self.user = User.objects.get(email=self.user.email)
        self.user.can_reset_password=True
        self.user.save()
    
    def test_reset_password_valid_email(self):
        url = reverse('reset_password')
        data = {'email': 'testpasswordreset@example.com'}
        # Make a POST request to the reset_password endpoint
        self.reload_user
        response = self.client.post(url, data, format='json')
        otp = secrets.token_urlsafe(20)
        self.user.otp=otp
        self.user.save()
    

        
        # Check that the response status code is 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check that the response contains the 'access' key
        self.assertIn('access', response.data['data'])

        # Additional checks as needed

    def test_reset_password_invalid_email(self):
        url = reverse('reset_password')
        data = {'email': 'nonexistent@example.com'}

        # Make a POST request to the reset_password endpoint
        response = self.client.post(url, data, format='json')

        # Check that the response status code is 404 Not Found
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # Check the response details
        self.assertEqual(response.data['message'], 'Invalid credentials, email not registered')

    def test_reset_password_google_user(self):
        self.user.is_google = True
        self.user.save()

        url = reverse('reset_password')
        data = {'email': 'testpasswordreset@example.com'}

        # Make a POST request to the reset_password endpoint
        response = self.client.post(url, data, format='json')

        # Check that the response status code is 404 Not Found
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # Check the response details
        self.assertEqual(response.data['message'], 'Invalid credentials, you registered with Google')

    def test_reset_password_missing_email(self):
        url = reverse('reset_password')
        data = {}  # Missing 'email' field

        # Make a POST request to the reset_password endpoint
        response = self.client.post(url, data, format='json')

        # Check that the response status code is 400 Bad Request
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Check the response details
        self.assertEqual(response.data['message'], 'Invalid details, email not supplied')


    def test_reset_password_confirm(self):
        url = reverse('reset_password_confirm')
        self.reload_user()  # Reload the user from the database
        
        print('\n\n\n', self.user.can_reset_password, '\n\n\n' )
        print('\n\n\n', self.user.otp, '\n\n\n' )
        self.assertTrue(self.user.can_reset_password)


    # Add more test cases for reset_password_confirm and update_password as needed

# Note: Adjust the 'reset_password' in reverse() based on your actual URL configuration.
