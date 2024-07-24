from binascii import unhexlify
from django.core import mail
from django.urls import reverse
from django.test import TestCase
from django.contrib.auth import get_user_model
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_email.models import EmailDevice
from django_otp.oath import TOTP
from rest_framework import status
from rest_framework.test import APIClient

User = get_user_model()


class BaseOTPTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.user_email = 'test@example.com'
        self.login_data = {
            'auth-username': 'testuser',
            'auth-password': 'testpass',
            'login_view-current_step': 'auth'
        }
    # When logging in ensure user is not verified but is authenticated
    def login_user(self):
        self.client.post(reverse('two_factor:login'), data=self.login_data)
        response = self.client.get(reverse('two_factor:setup'))
        self.assertTrue(response.wsgi_request.user.is_authenticated)
        self.assertFalse(response.wsgi_request.user.is_verified())

    def assert_unauthenticated_request_forbidden(self, url):
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

class EmailOTPTests(BaseOTPTest):
    def setUp(self):
        super().setUp()
        self.email_setup_step_one = reverse('email_setup_step_one')
        self.email_setup_step_two = reverse('email_setup_step_two')

    def test_unauthenticated_user(self):
        """Test that unauthenticated users cannot access the view"""
        self.assert_unauthenticated_request_forbidden(self.email_setup_step_one)
        self.assert_unauthenticated_request_forbidden(self.email_setup_step_two)

    def test_device_setup(self):

        # Test: User without email can't set up device
        self.login_user()
        response = self.client.post(self.email_setup_step_one)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('You must set an email address', str(response.data['error']))

        # Set email and proceed with normal flow
        self.user.email = self.user_email
        self.user.save()

        # Post to step 1, ensure a NON-confirmed device is created & email sent
        response = self.client.post(self.email_setup_step_one)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(EmailDevice.objects.filter(user=self.user).exists())
        self.assertFalse(EmailDevice.objects.get(user=self.user).confirmed)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to[0], self.user.email)

        # Get token from email and post it to the step two api
        email_body = mail.outbox[0].body
        token = email_body.strip()
        response = self.client.post(self.email_setup_step_two, {'token': token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Email 2FA setup completed', str(response.data['message']))

        # 4. Ensure user now authenticated, has a confirmed device and NOT verified.
        self.assertTrue(response.wsgi_request.user.is_authenticated)
        device = EmailDevice.objects.get(user=self.user)
        self.assertTrue(device.confirmed)
        self.assertFalse(response.wsgi_request.user.is_verified())

    def test_device_2fa(self):
        self.user.email = 'test@example.com'
        self.user.save()
        self.client.force_authenticate(user=self.user)

        # Step 1: Initiate setup
        self.client.post(self.email_setup_step_one)
        email_body = mail.outbox[0].body
        token = email_body.strip()
        self.client.post(self.email_setup_step_two, {'token': token})

        # Create a new OTP
        response = self.client.post(reverse('email_create_otp'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('OTP sent to your email', str(response.data['message']))

        # Get the new OTP from the email
        new_otp = mail.outbox[1].body.strip()

        # Verify the new OTP
        response = self.client.post(reverse('email_verify_otp'), {'token': new_otp})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('OTP verified successfully', str(response.data['message']))
        # self.assertFalse(response.wsgi_request.user.is_verified())


        # Try to verify with an invalid OTP
        response = self.client.post(reverse('email_verify_otp'), {'token': 'invalid_token'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid token', str(response.data['error']))

    def test_device_duplicate(self):
        """Test that users who already have an EmailDevice get an appropriate error"""
        self.user.email = 'test@example.com'
        self.user.save()
        EmailDevice.objects.create(user=self.user, name='default')
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.email_setup_step_one)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Email 2FA is already set up', str(response.data['error']))


class TOTPTests(BaseOTPTest):
    def setUp(self):
        super().setUp()
        self.totp_setup_step_one = reverse('totp_setup_step_one')
        self.totp_setup_step_two = reverse('totp_setup_step_two')
        self.totp_verify_otp = reverse('totp_verify_otp')

    # def test_unauthenticated_user(self):
    #     """Test that unauthenticated users cannot access the view"""
    #     self.assert_unauthenticated_request_forbidden(self.totp_setup_step_one)
    #     self.assert_unauthenticated_request_forbidden(self.totp_setup_step_two)

    def test_device_setup(self):
        self.client.post(reverse('two_factor:login'), data=self.login_data)
        response = self.client.get(reverse('two_factor:setup'))
        self.assertTrue(response.wsgi_request.user.is_authenticated)
        self.assertFalse(response.wsgi_request.user.is_verified())

        # 2. Post to step 1, ensure a NON-confirmed device is created & proper data returned
        response = self.client.post(self.totp_setup_step_one)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(TOTPDevice.objects.filter(user=self.user).exists())
        device = TOTPDevice.objects.get(user=self.user)
        self.assertFalse(device.confirmed)
        self.assertIn('secret_key', response.data)
        self.assertIn('otpauth_url', response.data)

        # 3. Create a token as if we're an authenticator app and post to step two
        hex_key = response.data['secret_key']
        key_bytes = unhexlify(hex_key)
        totp = TOTP(key_bytes)
        token = totp.token()
        response = self.client.post(self.totp_setup_step_two, {'token': token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 4. Ensure user now authenticated, has a confirmed device and NOT verified.
        self.assertTrue(response.wsgi_request.user.is_authenticated)
        device.refresh_from_db()  # Re-fetch to get updated confirmation status
        self.assertTrue(device.confirmed)
        self.assertFalse(response.wsgi_request.user.is_verified())

    def test_device_2fa(self):
        self.login_user()

        # TOTP setup just like in test_device_setup except no testing
        response = self.client.post(self.totp_setup_step_one)
        secret_key = response.data['secret_key']
        totp = TOTP(key=unhexlify(secret_key))
        token = totp.token()
        self.client.post(self.totp_setup_step_two, {'token': token})

        setup_response = self.client.get(reverse('two_factor:setup'))  # This will refresh the session
        self.assertTrue(setup_response.wsgi_request.user.is_authenticated)
        self.assertFalse(setup_response.wsgi_request.user.is_verified())

        # Now test the actual 2FA process
        token1 = totp.token()
        response = self.client.post(self.totp_verify_otp, {'username': self.user.username, 'token': token1})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Token verified successfully', str(response.data['message']))

        # Debug prints
        print("Response data:", response.data)
        print("User authenticated:", response.wsgi_request.user.is_authenticated)
        print("User verified:", response.wsgi_request.user.is_verified())

        # Get a fresh request to check verification status
        verify_response = self.client.get(reverse('two_factor:setup'))

        # More debug prints
        print("Verify response user authenticated:", verify_response.wsgi_request.user.is_authenticated)
        print("Verify response user verified:", verify_response.wsgi_request.user.is_verified())
        print("TOTP Device exists:", TOTPDevice.objects.filter(user=self.user, confirmed=True).exists())

        self.assertTrue(verify_response.wsgi_request.user.is_authenticated)
        self.assertTrue(verify_response.wsgi_request.user.is_verified())

    def test_device_duplicate(self):
        """Test that users who already have a TOTPDevice get an appropriate error"""
        self.client.force_authenticate(user=self.user)

        # First, set up a TOTP device
        response = self.client.post(self.totp_setup_step_one)
        secret_key = response.data['secret_key']
        totp = TOTP(key=unhexlify(secret_key))
        token = totp.token()
        self.client.post(self.totp_setup_step_two, {'token': token})

        # Now try to set up another TOTP device
        response = self.client.post(self.totp_setup_step_one)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('TOTP already set up', str(response.data['error']))





