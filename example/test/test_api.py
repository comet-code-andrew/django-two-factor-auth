from django.urls import reverse
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from django_otp.plugins.otp_email.models import EmailDevice

User = get_user_model()


class EmailSetupStepOneTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('email_setup_step_one')  # Make sure this matches your URL name
        self.user = User.objects.create_user(username='testuser', password='testpass123')

    def test_unauthenticated_user(self):
        """Test that unauthenticated users cannot access the view"""
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_user_without_email(self):
        """Test that users without an email address get a helpful error"""
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('You must set an email address', str(response.data['error']))

    def test_user_with_existing_email_device(self):
        """Test that users who already have an EmailDevice get an appropriate error"""
        self.user.email = 'test@example.com'
        self.user.save()
        EmailDevice.objects.create(user=self.user, name='default')
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Email 2FA is already set up', str(response.data['error']))

    def test_successful_setup_initiation(self):
        """Test successful initiation of email 2FA setup"""
        self.user.email = 'test@example.com'
        self.user.save()
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('OTP sent to your email', str(response.data['message']))
        self.assertTrue(EmailDevice.objects.filter(user=self.user).exists())
        self.assertFalse(EmailDevice.objects.get(user=self.user).confirmed)

    def test_successful_setup_flow(self):
        self.user.email = 'test@example.com'
        self.user.save()
        self.client.force_authenticate(user=self.user)

        # Step 1: Initiate setup
        response = self.client.post(reverse('email_setup_step_one'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('OTP sent to your email', str(response.data['message']))

        # Verify device was created, and that it is not confirmed yet
        device = EmailDevice.objects.get(user=self.user)
        self.assertFalse(device.confirmed)

        # Step 2: Verify token
        # In a real scenario, we'd get the token from the email. Here, we'll get it directly from the device.
        token = device.token
        response = self.client.post(reverse('email_setup_step_two'), {'token': token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Email 2FA setup completed', str(response.data['message']))

        # Verify device is now confirmed
        device.refresh_from_db()
        self.assertTrue(device.confirmed)

    def test_multiple_setup_initiations(self):
        """Test that multiple calls to step one update the existing device rather than creating new ones"""
        self.user.email = 'test@example.com'
        self.user.save()
        self.client.force_authenticate(user=self.user)

        # First call to step one
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('OTP sent to your email', str(response.data['message']))

        # Check that a device was created
        self.assertEqual(EmailDevice.objects.filter(user=self.user).count(), 1)
        first_device = EmailDevice.objects.get(user=self.user)
        first_token = first_device.token

        # Second call to step one
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('OTP sent to your email', str(response.data['message']))

        # Check that no new device was created, but the token was updated
        self.assertEqual(EmailDevice.objects.filter(user=self.user).count(), 1)
        second_device = EmailDevice.objects.get(user=self.user)
        second_token = second_device.token

        self.assertEqual(first_device.id, second_device.id)
        self.assertNotEqual(first_token, second_token)