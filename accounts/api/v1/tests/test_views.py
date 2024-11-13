from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.utils import timezone
from datetime import timedelta
from django.core.cache import cache
from accounts.models import User

class AuthTests(APITestCase):
    def setUp(self):
        self.phone_number = "1234567890"
        self.password = "password123"
        self.user = User.objects.create_user(phone_number=self.phone_number, password=self.password)
        self.user.save()
    
    def test_check_registration_new_user(self):
        """
        Ensure new user registration process initiates OTP sending.
        """
        url = reverse('accounts:check-registration')
        response = self.client.post(url, {"phone_number": "0987654321"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("OTP sent successfully", response.data["message"])

    def test_check_registration_existing_user(self):
        """
        Ensure existing user receives correct response when attempting to register again.
        """
        url = reverse('accounts:check-registration')
        response = self.client.post(url, {"phone_number": self.phone_number})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("User exists. Please proceed to login with your password.", response.data["message"])

    def test_verify_phone_otp_success(self):
        """
        Ensure OTP verification is successful and returns tokens.
        """
        otp = self.user.otp = "123456"
        self.user.otp_created_at = timezone.now()
        self.user.save()

        url = reverse('accounts:verify-otp')
        response = self.client.post(url, {"phone_number": self.phone_number, "otp": otp})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("OTP verified. Tokens issued.", response.data["message"])
        self.assertIn("access", response.data["tokens"])
        self.assertIn("refresh", response.data["tokens"])

    def test_verify_phone_otp_failure(self):
        """
        Ensure OTP verification fails and increments the failed attempt count.
        """
        otp = "wrong_otp"
        url = reverse('accounts:verify-otp')
        ip_address = '127.0.0.1'

        # Attempt with incorrect OTP
        for _ in range(3):
            response = self.client.post(url, {"phone_number": self.phone_number, "otp": otp})
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("Too many incorrect OTP attempts", response.data["message"])

    def test_set_password(self):
        """
        Ensure authenticated users can set their password.
        """
        self.client.force_authenticate(user=self.user)
        url = reverse('accounts:set-password')
        response = self.client.post(url, {"password": "new_password123"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Password set successfully", response.data["message"])
        self.assertTrue(self.user.check_password("new_password123"))

    def test_login_with_password_success(self):
        """
        Ensure existing users can log in with correct credentials.
        """
        url = reverse('accounts:login')
        response = self.client.post(url, {"phone_number": self.phone_number, "password": self.password})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Login successful", response.data["message"])
        self.assertIn("token", response.data)
        self.assertIn("access", response.data["token"])
        self.assertIn("refresh", response.data["token"])

    def test_login_with_password_failure_lockout(self):
        """
        Ensure lockout occurs after 3 failed login attempts.
        """
        url = reverse('accounts:login')
        wrong_password = "wrong_password"
        ip_address = '127.0.0.1'

        # Attempt with incorrect password
        for _ in range(3):
            response = self.client.post(url, {"phone_number": self.phone_number, "password": wrong_password})
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("Too many failed login attempts. Please try again after 1 hour.", response.data["message"])

    def tearDown(self):
        # Clear cache after tests
        cache.clear()
