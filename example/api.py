import binascii

from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django_otp.plugins.otp_email.models import EmailDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex
from django_otp.oath import totp as totp_func
from django_otp.plugins.otp_totp.models import TOTP

import time
from base64 import b32decode


class EmailSetupStepOne(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        if not user.email:
            return Response({"error": "You must set an email address before setting up email 2FA"},
                            status=status.HTTP_400_BAD_REQUEST)

        # Check for existing device
        device = EmailDevice.objects.filter(user=user).first()

        if device and device.confirmed:
            return Response({"error": "Email 2FA is already set up and confirmed for this account"},
                            status=status.HTTP_400_BAD_REQUEST)

        # Create or update the device
        if not device:
            device = EmailDevice(user=user, name="default", confirmed=False)

        try:
            device.generate_challenge()
            device.save()
            return Response({"message": "OTP sent to your email"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class EmailSetupStepTwo(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        token = request.data.get('token')
        device = EmailDevice.objects.filter(user=request.user, confirmed=False).first()
        if device and device.verify_token(token):
            device.confirmed = True
            device.save()
            return Response({"message": "Email 2FA setup completed"}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)


class EmailCreateOTP(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        device = EmailDevice.objects.filter(user=user, confirmed=True).first()

        if not device:
            return Response({"error": "No confirmed email device found for this user"},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            device.generate_challenge()
            return Response({"message": "OTP sent to your email"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class EmailVerifyOTP(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        token = request.data.get('token')

        if not token:
            return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)

        device = EmailDevice.objects.filter(user=user, confirmed=True).first()

        if not device:
            return Response({"error": "No confirmed email device found for this user"},
                            status=status.HTTP_400_BAD_REQUEST)

        if device.verify_token(token):
            return Response({"message": "OTP verified successfully"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)


class TOTPSetupStepOne(APIView):
    permission_classes = [IsAuthenticated]


    def post(self, request):
        user = request.user
        if TOTPDevice.objects.filter(user=user).exists():
            return Response({"error": "TOTP already set up"}, status=status.HTTP_400_BAD_REQUEST)

        # Generate a hex key
        key = random_hex(20)

        # Create an unconfirmed TOTP device
        device = TOTPDevice.objects.create(user=user, key=key, confirmed=False)

        # Generate otpauth_url
        otpauth_url = device.config_url

        return Response({
            "secret_key": key,
            "otpauth_url": otpauth_url
        }, status=status.HTTP_200_OK)


class TOTPSetupStepTwo(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        token = request.data.get('token')

        if not token:
            return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)

        device = TOTPDevice.objects.filter(user=user, confirmed=False).first()
        if not device:
            return Response({"error": "TOTP setup not initiated"}, status=status.HTTP_400_BAD_REQUEST)

        if device.verify_token(token):
            device.confirmed = True
            device.save()
            return Response({"message": "TOTP device verified and saved"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)


# class TOTPVerifyOTP(APIView):
#     permission_classes = [IsAuthenticated]
#
#     def post(self, request):
#         user = request.user
#         token = request.data.get('token')
#
#         if not token:
#             return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)
#
#         device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
#
#         if not device:
#             return Response({"error": "No confirmed TOTP device found for this user"},
#                             status=status.HTTP_400_BAD_REQUEST)
#
#         current_time = time.time()
#
#         print(f"Raw key: {device.key}")
#
#         # try:
#         #     # Decode the base32 key
#         #     bin_key = b32decode(device.key.upper())
#         #
#         #     totp_instance = TOTP(bin_key, device.step, device.t0, device.digits, device.drift)
#         #     totp_instance.time = current_time
#         #
#         #     expected_token = totp_instance.token()
#         #     print(f"Current time: {int(current_time)}")
#         #     print(f"Device t0: {device.t0}")
#         #     print(f"Device step: {device.step}")
#         #     print(f"Calculated t: {totp_instance.t()}")
#         #     print(f"digits: {device.digits}")
#         #     print(f"Expected token for user {user.username}: {expected_token}")
#         #     print(f"Received token: {token}")
#         #
#         #     # Generate tokens for the last 5 minutes and next 5 minutes
#         #     for i in range(-10, 11):
#         #         test_time = current_time + i * device.step
#         #         totp_instance.time = test_time
#         #         test_token = totp_instance.token()
#         #         print(f"Token for t{i:+d}: {test_token}")
#         #
#         # except Exception as e:
#         #     print(f"Error generating expected token: {str(e)}")
#         #     return Response({"error": f"Error generating token: {str(e)}"},
#         #                     status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#
#         if device.verify_token(token):
#             if not user.is_verified():
#                 device.throttle_reset()
#             return Response({"message": "Token verified successfully"}, status=status.HTTP_200_OK)
#         else:
#             device.throttle_increment()
#             return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)

User = get_user_model()


class TOTPVerifyOTP(APIView):
    def post(self, request):
        username = request.data.get('username')
        token = request.data.get('token')

        if not username or not token:
            return Response({'error': 'Username and token are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(username=username)
            device = TOTPDevice.objects.get(user=user)
            print(f"Device is allowed to verify: {device.verify_is_allowed()}")
            device.throttle_reset()
            device.save()
            print(f"Device is allowed to verify after reset: {device.verify_is_allowed()}")

        except (User.DoesNotExist, TOTPDevice.DoesNotExist):
            return Response({'error': 'User or TOTP device not found.'}, status=status.HTTP_404_NOT_FOUND)

        current_time = int(time.time())
        generated_token = totp_func(key=device.bin_key, step=device.step, digits=device.digits)

        print(f"Generated TOTP token: {generated_token}")
        print(f"Current timestamp: {current_time}")
        print(f"Device key: {device.key}")
        print(f"Token received: {token}")

        totp = TOTP(device.bin_key, device.step, device.t0, device.digits, device.drift)
        totp.time = time.time()

        print(f"TOTP time: {totp.time}")
        print(f"TOTP t(): {totp.t()}")
        print(f"TOTP token(): {totp.token()}")
        print(f"Device tolerance: {device.tolerance}")
        print(f"Device drift: {device.drift}")
        verification_result = device.verify_token(token)
        print(f"Verification result: {verification_result}")
        print(f"Debug: Verifying token {token} for device with last_t={device.last_t}")

        if verification_result:
            return Response({'message': 'Token verified successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)