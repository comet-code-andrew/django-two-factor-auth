from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django_otp.plugins.otp_email.models import EmailDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex
from django_otp.plugins.otp_totp.models import TOTP
import time

User = get_user_model()


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
    """
    First step in setting up TOTP for a user.

    This view creates a new TOTP device for the authenticated user and returns
    the necessary information to set up the device in an authenticator app.

    Permissions:
    - User must be authenticated

    Returns:
    - 200 OK with secret_key and otpauth_url if successful
    - 400 BAD REQUEST if TOTP is already set up for the user

    Note:
    - The created device is initially unconfirmed and requires validation
      in TOTPSetupStepTwo.
    """
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
    """
    Second step in setting up TOTP for a user.

    This view verifies the token provided by the user and confirms the TOTP device.

    Permissions:
    - User must be authenticated

    Payload:
    - token: The TOTP token generated by the user's authenticator app

    Returns:
    - 200 OK if the token is valid and the device is confirmed
    - 400 BAD REQUEST if the token is invalid or missing, or if TOTP setup wasn't initiated

    Important:
    - After successful verification, we reset the 'last_t' value to -1.
      This is crucial to allow the next verification to succeed, as the initial
      verification updates 'last_t' to the current time step.
    """
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
            device.last_t = -1  # Reset last_t to allow the next verification
            device.save()
            return Response({"message": "TOTP device verified and saved"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)


class TOTPVerifyOTP(APIView):
    """
    Verifies a TOTP token for a given user.

    Payload:
    - username: The username of the user
    - token: The TOTP token to verify

    Returns:
    - 200 OK if the token is valid
    - 400 BAD REQUEST if the token is invalid or if username/token is missing
    - 404 NOT FOUND if the user or TOTP device doesn't exist

    Note:
    - This view includes extensive logging for debugging purposes.
      Consider removing or conditionally enabling these logs in a production environment.
    - The 'last_t' value is critical for preventing token reuse. It's updated
      automatically by the verify_token method when a valid token is provided.
    """
    def post(self, request):
        username = request.data.get('username')
        token = request.data.get('token')

        print(f"View: Received request - Username: {username}, Token: {token}")

        if not username or not token:
            return Response({'error': 'Username and token are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(username=username)
            device = TOTPDevice.objects.get(user=user)
            print(f"View: Device found for user {username}")
            print(f"View: Device key: {device.key}")
            print(f"View: Device step: {device.step}")
            print(f"View: Device t0: {device.t0}")
            print(f"View: Device digits: {device.digits}")
            print(f"View: Device tolerance: {device.tolerance}")
            print(f"View: Device drift: {device.drift}")
            print(f"View: Device last_t: {device.last_t}")
        except (User.DoesNotExist, TOTPDevice.DoesNotExist):
            print(f"View: User or TOTP device not found for username: {username}")
            return Response({'error': 'User or TOTP device not found.'}, status=status.HTTP_404_NOT_FOUND)

        totp = TOTP(device.bin_key, device.step, device.t0, device.digits, device.drift)
        totp.time = time.time()

        print(f"View: Current time: {totp.time}")
        print(f"View: Calculated t: {totp.t()}")
        print(f"View: Generated token: {totp.token()}")
        print(f"View: Received token: {token}")

        print(f"View: Device last_t before verification: {device.last_t}")
        verification_result = device.verify_token(token)
        print(f"View: Device last_t after verification: {device.last_t}")

        if verification_result:
            request.session['otp_device_id'] = device.persistent_id

            print(f"View: Device drift after verification: {device.drift}")
            print(f"View: Device last_t after verification: {device.last_t}")
            return Response({'message': 'Token verified successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)