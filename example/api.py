from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django_otp.plugins.otp_email.models import EmailDevice


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