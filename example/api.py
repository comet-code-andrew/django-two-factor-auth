from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.urls import reverse


from django.contrib.auth import authenticate, login

from rest_framework import status


from django_otp import devices_for_user

from django_otp import login as otp_login

from django_otp.plugins.otp_email.models import EmailDevice
from django.contrib.auth.models import User

from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from django_otp.decorators import otp_required

class HomeAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        devices = list(devices_for_user(user))
        print(devices)

        otp_devices = []
        for device in devices:
            otp_devices.append({
                'name': device.name,
                'type': device.__class__.__name__,
                'confirmed': device.confirmed,
            })

        data = {
            'is_authenticated': user.is_authenticated,
            'username': user.username if user.is_authenticated else None,
            'otp_devices': otp_devices,
            'has_otp_device': bool(devices),
            'urls': {
                'home': reverse('home'),
                'secret': reverse('secret'),
                'profile': reverse('two_factor:profile'),
                'sessions': reverse('user_sessions:session_list'),
                'logout': reverse('logout'),
                'login': reverse('two_factor:login'),
            }
        }
        return Response(data)


class LoginStepOneAPIView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)
        login(request, user)

        if user is not None:
            devices = list(devices_for_user(user))

            if devices:
                device = devices[0]
                print("user:", user, "devices:",devices)
                device.generate_challenge()

            # Authentication successful
            return Response({
                'message': 'Authentication successful',
                'user_id': user.id,
                'requires_otp': hasattr(user, 'has_otp_device')  # Check if user has OTP set up
            }, status=status.HTTP_200_OK)
        else:
            # Authentication failed
            return Response({
                'message': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)


# @method_decorator(csrf_exempt, name='dispatch')
class LoginStepTwoAPIView(APIView):
    def post(self, request):

        # if request.user.is_authenticated:
        #     print("user is logged in already")
        #     return Response({
        #         'message': 'User is already authenticated',
        #         'user_id': request.user.id,
        #         'username': request.user.username
        #     }, status=status.HTTP_200_OK)

        user_id = request.data.get('user_id')
        otp_token = request.data.get('otp_token')

        if not user_id or not otp_token:
            return Response({'message': 'User ID and OTP token are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        devices = devices_for_user(user)

        for device in devices:
            if device.verify_token(otp_token):
                # OTP token is valid, log in the user
                otp_login(request, device)
                return Response({'message': 'OTP verification successful'}, status=status.HTTP_200_OK)

        return Response({'message': 'Invalid OTP token'}, status=status.HTTP_401_UNAUTHORIZED)


@method_decorator(otp_required, name='dispatch')
class SecretAPIView(APIView):
    def get(self, request):
        return Response({
            'message': 'This is a secret page. If you can see this, you are authenticated with 2FA.',
            'user': request.user.username
        }, status=status.HTTP_200_OK)