from django.conf import settings
from django.contrib import admin
from django.contrib.auth.views import LogoutView
from django.urls import include, path

from two_factor.gateways.twilio.urls import urlpatterns as tf_twilio_urls
from two_factor.urls import urlpatterns as tf_urls

from .views import (
    ExampleSecretView, HomeView, RegistrationCompleteView, RegistrationView,
)

# from .api import HomeAPIView, SecretAPIView, InitiateEmailSetupView, \
#     GenerateTokenView, ValidateTokenView, InitialLoginView, VerifyOTPView, GenerateOTPView

from .api import EmailSetupStepOne, EmailSetupStepTwo

urlpatterns = [
    path(
        '',
        HomeView.as_view(),
        name='home',
    ),
    path(
        'account/logout/',
        LogoutView.as_view(),
        name='logout',
    ),
    path(
        'secret/',
        ExampleSecretView.as_view(),
        name='secret',
    ),
    path(
        'account/register/',
        RegistrationView.as_view(),
        name='registration',
    ),
    path(
        'account/register/done/',
        RegistrationCompleteView.as_view(),
        name='registration_complete',
    ),
    path('', include(tf_urls)),
    path('', include(tf_twilio_urls)),
    path('', include('user_sessions.urls', 'user_sessions')),
    path('admin/', admin.site.urls),

    path('email-2fa/setup-step1/', EmailSetupStepOne.as_view(), name='email_setup_step_one'),
    path('email-2fa/setup-step2/', EmailSetupStepTwo.as_view(), name='email_setup_step_two'),

    # path('email-2fa/initial-login/', InitialLoginView.as_view(), name='initial_login_view'),
    # path('email-2fa/initiate-email-setup/', InitiateEmailSetupView.as_view(), name='initiate_email_setup'),
    # path('email-2fa/generate-otp/', GenerateOTPView.as_view(), name='generate_otp_view'),
    # path('email-2fa/verify-otp/', VerifyOTPView.as_view(), name='verify_otp_view'),

]

if settings.DEBUG:
    import debug_toolbar
    urlpatterns += [
        path('__debug__/', include(debug_toolbar.urls)),
    ]
