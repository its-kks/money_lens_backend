from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from account.serializers import UserRegisterSerializer,UserLoginSerializer, UserProfileSerializer, UserChangePasswordSerializer,\
SendPasswordResetEmailSerializer, UserPasswordResetSerializer
from django.contrib.auth import authenticate
from account.renderers import UserRenderer
from rest_framework.permissions import IsAuthenticated
import random
from django.core.mail import send_mail
from account.models import User
from django.conf import settings
import time
from django.contrib.sessions.models import Session


def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  
  return {  
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }   

def clear_old_sessions():
    current_time = time.time()
    for session in Session.objects.all():
        data = session.get_decoded()
        for key in list(data.keys()):
            if '@' in key:
                session_data = data.get(key)
                if session_data:
                    timestamp = session_data.get('timestamp')
                    if timestamp and current_time - timestamp > 600:  # 600 seconds
                        del data[key]
                        session.session_data = Session.objects.encode(data)
                        session.save()

# now 
class UserRegisterView(APIView):
  renderer_classes = (UserRenderer,)

  def post(self, request, format=None):
    clear_old_sessions()

    serializer = UserRegisterSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user_data = serializer.validated_data
    otp = random.randint(100000, 999999)  # Generate a 6-digit OTP

    # Store user data in session using email as the key
    request.session[user_data['email']] = {
        'email': user_data['email'],
        'username': user_data['username'],
        'password': user_data['password'],
        'avatar': user_data['avatar'],  # Store avatar as a string
        'otp': otp,
        'timestamp': time.time()
    }

    # Send OTP via email
    send_mail(
        'OTP Verification',
        f'Your OTP is {otp}',
        settings.DEFAULT_FROM_EMAIL,
        [user_data['email']],
        fail_silently=False,
    )

    return Response({'message': 'OTP sent to your email'}, status=status.HTTP_200_OK)
  
class VerifyOTPView(APIView):
  def post(self, request, format=None):
    clear_old_sessions()

    otp = request.data.get('otp')
    email = request.data.get('email')

    # Retrieve user data from session using email as the key
    user_data = request.session.get(email)
    if not user_data:
        return Response({'error': 'User data not found in session'}, status=status.HTTP_400_BAD_REQUEST)

    if otp == str(user_data['otp']):
        user = User(
            email=user_data['email'],
            username=user_data['username'],
            avatar=user_data['avatar']
        )
        user.set_password(user_data['password'])
        user.save()

        # Clear user data from session
        del request.session[email]

        token = get_tokens_for_user(user)
        return Response({'message': 'User registration is successful', 'token': token}, status=status.HTTP_201_CREATED)
    else:
        return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
  renderer_classes = (UserRenderer,)
  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.data.get('email')
    password = serializer.data.get('password')
    user = authenticate(email=email, password=password)
    if user:
      token = get_tokens_for_user(user)
      return Response({'message': 'User login is successful','token':token}, status=status.HTTP_200_OK)
    else:
      return Response({'errors':{ 'non_field_errors': ['Email or Password is Invalid'] } }, status=status.HTTP_404_NOT_FOUND)  

class UserProfileView(APIView):
  renderer_classes = (UserRenderer,)
  permission_classes = [IsAuthenticated]
  def get(self, request, format=None):
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)
  
class UserChangePasswordView(APIView):
  renderer_classes = (UserRenderer,)
  permission_classes = [IsAuthenticated]
  def post(self, request, format=None):
    serializer = UserChangePasswordSerializer(data=request.data,
    context={'user': request.user})
    serializer.is_valid(raise_exception=True)
    return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SendPasswordResetEmailView(APIView):
  renderer_classes = (UserRenderer,)
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'message':'Password Reset link sent. Check your email.'},
                        status=status.HTTP_200_OK)      
      
class UserPasswordResetView(APIView):
  renderer_classes = (UserRenderer,) 
  def post(self, request, uid, token , format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
    serializer.is_valid(raise_exception=True)
    return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
    