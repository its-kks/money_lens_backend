from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.conf import settings

class UserRegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'password2', 'avatar']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        pass1 = attrs.get('password')
        pass2 = attrs.get('password2')
        if pass1 != pass2:
            raise serializers.ValidationError('Passwords must match')
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2') 
        user = User(
            email=validated_data['email'],
            username=validated_data['username'],
            avatar=validated_data['avatar']
        )
        user.set_password(validated_data['password'])
        return user 
  
class UserLoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = User
    fields = ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
  class Meta:
    model = User
    fields = ['id', 'email', 'username', 'avatar']

class UserChangePasswordSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']
  
  def validate(self, attrs):
    password = attrs.get('password')
    password2 = attrs.get('password2')
    user = self.context.get('user')
    if password != password2:
      raise serializers.ValidationError('Passwords must match')
    user.set_password(password)
    user.save()
    return attrs
  
class SendPasswordResetEmailSerializer(serializers.Serializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    fields = ['email']
  
  def validate(self, attrs):
     email = attrs.get('email')
     if User.objects.filter(email=email).exists():
        user = User.objects.get(email=email)
        uid = urlsafe_base64_encode(force_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        host_name = '127.0.0.1:8000'
        link = f"{host_name}/api/user/reset-password/{uid}/{token}/"

        send_mail(
           'Passwor Reset Money Lens',
            f'Click this link to reset your password {link}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email], 
            fail_silently=False,
        )

        return attrs
     else:
        raise serializers.ValidationError('Not a registered e-mail')
  

class UserPasswordResetSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']
  
  def validate(self, attrs):
    try:
      password = attrs.get('password')
      password2 = attrs.get('password2')
      uid = self.context.get('uid')
      token = self.context.get('token')
      if password != password2:
        raise serializers.ValidationError('Passwords must match')
      id = smart_str(urlsafe_base64_decode(uid))
      user = User.objects.get(id=id)
      if not PasswordResetTokenGenerator().check_token(user, token):
        raise serializers.ValidationError('Token Expired or Invalid token')
      user.set_password(password)
      user.save()
      return attrs
    except DjangoUnicodeDecodeError as identifier:
       PasswordResetTokenGenerator().check_token(user, token)
       raise serializers.ValidationError('Token Expired or Invalid token')
       