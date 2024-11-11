from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from accounts.models import Profile,validate_phone_number

User = get_user_model()

class VerifyPhoneOTPModelSerializer(serializers.ModelSerializer):
    phone_number = serializers.CharField(max_length=15)
    otp = serializers.CharField(max_length=6)

    class Meta:
        model = User
        fields = ['phone_number', 'otp']

    def validate(self, data):
        phone_number = data.get('phone_number')
        otp = data.get('otp')
        
        try:
            user = User.objects.get(phone_number__iexact=phone_number)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this phone number does not exist.")

        # Check if the OTP matches and is within the expiration time
        if user.otp != otp:
            raise serializers.ValidationError("The OTP does not match.")
        
        # Return the validated data
        return data


class CompleteProfileSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name']

    def update(self, instance, validated_data):
        # Update first name and last name
        instance.first_name = validated_data.get('first_name')
        instance.last_name = validated_data.get('last_name')
        instance.save()
        return instance


class SetPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['password']

    def validate_password(self, value):
        # Use Django's password validators
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(str(e))
        
        return value

    def update(self, instance, validated_data):
        # Set the password and mark the user as verified
        password = validated_data['password']
        instance.set_password(password)
        instance.is_verified = True
        instance.save()
        return instance

    def update(self, instance, validated_data):
        # Set the password and mark the user as verified
        password = validated_data['password']
        instance.set_password(password)
        instance.is_verified = True
        instance.save()
        return instance


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom token serializer to include additional user information in the token.
    """
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        
        # Add additional user info to the token
        token['phone_number'] = user.phone_number
        token['id'] = user.id
        
        return token

class ProfileSerializer(serializers.ModelSerializer):
    phone_number = serializers.CharField(source="user.phone_number", read_only=True)

    class Meta:
        model = Profile
        fields = (
            "id",
            "phone_number",
            "first_name",
            "last_name",

        )
        read_only_fields = ["phone_number"]