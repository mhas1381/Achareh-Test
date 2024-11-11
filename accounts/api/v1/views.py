from rest_framework.response import Response
from rest_framework import viewsets, status, permissions
from rest_framework.permissions import IsAuthenticated , AllowAny
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from rest_framework import generics
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.exceptions import ValidationError
from .serializers import (
    VerifyPhoneOTPModelSerializer, 
    CustomTokenObtainPairSerializer,
    ProfileSerializer
)
from accounts.models import Profile , validate_phone_number
from .utils import otp_generator

User = get_user_model()

# Utility to generate and send OTP
def send_otp(phone_number):
    otp_key = otp_generator()
    print(f"Generated OTP: {otp_key}")  # For debugging
    return otp_key


class CheckRegistrationView(APIView):
    """
    Checks if the user is registered by mobile number and handles OTP sending for new users.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        phone_number = request.data.get('phone_number')
        
        if not phone_number:
            return Response({"message": "Phone number is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate phone number
        try:
            validate_phone_number(phone_number)
        except ValidationError as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the user exists based on the phone number
        user = User.objects.filter(phone_number=phone_number).first()
        
        if user:
            # Check if password is set
            if user.password:
                # If password is set, user is registered and can login
                return Response({"message": "User exists. Please proceed to login with your password."}, status=status.HTTP_200_OK)
            else:
                # If password is not set, send OTP for registration
                otp = send_otp(phone_number)
                if otp:
                    # Update the user with OTP for verification
                    user.otp = otp
                    user.otp_created_at = timezone.now()
                    user.save()

                    return Response({
                        "message": "OTP sent successfully. Please set your password."
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({"message": "Failed to send OTP"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            # New user, send OTP for registration
            otp = send_otp(phone_number)
            if otp:
                new_user = User.objects.create(phone_number=phone_number, otp=otp, otp_created_at=timezone.now())

                return Response({
                    "message": "OTP sent successfully. Proceed to verification."
                }, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Failed to send OTP"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VerifyPhoneOTPView(APIView):
    """
    Verifies OTP for new users to proceed with profile setup.
    If OTP is valid, returns JWT tokens.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        phone_number = request.data.get('phone_number')
        otp = request.data.get('otp')
        
        if not phone_number or not otp:
            return Response({"message": "Phone number and OTP are required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(phone_number=phone_number)
            
            # Check OTP validity and expiration
            if user.otp == otp and timezone.now() <= user.otp_created_at + timedelta(minutes=5):
                # OTP is valid, generate and return tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)

                return Response({
                    "message": "OTP verified. Tokens issued.",
                    "tokens": {
                        "access": access_token,
                        "refresh": refresh_token
                    }
                }, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST)
        
        except User.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

class ProfileApiView(generics.RetrieveUpdateAPIView):
    """
    API View for retrieving and updating the authenticated user's profile.
    """
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        # Get the profile associated with the authenticated user
        return get_object_or_404(Profile, user=self.request.user)

class SetPasswordView(APIView):
    """
    Allows users to set a password after completing their profile.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        password = request.data.get('password')

        if not password:
            return Response({"message": "Password is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        user = request.user
        user.set_password(password)
        user.is_verified = True
        user.save()
        
        return Response({"message": "Password set successfully"}, status=status.HTTP_200_OK)


class LoginWithPasswordView(APIView):
    """
    Logs in an existing user using mobile number and password.
    """
    def post(self, request):
        phone_number = request.data.get('phone_number')
        password = request.data.get('password')
        
        if not phone_number or not password:
            return Response({"message": "Phone number and password are required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(phone_number=phone_number)
            if user.check_password(password):
                refresh = RefreshToken.for_user(user)
                return Response({
                    "message": "Login successful",
                    "token": {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    "user_id": user.id,
                }, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
        
        except User.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
