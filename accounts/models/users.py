from django.db import models
from django.contrib.auth.models import (
    BaseUserManager,
    AbstractBaseUser,
    PermissionsMixin,
)
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
import re

class MyUserManager(BaseUserManager):
    def create_user(self, phone_number, password=None, **extra_fields):
        if not phone_number:
            raise ValueError('Phone number is required.')

        
        user, created = self.model.objects.get_or_create(phone_number=phone_number, defaults={'phone_number': phone_number, **extra_fields})
        if not created:
            raise ValueError('This phone number is already registered.')

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone_number, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(phone_number, password, **extra_fields)


def validate_phone_number(value):
    phone_regex = r'^\+?\d{10,15}$' 
    if not re.match(phone_regex, value):
        raise ValidationError("Phone number must be entered in the format: '+989999999'. Up to 15 digits allowed.")


class User(AbstractBaseUser, PermissionsMixin):
    phone_number = models.CharField(max_length=15, unique=True , validators=[validate_phone_number])
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)
    logged = models.BooleanField(default=False, help_text='If otp verification got successful')
    count = models.IntegerField(default=0, help_text='Number of otp sent')

    # Fields for blocking and tracking login attempts
    login_attempts = models.IntegerField(default=0)
    otp_attempts = models.IntegerField(default=0)
    blocked_until = models.DateTimeField(blank=True, null=True)


    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = []

    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)

    objects = MyUserManager()

    def is_blocked(self):
        return self.blocked_until and timezone.now() < self.blocked_until
    def __str__(self):
        return self.phone_number
