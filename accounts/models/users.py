from django.db import models
from django.contrib.auth.models import (
    BaseUserManager,
    AbstractBaseUser,
    PermissionsMixin,
)
from django.utils.translation import gettext_lazy as _

class MyUserManager(BaseUserManager):
    def create_user(self, phone_number, password=None, **extra_fields):
        if not phone_number:
            raise ValueError('شماره موبایل باید ثبت شود.')

        phone_number = self.normalize_phone_number(phone_number)

        if self.model.objects.filter(phone_number=phone_number).exists():
            raise ValueError('این شماره موبایل قبلا ثبت شده است.')

        user = self.model(phone_number=phone_number, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone_number, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(phone_number, password, **extra_fields)

    def normalize_phone_number(self, phone_number):
        phone_number = re.sub(r'\D', '', phone_number)
        if len(phone_number) == 11 and phone_number.startswith('0'):
            normalized_number = '+98' + phone_number[1:]
        elif len(phone_number) == 10 and phone_number.startswith('9'):
            normalized_number = '+98' + phone_number
        else:
            raise ValueError('شماره موبایل معتبر نمی باشد')
        return normalized_number


class User(AbstractBaseUser, PermissionsMixin):
    phone_number = models.CharField(max_length=15, unique=True)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)
    logged = models.BooleanField(default=False, help_text='If otp verification got successful')
    count = models.IntegerField(default=0, help_text='Number of otp sent')

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = []

    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)

    objects = MyUserManager()

    def __str__(self):
        return self.phone_number
