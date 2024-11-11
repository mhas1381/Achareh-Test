from django.urls import path, include
from ..views import ProfileApiView
urlpatterns=[
    path('complete-profile/', ProfileApiView.as_view(), name='complete-profile'),

]