"""jwtController URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from jwtIssuer import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth', views.auth, name="auth"),
    path('renew_token', views.renew_jwt_token, name="renew_jwt_token"),
    path('register', views.register, name="register"),
    path('update_profile', views.update_profile, name="update_profile"),
    path('request_password_reset', views.request_password_reset,
         name="request_password_reset"),
    path('reset_password', views.reset_password, name="reset_password"),
    path('get_public_cert', views.get_public_cert, name="get_public_cert"),

]
