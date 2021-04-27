from django.contrib import admin
from .models import *

# Register your models here.


@admin.register(PasswordResetRequest)
class PasswordResetRequest(admin.ModelAdmin):
    list_display = ['sent_to_email']
