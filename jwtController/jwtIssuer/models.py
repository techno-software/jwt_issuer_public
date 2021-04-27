from django.db import models
from django.contrib.auth.models import User


class PasswordResetRequest (models.Model):
    id = models.AutoField(primary_key=True)
    forUser = models.OneToOneField(
        User, on_delete=models.CASCADE, blank=False, null=False)

    reset_code = models.CharField(max_length=500, blank=False, null=False)
    sent_to_email = models.CharField(max_length=500, blank=False, null=False)
    time_sent = models.DateTimeField(blank=False, null=False)

    def __str__(self):
        return str(self.forUser)
