# Generated by Django 4.2.7 on 2023-12-01 17:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_auth', '0002_alter_customuser_is_active'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='picture',
            field=models.CharField(default='', max_length=255),
        ),
    ]
