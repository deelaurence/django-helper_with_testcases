# Generated by Django 4.2.7 on 2023-12-02 18:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_auth', '0005_customuser_last_seen'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='last_seen',
            field=models.CharField(default='', max_length=50),
        ),
    ]
