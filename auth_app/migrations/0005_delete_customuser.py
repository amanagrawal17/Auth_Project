# Generated by Django 5.0.1 on 2024-03-06 06:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('auth_app', '0004_initial'),
    ]

    operations = [
        migrations.DeleteModel(
            name='CustomUser',
        ),
    ]