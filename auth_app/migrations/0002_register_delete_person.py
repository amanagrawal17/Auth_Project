# Generated by Django 5.0.1 on 2024-02-06 05:33
''' modules imported'''
from django.db import migrations, models


class Migration(migrations.Migration):
    ''' migration class '''
    dependencies = [
        ('auth_app', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Register',
            fields=[
                ('id',
                 models.BigAutoField(auto_created=True,
                 primary_key=True,
                 serialize=False,
                 verbose_name='ID')),
                ('username', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=254)),
                ('password', models.CharField(max_length=100)),
            ],
        ),
        migrations.DeleteModel(
            name='Person',
        ),
    ]
