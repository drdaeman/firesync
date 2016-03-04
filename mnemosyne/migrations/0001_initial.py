# -*- coding: utf-8 -*-
# Generated by Django 1.9.3 on 2016-03-04 16:49
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Collection',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=32)),
                ('modified', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='StorageObject',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('bsoid', models.CharField(max_length=12)),
                ('modified', models.DateTimeField(auto_now=True)),
                ('expires', models.DateTimeField(blank=True, null=True)),
                ('payload', models.TextField()),
                ('sortindex', models.IntegerField(blank=True, null=True)),
                ('collection', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='mnemosyne.Collection')),
            ],
        ),
        migrations.AlterUniqueTogether(
            name='storageobject',
            unique_together=set([('collection', 'bsoid')]),
        ),
        migrations.AlterUniqueTogether(
            name='collection',
            unique_together=set([('user', 'name')]),
        ),
    ]
