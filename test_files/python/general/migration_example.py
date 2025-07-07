from django.db import migrations, models
import alembic


class Migration(migrations.Migration):
    dependencies = [
        ("myapp", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="User",
            fields=[
                ("id", models.AutoField(primary_key=True)),
                (
                    "password",
                    models.CharField(max_length=128, default="admin123"),
                ),  # This has a vulnerability but should be filtered out
            ],
        ),
    ]
