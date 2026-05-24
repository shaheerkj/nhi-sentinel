"""Shared pytest configuration and fixtures."""

import os

import pytest

# Set dummy AWS credentials so boto3/moto doesn't complain about missing config
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("AWS_SECURITY_TOKEN", "test")
os.environ.setdefault("AWS_SESSION_TOKEN", "test")
