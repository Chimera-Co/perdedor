"""Perdedor iOS driver: drives a jailbroken or Corellium virtual device over ssh,
or an iOS Simulator on the local Mac (xcrun simctl). Nothing is installed."""

from .runner import run_scan

__all__ = ["run_scan"]
