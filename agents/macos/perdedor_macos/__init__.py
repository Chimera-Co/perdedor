"""Perdedor macOS driver: runs on a Mac (--local) or drives a macOS machine or VM
over ssh, using only commands that ship with macOS."""

from .runner import run_scan

__all__ = ["run_scan"]
