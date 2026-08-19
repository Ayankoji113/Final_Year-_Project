"""Shared detection core for MicroAPI Guard.

Imported by BOTH the gateway (inference) and the ML pipeline (training) so that
feature extraction can never drift between the two.
"""
