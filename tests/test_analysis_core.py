import sys
import os
import pytest

# Add the parent directory to the path so we can import analysis_core
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import analysis_core as core

def test_sha256():
    """Tests the SHA256 hash function."""
    data = b"hello world"
    # Expected hash calculated with an external tool
    expected_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert core.sha256(data) == expected_hash

def test_exif_diff_no_diff():
    """Tests EXIF diff with identical metadata."""
    meta1 = {"Image Make": "Canon", "Image Model": "EOS R5"}
    meta2 = {"Image Make": "Canon", "Image Model": "EOS R5"}
    diff = core.exif_diff(meta1, meta2)
    assert len(diff) == 0

def test_exif_diff_with_diff():
    """Tests EXIF diff with different metadata."""
    meta1 = {"Image Make": "Canon", "Image Model": "EOS R5", "Image Software": "v1.0"}
    meta2 = {"Image Make": "Canon", "Image Model": "EOS R6", "Image Software": "v1.1"}
    diff = core.exif_diff(meta1, meta2)
    assert len(diff) == 2
    # Check if the specific differences are found
    diff_tags = [d[0] for d in diff]
    assert "Image Model" in diff_tags
    assert "Image Software" in diff_tags

def test_exif_diff_key_in_one_only():
    """Tests EXIF diff where a key exists in only one dict."""
    meta1 = {"Image Make": "Canon", "Image Model": "EOS R5"}
    meta2 = {"Image Make": "Canon"}
    diff = core.exif_diff(meta1, meta2)
    assert len(diff) == 1
    assert diff[0][0] == "Image Model"
    assert diff[0][1] == "EOS R5"
    assert diff[0][2] == "N/A"

    meta3 = {"Image Make": "Canon"}
    meta4 = {"Image Make": "Canon", "Image Model": "EOS R5"}
    diff2 = core.exif_diff(meta3, meta4)
    assert len(diff2) == 1
    assert diff2[0][0] == "Image Model"
    assert diff2[0][1] == "N/A"
    assert diff2[0][2] == "EOS R5"
