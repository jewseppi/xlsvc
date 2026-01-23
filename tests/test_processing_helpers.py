"""
Unit tests for processing helper functions
"""
import pytest
from main import is_empty_or_zero, column_to_index


class TestIsEmptyOrZero:
    """Tests for is_empty_or_zero function"""
    
    def test_none_value(self):
        """Test that None returns True"""
        assert is_empty_or_zero(None) is True
    
    def test_zero_integer(self):
        """Test that integer 0 returns True"""
        assert is_empty_or_zero(0) is True
    
    def test_zero_float(self):
        """Test that float 0.0 returns True"""
        assert is_empty_or_zero(0.0) is True
    
    def test_empty_string(self):
        """Test that empty string returns True"""
        assert is_empty_or_zero("") is True
    
    def test_whitespace_string(self):
        """Test that whitespace-only string returns True"""
        assert is_empty_or_zero("   ") is True
        assert is_empty_or_zero("\t\n") is True
    
    def test_string_zero(self):
        """Test that string "0" returns True"""
        assert is_empty_or_zero("0") is True
        assert is_empty_or_zero(" 0 ") is True
    
    def test_non_zero_integer(self):
        """Test that non-zero integer returns False"""
        assert is_empty_or_zero(1) is False
        assert is_empty_or_zero(-1) is False
        assert is_empty_or_zero(100) is False
    
    def test_non_zero_float(self):
        """Test that non-zero float returns False"""
        assert is_empty_or_zero(0.1) is False
        assert is_empty_or_zero(-0.1) is False
        assert is_empty_or_zero(1.5) is False
    
    def test_non_empty_string(self):
        """Test that non-empty string returns False"""
        assert is_empty_or_zero("hello") is False
        assert is_empty_or_zero("1") is False
        assert is_empty_or_zero("abc") is False


class TestColumnToIndex:
    """Tests for column_to_index function"""
    
    def test_single_letter_columns(self):
        """Test single letter column conversion"""
        assert column_to_index('A') == 1
        assert column_to_index('B') == 2
        assert column_to_index('Z') == 26
        assert column_to_index('a') == 1  # lowercase
        assert column_to_index('F') == 6
    
    def test_double_letter_columns(self):
        """Test double letter column conversion"""
        assert column_to_index('AA') == 27
        assert column_to_index('AB') == 28
        assert column_to_index('AZ') == 52
        assert column_to_index('BA') == 53
    
    def test_numeric_input(self):
        """Test numeric column input"""
        assert column_to_index('1') == 1
        assert column_to_index('5') == 5
        assert column_to_index('26') == 26
        assert column_to_index(1) == 1
        assert column_to_index(5) == 5
    
    def test_whitespace_handling(self):
        """Test that whitespace is handled correctly"""
        assert column_to_index(' A ') == 1
        assert column_to_index('  F  ') == 6
        assert column_to_index(' AA ') == 27
    
    def test_edge_cases(self):
        """Test edge cases"""
        assert column_to_index('IV') == 256  # Excel max column in older versions
        assert column_to_index('XFD') == 16384  # Excel max column in newer versions
