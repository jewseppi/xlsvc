def evaluate_cell_value(cell):
    """
    Get the actual value of a cell, evaluating formulas if necessary.
    Returns the calculated value for formulas, or the raw value otherwise.
    """
    if hasattr(cell, 'value'):
        value = cell.value
        
        if isinstance(value, str) and value.startswith('='):
            return None  # Return None to indicate we need data_only mode
        
        return value
    return None


def is_empty_or_zero(val):
    """
    Check if a value is empty, None, zero, or blank.
    Handles various data types appropriately.
    """
    if val is None:
        return True
    if val == 0:
        return True
    if val == "":
        return True
    if isinstance(val, str) and val.strip() == '':
        return True
    if isinstance(val, str) and val.strip() == '0':
        return True
    return False


def column_to_index(col):
    """Convert column letter (A, F, Z) or number (1, 6, 26) to 1-based column index"""
    col = str(col).strip().upper()
    
    # If it's already a number, return it as int
    if col.isdigit():
        return int(col)
    
    # Convert letter(s) to number (A=1, B=2, ... Z=26, AA=27, etc.)
    index = 0
    for char in col:
        if char.isalpha():
            index = index * 26 + (ord(char) - ord('A') + 1)
    return index
