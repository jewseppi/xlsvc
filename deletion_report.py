"""
Module for generating Excel deletion reports.
Shows which rows were deleted during processing.
"""

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment

def generate_deletion_report(deleted_rows_data, output_path):
    """
    Generate an Excel workbook showing deleted rows.
    
    Args:
        deleted_rows_data: Dict of {sheet_name: [{'row_number': int, 'data': [cell values]}]}
        output_path: Where to save the report file
    
    Returns:
        output_path if successful, None if no data
    """
    if not deleted_rows_data or len(deleted_rows_data) == 0:
        print("No deleted rows data to generate report")
        return None
    
    wb = Workbook()
    wb.remove(wb.active)  # Remove default sheet
    
    sheets_added = 0
    for sheet_name, rows in deleted_rows_data.items():
        if not rows or len(rows) == 0:
            continue
            
        ws = wb.create_sheet(title=sheet_name[:31])  # Excel sheet name limit
        sheets_added += 1
        
        # Header row
        max_cols = len(rows[0]['data']) if rows else 0
        headers = ['Original Row #'] + [f'Col {chr(65+i)}' if i < 26 else f'Col {i+1}' for i in range(max_cols)]
        ws.append(headers)
        
        # Style header
        for cell in ws[1]:
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color='4472C4', end_color='4472C4', fill_type='solid')
            cell.alignment = Alignment(horizontal='center', vertical='center')
        
        # Data rows
        for row_info in rows:
            ws.append([row_info['row_number']] + row_info['data'])
        
        # Auto-size columns (approximate)
        for idx, column in enumerate(ws.columns, 1):
            max_length = 0
            column_letter = column[0].column_letter
            for cell in column:
                try:
                    cell_len = len(str(cell.value)) if cell.value is not None else 0
                    if cell_len > max_length:
                        max_length = cell_len
                except:
                    pass
            adjusted_width = min(max(max_length + 2, 10), 50)
            ws.column_dimensions[column_letter].width = adjusted_width
    
    if sheets_added == 0:
        print("No sheets added to report")
        return None
    
    wb.save(output_path)
    wb.close()
    
    print(f"Deletion report saved to {output_path} with {sheets_added} sheet(s)")
    return output_path

def capture_row_data(sheet, row_num, max_cols=50):
    """
    Capture all cell values from a row (for openpyxl sheets).
    
    Args:
        sheet: openpyxl worksheet
        row_num: Row number (1-based)
        max_cols: Maximum columns to capture
    
    Returns:
        List of cell values
    """
    row_data = []
    for col in range(1, max_cols + 1):
        try:
            cell_value = sheet.cell(row=row_num, column=col).value
            row_data.append(cell_value if cell_value is not None else '')
        except:
            break
    
    # Trim trailing empty cells
    while row_data and row_data[-1] == '':
        row_data.pop()
    
    return row_data