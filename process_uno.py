import uno
import os
import sys
import time
import json
from com.sun.star.beans import PropertyValue

# Import the deletion report module
sys.path.append('.')
from deletion_report import generate_deletion_report

def main():
    try:
        print("UNO script starting...")
        
        # Connect to LibreOffice
        localContext = uno.getComponentContext()
        resolver = localContext.ServiceManager.createInstanceWithContext(
            "com.sun.star.bridge.UnoUrlResolver", localContext)
        
        print("Connecting to LibreOffice UNO server...")
        context = resolver.resolve("uno:socket,host=localhost,port=2002;urp;StarOffice.ComponentContext")
        desktop = context.ServiceManager.createInstanceWithContext(
            "com.sun.star.frame.Desktop", context)
        
        print("Connected to LibreOffice UNO server")
        
        # Load document
        input_path = os.path.abspath("input.xlsx")
        file_url = uno.systemPathToFileUrl(input_path)
        print(f"Loading document: {file_url}")
        
        doc = desktop.loadComponentFromURL(file_url, "_blank", 0, ())
        print("Document loaded")
        
        # Get filter rules
        filter_rules = get_filter_rules()
        print(f"Using {len(filter_rules)} filter rules:")
        for rule in filter_rules:
            print(f"  - Column {rule['column']} = '{rule['value']}'")
        
        # Process and capture deleted row data
        deleted_rows, deleted_data = delete_empty_rows_direct(doc, filter_rules)
        print(f"Deleted {deleted_rows} empty rows")
        
        # Save processed file
        output_path = os.path.abspath("output.xlsx")
        output_url = uno.systemPathToFileUrl(output_path)
        print(f"Output URL: {output_url}")
        
        save_props = (
            PropertyValue("Overwrite", 0, True, 0),
            PropertyValue("FilterName", 0, "Calc MS Excel 2007 XML", 0),
        )
        
        doc.storeToURL(output_url, save_props)
        doc.close(True)
        
        print("LibreOffice save complete. Normalizing format...")
        
        # Normalize with openpyxl
        from openpyxl import load_workbook
        wb = load_workbook(output_path, data_only=True, keep_vba=False)
        wb.save(output_path)
        wb.close()
        
        print("Format normalized.")
        
        # Generate deletion report
        print("Generating deletion report...")
        report_path = generate_deletion_report(deleted_data, "deletion_report.xlsx")
        if report_path:
            print(f"Deletion report created: {report_path}")
        else:
            print("No deletion report generated (no data)")
        
        print(f"Processing complete. Deleted {deleted_rows} rows.")
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

def get_filter_rules():
    """Get filter rules from environment variable"""
    filter_rules_json = os.getenv('FILTER_RULES')
    
    if not filter_rules_json:
        raise Exception("FILTER_RULES environment variable is required")
    
    try:
        rules = json.loads(filter_rules_json)
        print(f"Loaded {len(rules)} filter rules from FILTER_RULES env var")
        
        if not rules or len(rules) == 0:
            raise Exception("FILTER_RULES cannot be empty")
        
        return rules
    except json.JSONDecodeError as e:
        raise Exception(f"Invalid FILTER_RULES JSON: {e}")

def column_to_index(col):
    """Convert column letter or number to zero-based index"""
    col = str(col).strip().upper()
    
    if col.isdigit():
        return int(col) - 1
    
    index = 0
    for char in col:
        if char.isalpha():
            index = index * 26 + (ord(char) - ord('A') + 1)
    return index - 1

def delete_empty_rows_direct(doc, filter_rules):
    """
    Delete rows based on filter rules and capture data for report.
    Returns: (deleted_count, deleted_data_dict)
    """
    doc.calculateAll()
    time.sleep(2)
    
    deleted_count = 0
    deleted_data = {}  # {sheet_name: [row_data]}
    
    try:
        sheets = doc.getSheets()
        print(f"Processing {sheets.getCount()} sheets")
        
        for sheet_idx in range(sheets.getCount()):
            sheet = sheets.getByIndex(sheet_idx)
            sheet_name = sheet.getName()
            print(f"Processing sheet: {sheet_name}")
            
            last_row = 1000
            print(f"Checking up to row {last_row} in {sheet_name}")
            
            rows_to_delete = []
            sheet_deleted_data = []
            
            for row in range(last_row - 1, -1, -1):
                try:
                    # Get column A to check if row has data
                    col_a_cell = sheet.getCellByPosition(0, row)
                    col_a_value = col_a_cell.getString().strip()
                    
                    # Skip completely empty rows
                    if not col_a_value:
                        continue
                    
                    all_empty = True
                    debug_values = []
                    
                    # Check columns based on filter_rules
                    for rule in filter_rules:
                        try:
                            col_index = column_to_index(rule['column'])
                            expected_value = rule['value']
                            
                            cell = sheet.getCellByPosition(col_index, row)
                            cell_value = cell.getValue()
                            cell_string = cell.getString().strip()
                            
                            debug_values.append(f"{rule['column']}={cell_value}|'{cell_string}'")
                            
                            is_empty = (cell_value == 0 or cell_value == 0.0) and (cell_string == "" or cell_string == "0")
                            
                            if not is_empty:
                                all_empty = False
                                break
                                
                        except Exception as e:
                            all_empty = False
                            break
                    
                    # Debug output for specific rows
                    if "E-ST" in col_a_value:
                        print(f"DEBUG Row {row+1} ({col_a_value}): {' | '.join(debug_values)} -> DELETE={all_empty}")
                    
                    if all_empty:
                        # Capture row data before deletion
                        row_data = {
                            'row_number': row + 1,  # 1-based for display
                            'data': []
                        }
                        
                        # Get all cell values
                        max_cols = 50
                        for col in range(max_cols):
                            try:
                                cell = sheet.getCellByPosition(col, row)
                                value = cell.getString() if cell.getString() else cell.getValue()
                                row_data['data'].append(value if value else '')
                            except:
                                break
                        
                        # Trim trailing empty cells
                        while row_data['data'] and row_data['data'][-1] == '':
                            row_data['data'].pop()
                        
                        sheet_deleted_data.append(row_data)
                        rows_to_delete.append(row)
                        
                except Exception:
                    continue
            
            print(f"Found {len(rows_to_delete)} empty rows to delete in {sheet_name}")
            
            if sheet_deleted_data:
                deleted_data[sheet_name] = sheet_deleted_data
            
            # Delete rows
            for row in rows_to_delete:
                try:
                    sheet.getRows().removeByIndex(row, 1)
                    deleted_count += 1
                except Exception as e:
                    print(f"Error deleting row {row}: {e}")
                    
    except Exception as e:
        print(f"Error in delete_empty_rows_direct: {e}")
        import traceback
        traceback.print_exc()
    
    return deleted_count, deleted_data

if __name__ == "__main__":
    exit_code = main()
    print(f"UNO exit: {exit_code}")
    sys.exit(exit_code)