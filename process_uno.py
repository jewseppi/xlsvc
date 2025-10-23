import uno
import os
import sys
import time

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
        
        # Get filter rules from environment
        filter_rules = get_filter_rules()
        print(f"Using {len(filter_rules)} filter rules:")
        for rule in filter_rules:
            print(f"  - Column {rule['column']} = '{rule['value']}'")

        # Process directly with UNO API
        deleted_rows = delete_empty_rows_direct(doc)
        print(f"Deleted {deleted_rows} empty rows")
        
        # Save the result
        output_path = os.path.abspath("output.xlsx")
        output_url = uno.systemPathToFileUrl(output_path)
        print(f"Output URL: {output_url}")
        
        doc.storeAsURL(output_url, ())
        doc.close(True)
        
        print(f"Processing complete. Deleted {deleted_rows} rows.")
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

def get_filter_rules():
    """Get filter rules from environment variable - frontend always provides them"""
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
    
    # If it's already a number, convert directly
    if col.isdigit():
        return int(col) - 1
    
    # Convert letter(s) to index (A=0, B=1, ... Z=25, AA=26, etc.)
    index = 0
    for char in col:
        if char.isalpha():
            index = index * 26 + (ord(char) - ord('A') + 1)
    return index - 1

def delete_empty_rows_direct(doc, filter_rules):
    # Force calculation first
    doc.calculateAll()
    time.sleep(2)
    
    deleted_count = 0
    
    try:
        sheets = doc.getSheets()
        print(f"Processing {sheets.getCount()} sheets")
        
        for sheet_idx in range(sheets.getCount()):
            sheet = sheets.getByIndex(sheet_idx)
            sheet_name = sheet.getName()
            print(f"Processing sheet: {sheet_name}")
            
            # Use fixed range instead of cursor
            last_row = 1000  # Reasonable limit
            print(f"Checking up to row {last_row} in {sheet_name}")
            
            rows_to_delete = []
            
            for row in range(last_row - 1, -1, -1):
                try:
                    # Get column A value to identify the row
                    col_a_cell = sheet.getCellByPosition(0, row)
                    col_a_value = col_a_cell.getString().strip()
                    
                    # Skip completely empty rows
                    if not col_a_value:
                        continue
                    
                    all_empty = True
                    debug_values = []
                    
                    # Check columns based on filter_rules instead of hardcoded F,G,H,I
                    for rule in filter_rules:
                        try:
                            col_index = column_to_index(rule['column'])
                            expected_value = rule['value']
                            
                            cell = sheet.getCellByPosition(col_index, row)
                            cell_value = cell.getValue()
                            cell_string = cell.getString().strip()
                            
                            debug_values.append(f"{rule['column']}={cell_value}|'{cell_string}'")
                            
                            # YOUR EXACT WORKING LOGIC for checking if empty
                            is_empty = (cell_value == 0 or cell_value == 0.0) and (cell_string == "" or cell_string == "0")
                            
                            if not is_empty:
                                all_empty = False
                                
                        except Exception as e:
                            all_empty = False
                            break
                    
                    if all_empty:
                        rows_to_delete.append(row)
                        
                except Exception:
                    continue
            
            print(f"Found {len(rows_to_delete)} empty rows to delete in {sheet_name}")
            
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
    
    return deleted_count

if __name__ == "__main__":
    exit_code = main()
    print(f"UNO exit: {exit_code}")
    sys.exit(exit_code)