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

def delete_empty_rows_direct(doc):
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
                    
                    # Check columns F, G, H, I (indices 5, 6, 7, 8)
                    for col in [5, 6, 7, 8]:
                        try:
                            cell = sheet.getCellByPosition(col, row)
                            cell_value = cell.getValue()
                            cell_string = cell.getString().strip()
                            
                            debug_values.append(f"{chr(70+col-5)}={cell_value}|'{cell_string}'")
                            
                            if cell_value != 0 or cell_string != "":
                                all_empty = False
                                
                        except Exception as e:
                            all_empty = False
                            break
                    
                    # Debug output for rows containing "E-ST" 
                    if "E-ST" in col_a_value:
                        print(f"DEBUG Row {row+1} ({col_a_value}): {' | '.join(debug_values)} -> DELETE={all_empty}")
                    
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