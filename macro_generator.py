from datetime import datetime


def generate_libreoffice_macro(original_filename, rows_to_delete_by_sheet, filter_rules=None):
    """Generate a LibreOffice Calc macro that deletes rows"""
    
    macro_header = f'''REM Macro generated to clean up: {original_filename}
REM Generated on: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC
Option Explicit

Private Sub _SafeSetEnable(oController As Object, enabled As Boolean)
    On Error Resume Next
    If Not oController Is Nothing Then
        Dim oFrame As Object, oWin As Object
        oFrame = oController.getFrame()
        If Not oFrame Is Nothing Then
            oWin = oFrame.getContainerWindow()
            If Not oWin Is Nothing Then
                oWin.setEnable(enabled)
            End If
        End If
    End If
    On Error GoTo 0
End Sub

Private Sub _SaveAndQuit(oDoc As Object)
    On Error Resume Next
    If Not oDoc Is Nothing Then
        oDoc.store                 ' save in place (keeps XLSX)
        oDoc.close(True)           ' close without prompts
    End If
    StarDesktop.terminate          ' end soffice process
    On Error GoTo 0
End Sub

Sub DeleteEmptyRows()
    On Error GoTo EH

    Dim oDoc As Object, oController As Object, oSheet As Object
    Dim rowsDeleted As Long
    oDoc = ThisComponent
    oController = oDoc.getCurrentController()
    rowsDeleted = 0

    _SafeSetEnable oController, False   ' ok in headless (no-op if not available)
'''

    # Build the per-sheet deletion body
    macro_body = ""
    for sheet_name, rows in rows_to_delete_by_sheet.items():
        sorted_rows = sorted(rows, reverse=True)  # delete bottom-up

        # Compact consecutive runs for fewer removeByIndex calls
        row_groups = []
        if sorted_rows:
            grp = [sorted_rows[0]]
            for r in sorted_rows[1:]:
                if r == grp[-1] - 1:
                    grp.append(r)
                else:
                    row_groups.append(grp)
                    grp = [r]
            row_groups.append(grp)

        macro_body += f'''
    ' Process sheet: {sheet_name}
    If oDoc.Sheets.hasByName("{sheet_name}") Then
        oSheet = oDoc.Sheets.getByName("{sheet_name}")
'''

        for grp in row_groups:
            start_row = min(grp)
            count = len(grp)
            # LibreOffice Basic uses 0-based index for removeByIndex
            macro_body += f'''        oSheet.Rows.removeByIndex({start_row - 1}, {count})
        rowsDeleted = rowsDeleted + {count}
'''

        macro_body += '''    End If
'''

    macro_footer = '''
    _SafeSetEnable oController, True
    _SaveAndQuit oDoc
    Exit Sub

EH:
    ' Write a minimal error log to home dir (read by workflow)
    On Error Resume Next
    Dim f As Integer
    f = FreeFile()
    Open Environ("HOME") & "/macro.log" For Append As #f
    Print #f, "Error " & Err & ": " & Error$ & " at " & Now
    Close #f
    _SafeSetEnable oController, True
    _SaveAndQuit oDoc
End Sub
'''

    return macro_header + macro_body + macro_footer


def generate_instructions(original_filename, total_rows, sheet_names, filter_rules):
    """Generate step-by-step instructions for using the macro"""
    
    # Build filter description
    bullet = "\u2022"
    arrow = "\u2192"
    nl = chr(10)
    filter_desc = "These rows match ALL of the following conditions:\n"
    for rule in filter_rules:
        if rule['value'] == '0':
            filter_desc += f"  {bullet} Column {rule['column']} is empty or zero\n"
        else:
            filter_desc += f"  {bullet} Column {rule['column']} equals '{rule['value']}'\n"

    sheet_list = nl.join(bullet + " " + sheet for sheet in sheet_names)
    sheet_breakdown = nl.join(
        bullet + " " + sheet + ": rows to review and potentially delete"
        for sheet in sheet_names
    )

    return f"""EXCEL FILE CLEANUP INSTRUCTIONS
Generated for: {original_filename}
Generated on: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC

=== SUMMARY ===
Analysis found {total_rows} rows to be deleted across {len(sheet_names)} sheet(s):
{sheet_list}

{filter_desc}

=== METHOD 1: LIBREOFFICE CALC MACRO (RECOMMENDED) ===

1. BACKUP YOUR FILE FIRST!
   - Make a copy of your original Excel file before proceeding

2. Download the macro file:
   - Click "Download Macro" button in the web interface
   - Save the .bas file to your computer

3. Open your Excel file in LibreOffice Calc:
   - Download LibreOffice (free) if you don't have it: https://www.libreoffice.org/download/
   - Open your Excel file in LibreOffice Calc

4. Import and run the macro:
   - Go to Tools {arrow} Macros {arrow} Organize Macros {arrow} LibreOffice Basic
   - Click "New" to create a new module
   - Delete the default code and paste the macro content
   - Click "Run" (or press F5)
   - The macro will show progress and completion message

5. Save your file:
   - File {arrow} Save (keeps Excel format)
   - Or File {arrow} Save As to choose a different name/format

=== METHOD 2: MANUAL DELETION ===

If you prefer to delete rows manually, here's what to look for:
- Find rows where columns F, G, H, and I are ALL empty or contain only zeros
- Delete these entire rows
- Work from bottom to top to avoid row number changes

Sheet-by-sheet breakdown:
{sheet_breakdown}

=== IMPORTANT NOTES ===
- This process will preserve all images, charts, and formatting
- The macro deletes entire rows, not just cell contents
- Always backup your file before making changes
- If you encounter issues, you can restore from your backup

=== SUPPORT ===
If you need help or encounter issues:
1. Make sure you have LibreOffice Calc installed
2. Check that macros are enabled in LibreOffice
3. Ensure you're pasting the complete macro code
4. Try the manual method if the macro doesn't work

Generated by Excel Processor Tool
"""
